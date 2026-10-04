// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! A worker that passively introspects a running Linux guest.
//!
//! The worker reads guest physical memory and VP registers over the same
//! [`DebugRequest`] channel used by the gdbstub worker, and runs the
//! [`linux_vmi`] integrity scanner periodically and on request.
//!
//! Memory is read while the guest runs, so a scan can observe a page in the
//! middle of an update. Rescan before treating a single finding as
//! conclusive.

#![forbid(unsafe_code)]

use anyhow::Context;
use futures::FutureExt;
use futures::StreamExt;
use futures::executor::block_on;
use linux_vmi::PhysMemory;
use linux_vmi::paging::PagingRoot;
use linux_vmi::scanner::Scanner;
use linux_vmi::symbols::SymbolTable;
use mesh::rpc::RpcSend;
use mesh_worker::Worker;
use mesh_worker::WorkerId;
use mesh_worker::WorkerRpc;
use pal_async::local::block_with_io;
use pal_async::timer::PolledTimer;
use std::time::Duration;
use vmi_worker_defs::VMI_WORKER;
use vmi_worker_defs::VmiParameters;
use vmi_worker_defs::VmiRequest;
use vmm_core_defs::debug_rpc::DebugRequest;
use vmm_core_defs::debug_rpc::DebuggerVpState;
use vmm_core_defs::debug_rpc::GuestAddress;

/// The VM introspection worker.
pub struct VmiWorker {
    params: VmiParameters,
    scanner: Option<Scanner>,
}

impl Worker for VmiWorker {
    type Parameters = VmiParameters;
    type State = VmiParameters;
    const ID: WorkerId<Self::Parameters> = VMI_WORKER;

    fn new(params: Self::Parameters) -> anyhow::Result<Self> {
        Ok(Self {
            params,
            scanner: None,
        })
    }

    fn restart(state: Self::State) -> anyhow::Result<Self> {
        Self::new(state)
    }

    fn run(
        mut self,
        mut rpc_recv: mesh::Receiver<WorkerRpc<Self::Parameters>>,
    ) -> anyhow::Result<()> {
        block_with_io(async |driver| {
            tracing::info!(
                symbols = self.params.symbols_path,
                interval_secs = self.params.interval_secs,
                "vmi worker started"
            );
            let mut timer = PolledTimer::new(&driver);
            let mut control_closed = false;
            loop {
                enum Event {
                    Worker(Result<WorkerRpc<VmiParameters>, mesh::RecvError>),
                    Control(Option<VmiRequest>),
                    Tick,
                }

                let interval = self.params.interval_secs;
                let event = futures::select! { // merge semantics
                    r = rpc_recv.recv().fuse() => Event::Worker(r),
                    r = async {
                        if control_closed {
                            std::future::pending().await
                        } else {
                            self.params.control.next().await
                        }
                    }.fuse() => Event::Control(r),
                    _ = async {
                        if interval == 0 {
                            std::future::pending::<()>().await;
                        }
                        timer.sleep(Duration::from_secs(interval)).await;
                    }.fuse() => Event::Tick,
                };

                match event {
                    Event::Worker(Ok(WorkerRpc::Stop)) | Event::Worker(Err(_)) => return Ok(()),
                    Event::Worker(Ok(WorkerRpc::Inspect(deferred))) => deferred.inspect(()),
                    Event::Worker(Ok(WorkerRpc::Restart(rpc))) => {
                        rpc.complete(Ok(self.params));
                        return Ok(());
                    }
                    Event::Control(Some(VmiRequest::Scan(rpc))) => {
                        rpc.handle_failable_sync(|reset| {
                            if reset {
                                if let Some(scanner) = &mut self.scanner {
                                    scanner.reset_baseline();
                                }
                            }
                            self.scan().map(|report| report.to_string())
                        });
                    }
                    Event::Control(None) => {
                        // Keep scanning periodically until stopped.
                        control_closed = true;
                    }
                    Event::Tick => match self.scan() {
                        Ok(report) if report.findings.is_empty() => {
                            tracing::info!(baseline = report.baseline, "vmi scan clean");
                        }
                        Ok(report) => {
                            for finding in &report.findings {
                                tracelimit::warn_ratelimited!(%finding, "vmi finding");
                            }
                        }
                        Err(err) => {
                            tracing::info!(
                                error = err.as_ref() as &dyn std::error::Error,
                                "vmi scan skipped"
                            );
                        }
                    },
                }
            }
        })
    }
}

impl VmiWorker {
    fn scan(&mut self) -> anyhow::Result<linux_vmi::scanner::ScanReport> {
        if self.scanner.is_none() {
            let text = std::fs::read_to_string(&self.params.symbols_path).with_context(|| {
                format!("failed to read symbols from {}", self.params.symbols_path)
            })?;
            let symbols = SymbolTable::parse(&text);
            tracing::info!(count = symbols.len(), "loaded guest kernel symbols");
            self.scanner = Some(Scanner::new(symbols).context("invalid symbol table")?);
        }

        let root = paging_root(&self.params.req_chan)?;
        let mut mem = RpcMemory(&self.params.req_chan);
        let report = self
            .scanner
            .as_mut()
            .unwrap()
            .scan(&mut mem, root)
            .context("scan failed")?;
        Ok(report)
    }
}

/// Reads the kernel paging root from VP 0.
fn paging_root(req_chan: &mesh::Sender<DebugRequest>) -> anyhow::Result<PagingRoot> {
    let state = block_on(req_chan.call_failable(DebugRequest::GetVpState, 0))
        .context("failed to get VP state")?;
    Ok(match *state {
        DebuggerVpState::Aarch64(s) => PagingRoot::Aarch64 {
            ttbr1: s.ttbr1_el1,
            tcr: s.tcr_el1,
        },
        DebuggerVpState::X86_64(s) => PagingRoot::X86_64 {
            cr3: s.cr3,
            la57: s.cr4 & (1 << 12) != 0,
        },
    })
}

/// Guest physical memory access over the debug request channel.
struct RpcMemory<'a>(&'a mesh::Sender<DebugRequest>);

/// The largest read sent in one request. Responses cross a process boundary,
/// and some mesh transports cannot send large messages (on macOS, anything over
/// 256KiB fails).
const MAX_READ: usize = 64 * 1024;

impl PhysMemory for RpcMemory<'_> {
    fn read_phys(&mut self, gpa: u64, buf: &mut [u8]) -> std::io::Result<()> {
        for (i, chunk) in buf.chunks_mut(MAX_READ).enumerate() {
            let gpa = gpa + (i * MAX_READ) as u64;
            let data = block_on(self.0.call_failable(
                DebugRequest::ReadMemory,
                (GuestAddress::Gpa(gpa), chunk.len()),
            ))
            .map_err(std::io::Error::other)?;
            let data = data
                .get(..chunk.len())
                .ok_or_else(|| std::io::Error::other("short read"))?;
            chunk.copy_from_slice(data);
        }
        Ok(())
    }
}
