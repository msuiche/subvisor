// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Client definitions for the VM introspection worker.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
use mesh::rpc::FailableRpc;
use mesh_worker::WorkerId;
use vmm_core_defs::debug_rpc::DebugRequest;

/// Parameters for launching the VM introspection worker.
#[derive(MeshPayload)]
pub struct VmiParameters {
    /// Channel for reading guest memory and VP state.
    pub req_chan: mesh::Sender<DebugRequest>,
    /// Path to the guest kernel's symbols, in `/proc/kallsyms` or
    /// `System.map` format. Read lazily, so it may be created after the VM
    /// starts.
    pub symbols_path: String,
    /// Seconds between periodic scans, or zero to scan only on request.
    pub interval_secs: u64,
    /// Requests from the VMM.
    pub control: mesh::Receiver<VmiRequest>,
}

/// Requests to the VM introspection worker.
#[derive(MeshPayload)]
pub enum VmiRequest {
    /// Runs a scan and returns the report as text. If the input is true, the
    /// baseline is discarded first so that this scan records a new one.
    Scan(FailableRpc<bool, String>),
}

/// The VM introspection worker.
pub const VMI_WORKER: WorkerId<VmiParameters> = WorkerId::new("VmiWorker");
