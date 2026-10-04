// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Passive introspection of a Linux guest kernel from guest physical memory.
//!
//! The engine only needs two things from its host: a way to read guest
//! physical memory ([`PhysMemory`]) and the kernel's paging root
//! ([`paging::PagingRoot`]). It does not depend on the VMM, so the same code
//! can run host side, in a paravisor, or against a memory dump.
//!
//! The current checks are integrity checks over kernel text, rodata, and the
//! system call table. Each region is hashed per page on the first scan, and
//! later scans report any page or table entry that differs from that baseline.

#![forbid(unsafe_code)]

pub mod paging;
pub mod scanner;
pub mod symbols;

use thiserror::Error;

/// Access to guest physical memory.
pub trait PhysMemory {
    /// Reads guest physical memory starting at `gpa` into `buf`.
    fn read_phys(&mut self, gpa: u64, buf: &mut [u8]) -> std::io::Result<()>;
}

/// An introspection error.
#[derive(Debug, Error)]
pub enum Error {
    /// Reading guest physical memory failed.
    #[error("failed to read guest physical address {gpa:#x}")]
    Read {
        /// The address that failed.
        gpa: u64,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The guest uses a paging configuration this engine does not support.
    #[error("unsupported paging configuration: {0}")]
    UnsupportedPaging(&'static str),
    /// A symbol required by a check is missing from the symbol table.
    #[error("required symbol `{0}` not found")]
    MissingSymbol(&'static str),
    /// The kernel is not mapped by the provided paging root.
    #[error("kernel address {0:#x} is not mapped by the paging root")]
    KernelNotMapped(u64),
}
