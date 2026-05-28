//! # Bitcoin Core Sv2 Library
//!
//! `bitcoin_core_sv2` bridges Bitcoin Core IPC with Stratum V2 protocols:
//! - [Template Distribution Protocol](https://github.com/stratum-mining/sv2-spec/blob/main/07-Template-Distribution-Protocol.md)
//! - [Job Declaration Protocol](https://github.com/stratum-mining/sv2-spec/blob/main/08-Job-Declaration-Protocol.md)
//!
//! ## Overview
//!
//! `bitcoin_core_sv2` can be used to:
//! - Build Sv2 applications acting as TDP clients (for example Pool or JDC) connected directly to a
//!   Bitcoin Core node.
//! - Build Sv2 template-provider applications acting as TDP servers backed by Bitcoin Core.
//! - Build Sv2 applications acting as JDP servers (for example Pool or JDS) connected directly to a
//!   Bitcoin Core node.
//!
//! ## Module layout
//!
//! - [`common`] exposes version-agnostic runtime handles and factories based on Sv2 IO primitives,
//!   with enum dispatch across backend versions.
//! - [`unix_capnp::v30x`] contains the Bitcoin Core v30.x IPC implementation.
//! - [`unix_capnp::v31x`] contains the Bitcoin Core v31.x IPC implementation.
//!
//! Downstream applications should integrate through [`common`] and choose a
//! [`common::BitcoinCoreVersion`] at runtime.
//!
//! Backend-specific IPC/runtime constraints are documented under [`unix_capnp`].

pub mod common;
pub mod unix_capnp;

/// The minimum block reserved weight established by Bitcoin Core.
pub const MIN_BLOCK_RESERVED_WEIGHT: u64 = 2000;
