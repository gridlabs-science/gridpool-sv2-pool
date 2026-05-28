//! Bitcoin Core v30.x IPC implementation modules.
//!
//! This namespace contains the concrete v30.x runtime implementations used when
//! [`crate::common::BitcoinCoreVersion::V30X`] is selected.
//!
//! It is wired against `bitcoin_capnp_types_v30`, which re-exports the matching `capnp`
//! and `capnp-rpc` APIs.

pub mod job_declaration_protocol;
pub mod template_distribution_protocol;
