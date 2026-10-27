//! effect-attest: kernel-observed effects of MCP `tools/call`, signed.
//!
//! - [`server`]: MCP stdio server; each call runs in its own cgroup v2.
//! - [`tracer`]: eBPF loader and ring buffer router (needs root).
//! - [`effects`]: record decoding and enter/exit joining.
//! - [`statement`], [`dsse`]: in-toto Statement v1 inside a DSSE envelope,
//!   signed with Ed25519, plus the verifier.
//! - [`bench`]: completeness / misattribution measurement.
pub mod bench;
pub mod cgroup;
pub mod config;
pub mod dsse;
pub mod effects;
pub mod jsonrpc;
pub mod server;
pub mod statement;
pub mod syscalls;
pub mod timefmt;
pub mod tracer;
