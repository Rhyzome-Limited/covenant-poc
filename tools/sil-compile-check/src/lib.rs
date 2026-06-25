//! Toolchain probe — no library code of its own.
//!
//! The real assertion lives in `tests/compile.rs`: a trivial `.sil` compiles
//! via `silverscript-lang` (commit faaa074) and yields a non-empty redeem
//! script plus a Kaspa P2SH script hash computed with `rusty-kaspa` v2.0.1.
//! This empty lib just gives the crate a build target so `cargo build` pulls
//! and compiles both toolchain deps in CI.
