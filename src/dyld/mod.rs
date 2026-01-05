//! Dyld shared cache handling.
//!
//! This module provides types and utilities for parsing and working with
//! Apple's dyld shared cache format. The cache is used on iOS and macOS to
//! optimize loading of system frameworks.
//!
//! # Cache Structure
//!
//! A dyld shared cache consists of:
//! - A header with metadata about the cache
//! - Mappings that describe how regions of the cache map to virtual memory
//! - Image information for each dylib in the cache
//! - Slide information for ASLR rebasing
//! - Local symbols (optionally in a separate `.symbols` file)
//!
//! # Sub-caches
//!
//! Starting with iOS 15 / macOS 12, caches can be split into multiple files:
//! - Main cache: `dyld_shared_cache_arm64e`
//! - Sub-caches: `dyld_shared_cache_arm64e.1`, `.2`, etc.
//! - Symbols: `dyld_shared_cache_arm64e.symbols`

mod context;
mod structs;
pub mod trie;

pub use context::*;
pub use structs::*;
pub use trie::*;
