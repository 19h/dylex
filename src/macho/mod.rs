//! Mach-O file format handling.
//!
//! This module provides types and utilities for parsing and modifying Mach-O files,
//! which are the executable format used on macOS and iOS.

mod constants;
mod context;
mod structs;

pub use constants::*;
pub use context::*;
pub use structs::*;
