//! Converters for extracting images from the dyld shared cache.
//!
//! This module contains the core extraction logic that transforms a Mach-O image
//! embedded in the shared cache back into a standalone dylib. The conversion
//! process reverses the optimizations applied by Apple's SharedCacheBuilder.
//!
//! # Extraction Pipeline
//!
//! The extraction follows this order (reverse of cache building):
//!
//! 0. **Header Fixup** - Clears MH_DYLIB_IN_CACHE flag and zeros chained fixups
//! 1. **Slide Info Processing** - Rebases pointers by removing ASLR slide encoding
//! 2. **LINKEDIT Optimization** - Rebuilds the merged LINKEDIT segment
//! 3. **Stub Fixing** - Restores optimized stubs to use lazy binding
//! 4. **ObjC Fixing** - Restores ObjC metadata moved to libobjc
//! 5. **Offset Optimization** - Compacts file offsets for smaller output

mod context;
mod fixup;
mod linkedit;
mod objc;
mod slide;
mod stub;
mod writer;

pub use context::*;
pub use fixup::*;
pub use linkedit::*;
pub use objc::*;
pub use slide::*;
pub use stub::*;
pub use writer::*;
