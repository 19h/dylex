//! Error types for the dyld cache extractor.
//!
//! This module provides comprehensive error handling for all extraction operations,
//! including cache parsing, Mach-O processing, slide info handling, and symbol resolution.

use std::path::PathBuf;

use thiserror::Error;

/// The main error type for dyld cache extraction operations.
#[derive(Error, Debug)]
pub enum Error {
    // ==================== I/O Errors ====================
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to open file '{path}': {source}")]
    FileOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to memory map file '{path}': {source}")]
    MemoryMap {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write output file '{path}': {source}")]
    FileWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    // ==================== Cache Format Errors ====================
    #[error("invalid dyld cache magic: expected 'dyld', got {0:?}")]
    InvalidMagic([u8; 4]),

    #[error("unsupported dyld cache format version: {0}")]
    UnsupportedCacheVersion(String),

    #[error("cache header field '{field}' not present in this cache version")]
    MissingHeaderField { field: &'static str },

    #[error("invalid mapping offset {offset:#x} (file size: {file_size:#x})")]
    InvalidMappingOffset { offset: u64, file_size: u64 },

    #[error("address {addr:#x} not found in any cache mapping")]
    AddressNotFound { addr: u64 },

    #[error("file offset {offset:#x} not found in any cache mapping")]
    OffsetNotFound { offset: u64 },

    #[error("subcache file not found: {path}")]
    SubcacheNotFound { path: PathBuf },

    #[error("subcache UUID mismatch for '{path}': expected {expected}, got {actual}")]
    SubcacheUuidMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    // ==================== Mach-O Errors ====================
    #[error("invalid Mach-O magic: {0:#x}")]
    InvalidMachoMagic(u32),

    #[error("unsupported Mach-O file type: {0}")]
    UnsupportedMachoType(u32),

    #[error("Mach-O segment '{name}' not found")]
    SegmentNotFound { name: String },

    #[error("Mach-O section '{segment},{section}' not found")]
    SectionNotFound { segment: String, section: String },

    #[error("load command at offset {offset:#x} extends beyond header")]
    LoadCommandOverflow { offset: usize },

    #[error("unknown load command type: {0:#x}")]
    UnknownLoadCommand(u32),

    #[error("insufficient space for new load commands (need {needed} bytes, have {available})")]
    InsufficientLoadCommandSpace { needed: usize, available: usize },

    // ==================== Slide Info Errors ====================
    #[error("unsupported slide info version: {0}")]
    UnsupportedSlideVersion(u32),

    #[error("invalid slide info at offset {offset:#x}: {reason}")]
    InvalidSlideInfo { offset: u64, reason: String },

    #[error("page start index {index} out of bounds (max: {max})")]
    PageStartOutOfBounds { index: usize, max: usize },

    // ==================== Symbol Errors ====================
    #[error("symbol table not found in Mach-O")]
    SymbolTableNotFound,

    #[error("string table offset {offset} out of bounds (size: {size})")]
    StringTableOverflow { offset: u32, size: u32 },

    #[error("invalid export trie at offset {offset:#x}")]
    InvalidExportTrie { offset: usize },

    #[error("invalid ULEB128 at offset {offset:#x}")]
    InvalidUleb128 { offset: usize },

    #[error("indirect symbol index {index} out of bounds")]
    IndirectSymbolOutOfBounds { index: usize },

    // ==================== Stub Fixer Errors ====================
    #[error("invalid ARM64 instruction at {addr:#x}: {instr:#x}")]
    InvalidArm64Instruction { addr: u64, instr: u32 },

    #[error("unable to resolve stub at {addr:#x}")]
    UnresolvableStub { addr: u64 },

    #[error("branch target {target:#x} out of range from {from:#x}")]
    BranchOutOfRange { from: u64, target: u64 },

    // ==================== ObjC Fixer Errors ====================
    #[error("invalid ObjC class at {addr:#x}")]
    InvalidObjcClass { addr: u64 },

    #[error("invalid ObjC method list at {addr:#x}")]
    InvalidObjcMethodList { addr: u64 },

    #[error("selector not found in cache: {selector}")]
    SelectorNotFound { selector: String },

    #[error("unable to create extra segment: no suitable gap found")]
    NoExtraSegmentSpace,

    // ==================== Image Errors ====================
    #[error("image not found: {name}")]
    ImageNotFound { name: String },

    #[error("image at index {index} out of bounds (total: {total})")]
    ImageIndexOutOfBounds { index: usize, total: usize },

    // ==================== Parse Errors ====================
    #[error("parse error at offset {offset:#x}: {reason}")]
    Parse { offset: usize, reason: String },

    #[error("buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall { needed: usize, available: usize },

    #[error("data alignment error: offset {offset:#x} not aligned to {alignment}")]
    AlignmentError { offset: usize, alignment: usize },
}

/// A specialized Result type for dyld cache operations.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Returns true if this error indicates a recoverable condition.
    ///
    /// Some errors (like missing optional symbols or unresolvable stubs) may be
    /// logged as warnings but shouldn't abort extraction.
    #[inline]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::SelectorNotFound { .. }
                | Error::UnresolvableStub { .. }
                | Error::InvalidObjcClass { .. }
                | Error::InvalidObjcMethodList { .. }
        )
    }

    /// Creates a parse error with a formatted message.
    #[inline]
    pub fn parse(offset: usize, reason: impl Into<String>) -> Self {
        Error::Parse {
            offset,
            reason: reason.into(),
        }
    }

    /// Creates an address not found error.
    #[inline]
    pub fn address_not_found(addr: u64) -> Self {
        Error::AddressNotFound { addr }
    }

    /// Creates a buffer too small error.
    #[inline]
    pub fn buffer_too_small(needed: usize, available: usize) -> Self {
        Error::BufferTooSmall { needed, available }
    }
}
