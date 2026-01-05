//! Stub fixer for restoring optimized stubs.
//!
//! In the dyld shared cache, stubs are optimized to bypass lazy binding.
//! This module restores them to use the normal stub -> symbol pointer -> stub helper chain.

use crate::arm64;
use crate::error::Result;

use super::ExtractionContext;

/// Fixes stubs and callsites in the extracted image.
pub fn fix_stubs(ctx: &mut ExtractionContext) -> Result<()> {
    if !ctx.macho.is_arm64() {
        ctx.info("Skipping stub fixing (not ARM64)");
        return Ok(());
    }

    ctx.info("Fixing stubs...");

    // TODO: Full stub fixing implementation
    // This requires:
    // 1. Building a symbolizer from dependency exports
    // 2. Finding all symbol pointers and their symbols
    // 3. Fixing stub helper references
    // 4. Generating new stubs where needed
    // 5. Fixing callsites that point to external functions

    Ok(())
}

/// Stub format detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubFormat {
    /// ADRP + LDR + BR (12 bytes, normal arm64)
    Normal,
    /// ADRP + ADD + BR (12 bytes, optimized)
    Optimized,
    /// ADRP + ADD + LDR + BRAA (16 bytes, arm64e normal)
    AuthNormal,
    /// ADRP + ADD + BR + TRAP (16 bytes, arm64e optimized)
    AuthOptimized,
    /// ADRP + LDR + BRAAZ (12 bytes, arm64e resolver)
    AuthResolver,
    /// Complex resolver function
    Resolver,
    /// Simple branch instruction
    Branch,
    /// Unknown format
    Unknown,
}

/// Detects the stub format at the given offset.
pub fn detect_stub_format(data: &[u8], is_arm64e: bool) -> StubFormat {
    if data.len() < 12 {
        return StubFormat::Unknown;
    }

    let instr0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let instr1 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let instr2 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    // Check for simple branch
    if arm64::is_branch(instr0) {
        return StubFormat::Branch;
    }

    // Check for ADRP start
    if !arm64::is_adrp(instr0) {
        return StubFormat::Unknown;
    }

    // ADRP + LDR + BR (normal stub)
    if arm64::is_ldr_unsigned_imm(instr1) && arm64::is_br(instr2) {
        return StubFormat::Normal;
    }

    // ADRP + ADD + BR (optimized stub)
    if arm64::is_add_imm(instr1) && arm64::is_br(instr2) {
        return StubFormat::Optimized;
    }

    // ARM64e formats need 16 bytes
    if is_arm64e && data.len() >= 16 {
        let instr3 = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

        // ADRP + ADD + LDR + BRAA (auth normal)
        if arm64::is_add_imm(instr1) && arm64::is_ldr_unsigned_imm(instr2) && arm64::is_braa(instr3)
        {
            return StubFormat::AuthNormal;
        }

        // ADRP + ADD + BR + TRAP (auth optimized)
        if arm64::is_add_imm(instr1) && arm64::is_br(instr2) && arm64::is_trap(instr3) {
            return StubFormat::AuthOptimized;
        }
    }

    // ADRP + LDR + BRAAZ (auth resolver)
    if arm64::is_ldr_unsigned_imm(instr1) && arm64::is_braaz(instr2) {
        return StubFormat::AuthResolver;
    }

    StubFormat::Unknown
}

/// Generates a normal stub (ADRP + LDR + BR).
pub fn generate_stub_normal(stub_addr: u64, ptr_addr: u64) -> [u8; 12] {
    let adrp = arm64::encode_adrp(16, stub_addr, ptr_addr);
    let ldr = arm64::encode_ldr_unsigned(16, 16, (ptr_addr & 0xFFF) >> 3);
    let br = arm64::encode_br(16);

    let mut result = [0u8; 12];
    result[0..4].copy_from_slice(&adrp.to_le_bytes());
    result[4..8].copy_from_slice(&ldr.to_le_bytes());
    result[8..12].copy_from_slice(&br.to_le_bytes());
    result
}

/// Generates an auth stub (ADRP + ADD + LDR + BRAA).
pub fn generate_stub_auth(stub_addr: u64, ptr_addr: u64) -> [u8; 16] {
    let adrp = arm64::encode_adrp(17, stub_addr, ptr_addr);
    let add = arm64::encode_add_imm(17, 17, (ptr_addr & 0xFFF) as u32);
    let ldr = arm64::encode_ldr_unsigned(16, 17, 0);
    let braa = arm64::encode_braa(16, 17);

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&adrp.to_le_bytes());
    result[4..8].copy_from_slice(&add.to_le_bytes());
    result[8..12].copy_from_slice(&ldr.to_le_bytes());
    result[12..16].copy_from_slice(&braa.to_le_bytes());
    result
}
