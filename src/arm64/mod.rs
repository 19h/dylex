//! ARM64 instruction encoding and decoding.
//!
//! This module provides utilities for working with ARM64 instructions,
//! which is needed for stub fixing and callsite patching.

/// ARM64 instruction type.
#[derive(Debug, Clone, Copy)]
pub struct Instruction(pub u32);

impl Instruction {
    /// Creates an instruction from a u32.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw instruction value.
    #[inline]
    pub fn value(self) -> u32 {
        self.0
    }
}

// =============================================================================
// Instruction Detection
// =============================================================================

/// Returns true if the instruction is ADRP.
#[inline]
pub fn is_adrp(instr: u32) -> bool {
    (instr & 0x9F00_0000) == 0x9000_0000
}

/// Returns true if the instruction is ADD (immediate).
#[inline]
pub fn is_add_imm(instr: u32) -> bool {
    (instr & 0x7F80_0000) == 0x1100_0000
}

/// Returns true if the instruction is LDR (unsigned immediate).
#[inline]
pub fn is_ldr_unsigned_imm(instr: u32) -> bool {
    (instr & 0x3B40_0000) == 0x3940_0000
}

/// Returns true if the instruction is BR (branch to register).
#[inline]
pub fn is_br(instr: u32) -> bool {
    (instr & 0xFFFF_FC1F) == 0xD61F_0000
}

/// Returns true if the instruction is B or BL (branch).
#[inline]
pub fn is_branch(instr: u32) -> bool {
    (instr & 0x7C00_0000) == 0x1400_0000
}

/// Returns true if the instruction is BL (branch with link).
#[inline]
pub fn is_bl(instr: u32) -> bool {
    (instr & 0xFC00_0000) == 0x9400_0000
}

/// Returns true if the instruction is BRAA (authenticated branch).
#[inline]
pub fn is_braa(instr: u32) -> bool {
    (instr & 0xFFFF_FC00) == 0xD71F_0800
}

/// Returns true if the instruction is BRAAZ (authenticated branch, zero modifier).
#[inline]
pub fn is_braaz(instr: u32) -> bool {
    (instr & 0xFFFF_FC1F) == 0xD71F_081F
}

/// Returns true if the instruction is a trap (BRK).
#[inline]
pub fn is_trap(instr: u32) -> bool {
    (instr & 0xFFE0_001F) == 0xD420_0000
}

/// Returns true if the instruction is NOP.
#[inline]
pub fn is_nop(instr: u32) -> bool {
    instr == 0xD503_201F
}

/// Returns true if the instruction is RET.
#[inline]
pub fn is_ret(instr: u32) -> bool {
    (instr & 0xFFFF_FC1F) == 0xD65F_0000
}

// =============================================================================
// Instruction Decoding
// =============================================================================

/// Decodes an ADRP instruction, returning the target address.
pub fn decode_adrp(instr: u32, pc: u64) -> u64 {
    let immlo = ((instr >> 29) & 0x3) as u64;
    let immhi = ((instr >> 5) & 0x7_FFFF) as u64;
    let imm = (immhi << 2) | immlo;

    // Sign extend the 21-bit immediate to 64 bits
    let imm = if (imm & (1 << 20)) != 0 {
        imm | 0xFFFF_FFFF_FFE0_0000
    } else {
        imm
    };

    // Scale by 4KB and add to page-aligned PC
    let offset = imm << 12;
    (pc & !0xFFF).wrapping_add(offset as u64)
}

/// Decodes an ADD (immediate) instruction, returning the immediate value.
pub fn decode_add_imm(instr: u32) -> u32 {
    let imm12 = (instr >> 10) & 0xFFF;
    let shift = (instr >> 22) & 0x3;
    if shift == 1 { imm12 << 12 } else { imm12 }
}

/// Decodes an LDR (unsigned immediate) instruction, returning the offset.
pub fn decode_ldr_offset(instr: u32) -> u32 {
    let imm12 = (instr >> 10) & 0xFFF;
    let size = (instr >> 30) & 0x3;
    imm12 << size
}

/// Decodes a B/BL instruction, returning the target address.
pub fn decode_branch(instr: u32, pc: u64) -> u64 {
    let imm26 = (instr & 0x03FF_FFFF) as i64;

    // Sign extend the 26-bit immediate to 64 bits
    let imm26 = if (imm26 & (1 << 25)) != 0 {
        imm26 | !0x03FF_FFFF
    } else {
        imm26
    };

    // Scale by 4 and add to PC
    let offset = imm26 << 2;
    pc.wrapping_add(offset as u64)
}

/// Gets the register number from an ADRP instruction.
pub fn adrp_rd(instr: u32) -> u8 {
    (instr & 0x1F) as u8
}

/// Gets the register number from an ADD/LDR instruction.
pub fn add_rd(instr: u32) -> u8 {
    (instr & 0x1F) as u8
}

/// Gets the source register from a BR instruction.
pub fn br_rn(instr: u32) -> u8 {
    ((instr >> 5) & 0x1F) as u8
}

// =============================================================================
// Instruction Encoding
// =============================================================================

/// Encodes an ADRP instruction.
pub fn encode_adrp(rd: u8, pc: u64, target: u64) -> u32 {
    let target_page = target & !0xFFF;
    let pc_page = pc & !0xFFF;
    let delta = target_page.wrapping_sub(pc_page) as i64;
    let imm = (delta >> 12) as u32;

    let immlo = (imm & 0x3) << 29;
    let immhi = ((imm >> 2) & 0x7_FFFF) << 5;

    0x9000_0000 | immlo | immhi | (rd as u32)
}

/// Encodes an ADD (immediate) instruction.
pub fn encode_add_imm(rd: u8, rn: u8, imm: u32) -> u32 {
    let imm12 = (imm & 0xFFF) << 10;
    let sf = 1u32 << 31; // 64-bit operation

    0x1100_0000 | sf | imm12 | ((rn as u32) << 5) | (rd as u32)
}

/// Encodes an LDR (unsigned immediate) instruction.
pub fn encode_ldr_unsigned(rt: u8, rn: u8, offset: u64) -> u32 {
    let imm12 = ((offset >> 3) & 0xFFF) as u32; // Scale by 8 for 64-bit loads
    let size = 3u32; // 64-bit load

    0x3940_0000 | (size << 30) | (1 << 22) | (imm12 << 10) | ((rn as u32) << 5) | (rt as u32)
}

/// Encodes a BR (branch to register) instruction.
pub fn encode_br(rn: u8) -> u32 {
    0xD61F_0000 | ((rn as u32) << 5)
}

/// Encodes a B (branch) instruction.
pub fn encode_b(pc: u64, target: u64) -> u32 {
    let offset = target.wrapping_sub(pc) as i64;
    let imm26 = ((offset >> 2) & 0x03FF_FFFF) as u32;
    0x1400_0000 | imm26
}

/// Encodes a BL (branch with link) instruction.
pub fn encode_bl(pc: u64, target: u64) -> u32 {
    let offset = target.wrapping_sub(pc) as i64;
    let imm26 = ((offset >> 2) & 0x03FF_FFFF) as u32;
    0x9400_0000 | imm26
}

/// Encodes a BRAA instruction.
pub fn encode_braa(rn: u8, rm: u8) -> u32 {
    0xD71F_0800 | ((rn as u32) << 5) | (rm as u32)
}

/// Encodes a BRAAZ instruction.
pub fn encode_braaz(rn: u8) -> u32 {
    0xD71F_081F | ((rn as u32) << 5)
}

/// Encodes a NOP instruction.
pub fn encode_nop() -> u32 {
    0xD503_201F
}

/// Encodes a BRK (trap) instruction.
pub fn encode_brk(imm: u16) -> u32 {
    0xD420_0000 | ((imm as u32) << 5)
}

// =============================================================================
// High-Level Helpers
// =============================================================================

/// Follows an ADRP+ADD or ADRP+LDR sequence to get the target address.
pub fn follow_adrp_add(adrp_addr: u64, instr0: u32, instr1: u32) -> Option<u64> {
    if !is_adrp(instr0) {
        return None;
    }

    let page = decode_adrp(instr0, adrp_addr);

    if is_add_imm(instr1) {
        let offset = decode_add_imm(instr1);
        Some(page + offset as u64)
    } else if is_ldr_unsigned_imm(instr1) {
        let offset = decode_ldr_offset(instr1);
        Some(page + offset as u64)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_adrp() {
        assert!(is_adrp(0x90000010)); // ADRP X16, ...
        assert!(!is_adrp(0xD61F0200)); // BR X16
    }

    #[test]
    fn test_decode_branch() {
        // BL to nearby address
        let pc = 0x1000;
        let target = decode_branch(0x94000004, pc); // BL +16
        assert_eq!(target, 0x1010);
    }

    #[test]
    fn test_encode_decode_adrp() {
        let pc = 0x1_8000_0000u64;
        let target = 0x1_8000_1000u64;

        let instr = encode_adrp(16, pc, target);
        assert!(is_adrp(instr));

        let decoded = decode_adrp(instr, pc);
        assert_eq!(decoded, target & !0xFFF);
    }

    #[test]
    fn test_is_braa() {
        let instr = encode_braa(16, 17);
        assert!(is_braa(instr));
        assert!(!is_braa(encode_br(16)));
    }

    #[test]
    fn test_encode_b() {
        let pc = 0x1000u64;
        let target = 0x1100u64;

        let instr = encode_b(pc, target);
        assert!(is_branch(instr));

        let decoded = decode_branch(instr, pc);
        assert_eq!(decoded, target);
    }
}
