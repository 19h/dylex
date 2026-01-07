//! Stub fixer for restoring optimized stubs.
//!
//! In the dyld shared cache, stubs are optimized to bypass lazy binding by
//! directly branching to the resolved target. This module restores the normal
//! stub format that goes through the lazy symbol pointer, allowing the binary
//! to work standalone.
//!
//! Additionally, in shared caches, auth stubs often reference a "shared region GOT"
//! that's outside the image. This module rewrites such stubs to use the image's
//! own `__auth_got` section and populates those GOT entries with resolved values.

use crate::arm64;
use crate::dyld::SlidePointer5;
use crate::error::Result;
use crate::macho::SectionInfo;
use tracing::debug;

use super::ExtractionContext;

// =============================================================================
// Stub Format Detection
// =============================================================================

/// Stub format classification.
///
/// Different stub formats are used depending on architecture and optimization level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubFormat {
    /// ADRP + LDR + BR (12 bytes, standard arm64)
    Normal,
    /// ADRP + ADD + BR (12 bytes, optimized - branches directly)
    Optimized,
    /// ADRP + ADD + LDR + BRAA (16 bytes, arm64e standard)
    AuthNormal,
    /// ADRP + ADD + BR + NOP/BRK (16 bytes, arm64e optimized)
    AuthOptimized,
    /// ADRP + LDR + BRAAZ (12 bytes, arm64e resolver)
    AuthResolver,
    /// Simple B instruction
    Branch,
    /// Unrecognized format
    Unknown,
}

/// Detects the stub format from instruction bytes.
pub fn detect_stub_format(data: &[u8], is_arm64e: bool) -> StubFormat {
    if data.len() < 12 {
        return StubFormat::Unknown;
    }

    let instr0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let instr1 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let instr2 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    // Simple branch
    if arm64::is_branch(instr0) {
        return StubFormat::Branch;
    }

    // Must start with ADRP
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

        // ADRP + ADD + BR + trap/nop (auth optimized)
        if arm64::is_add_imm(instr1)
            && arm64::is_br(instr2)
            && (arm64::is_trap(instr3) || arm64::is_nop(instr3))
        {
            return StubFormat::AuthOptimized;
        }
    }

    // ADRP + LDR + BRAAZ (auth resolver)
    if arm64::is_ldr_unsigned_imm(instr1) && arm64::is_braaz(instr2) {
        return StubFormat::AuthResolver;
    }

    StubFormat::Unknown
}

// =============================================================================
// Stub Generation
// =============================================================================

/// Generates a standard ARM64 stub (ADRP + LDR + BR).
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

/// Generates an ARM64e authenticated stub (ADRP + ADD + LDR + BRAA).
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

// =============================================================================
// Stub Section Info
// =============================================================================

/// Information about a stub section.
struct StubSectionInfo {
    /// Section file offset
    offset: usize,
    /// Section virtual address
    addr: u64,
    /// Size of each stub
    stub_size: usize,
    /// Number of stubs
    count: usize,
    /// Reserved1 (index into indirect symbol table) - for future symbol resolution
    #[allow(dead_code)]
    indirect_sym_index: u32,
}

impl StubSectionInfo {
    fn from_section(section: &SectionInfo) -> Option<Self> {
        let stub_size = section.section.reserved2 as usize;
        if stub_size == 0 {
            return None;
        }

        let size = section.section.size as usize;
        let count = size / stub_size;

        Some(Self {
            offset: section.section.offset as usize,
            addr: section.section.addr,
            stub_size,
            count,
            indirect_sym_index: section.section.reserved1,
        })
    }
}

/// Information about a symbol pointer section.
struct SymbolPointerSectionInfo {
    /// Section file offset - for future pointer value updates
    #[allow(dead_code)]
    offset: usize,
    /// Section virtual address
    addr: u64,
    /// Number of pointers
    count: usize,
    /// Reserved1 (index into indirect symbol table) - for future symbol resolution
    #[allow(dead_code)]
    indirect_sym_index: u32,
}

impl SymbolPointerSectionInfo {
    fn from_section(section: &SectionInfo) -> Option<Self> {
        let size = section.section.size as usize;
        let count = size / 8; // 64-bit pointers

        Some(Self {
            offset: section.section.offset as usize,
            addr: section.section.addr,
            count,
            indirect_sym_index: section.section.reserved1,
        })
    }
}

// =============================================================================
// Main Stub Fixer
// =============================================================================

/// Fixes stubs in the extracted image.
///
/// This function:
/// 1. Finds all stub sections (__stubs, __auth_stubs)
/// 2. Finds corresponding symbol pointer sections (__la_symbol_ptr, __auth_got)
/// 3. Detects optimized stubs that branch directly to targets
/// 4. Rewrites optimized stubs to use the normal format through symbol pointers
pub fn fix_stubs(ctx: &mut ExtractionContext) -> Result<()> {
    if !ctx.macho.is_arm64() {
        ctx.info("Skipping stub fixing (not ARM64)");
        return Ok(());
    }

    ctx.info("Fixing stubs...");

    let is_arm64e = ctx.is_arm64e();
    let mut fixed_count = 0;

    // Fix regular stubs
    fixed_count += fix_stub_section(
        ctx,
        "__TEXT",
        "__stubs",
        "__DATA",
        "__la_symbol_ptr",
        is_arm64e,
    )?;

    // Try __DATA_CONST for symbol pointers (newer binaries)
    fixed_count += fix_stub_section(
        ctx,
        "__TEXT",
        "__stubs",
        "__DATA_CONST",
        "__la_symbol_ptr",
        is_arm64e,
    )?;

    // Fix auth stubs (arm64e)
    if is_arm64e {
        fixed_count +=
            fix_stub_section(ctx, "__TEXT", "__auth_stubs", "__DATA", "__auth_got", true)?;
        fixed_count += fix_stub_section(
            ctx,
            "__TEXT",
            "__auth_stubs",
            "__DATA_CONST",
            "__auth_got",
            true,
        )?;
        // Try __AUTH_CONST (newer caches use this segment for auth_got)
        fixed_count += fix_stub_section(
            ctx,
            "__TEXT",
            "__auth_stubs",
            "__AUTH_CONST",
            "__auth_got",
            true,
        )?;
    }

    if fixed_count > 0 {
        ctx.info(&format!("Fixed {} optimized stubs", fixed_count));
    }

    Ok(())
}

/// Fixes a single stub section.
fn fix_stub_section(
    ctx: &mut ExtractionContext,
    stub_segment: &str,
    stub_section: &str,
    ptr_segment: &str,
    ptr_section: &str,
    is_arm64e: bool,
) -> Result<usize> {
    // Get stub section info
    let stubs = match ctx.macho.section(stub_segment, stub_section) {
        Some(s) => s.clone(),
        None => {
            debug!("Stub section {}/{} not found", stub_segment, stub_section);
            return Ok(0);
        }
    };

    let stub_info = match StubSectionInfo::from_section(&stubs) {
        Some(info) => info,
        None => {
            debug!(
                "Could not parse stub section info for {}/{}",
                stub_segment, stub_section
            );
            return Ok(0);
        }
    };

    // Get symbol pointer section info
    let ptrs = match ctx.macho.section(ptr_segment, ptr_section) {
        Some(s) => s.clone(),
        None => {
            debug!("Pointer section {}/{} not found", ptr_segment, ptr_section);
            return Ok(0);
        }
    };

    let ptr_info = match SymbolPointerSectionInfo::from_section(&ptrs) {
        Some(info) => info,
        None => {
            debug!(
                "Could not parse pointer section info for {}/{}",
                ptr_segment, ptr_section
            );
            return Ok(0);
        }
    };

    debug!(
        "Processing {} stubs in {}/{} -> {}/{} ({} pointers)",
        stub_info.count, stub_segment, stub_section, ptr_segment, ptr_section, ptr_info.count
    );

    // Stubs and pointers should have matching indirect symbol indices
    // Each stub corresponds to a lazy symbol pointer
    if stub_info.count != ptr_info.count {
        // Mismatched counts - try to use the minimum
        let count = stub_info.count.min(ptr_info.count);
        if count == 0 {
            return Ok(0);
        }
    }

    let mut fixed = 0;
    let expected_stub_size = if is_arm64e { 16 } else { 12 };

    // Get the slide info value_add for decoding pointers
    // For arm64e caches, this is typically 0x180000000
    let value_add = ctx.cache.slide_info_value_add().unwrap_or(0x180000000);

    // Process each stub
    for i in 0..stub_info.count {
        let stub_offset = stub_info.offset + i * stub_info.stub_size;
        let stub_addr = stub_info.addr + (i * stub_info.stub_size) as u64;
        let ptr_addr = ptr_info.addr + (i * 8) as u64;
        let ptr_offset = ptr_info.offset + i * 8;

        // Read stub bytes
        if stub_offset + stub_info.stub_size > ctx.macho.data.len() {
            break;
        }

        let stub_data = &ctx.macho.data[stub_offset..stub_offset + stub_info.stub_size];
        let format = detect_stub_format(stub_data, is_arm64e);

        debug!(
            "Stub {}: format={:?}, addr=0x{:x}, size={}",
            i, format, stub_addr, stub_info.stub_size
        );

        // For AuthNormal stubs, check if they reference an external GOT
        if is_arm64e && format == StubFormat::AuthNormal && stub_data.len() >= 16 {
            let instr0 =
                u32::from_le_bytes([stub_data[0], stub_data[1], stub_data[2], stub_data[3]]);
            let instr1 =
                u32::from_le_bytes([stub_data[4], stub_data[5], stub_data[6], stub_data[7]]);

            // Decode the GOT address that this stub currently references
            if let Some(current_got_addr) = arm64::follow_adrp_add(stub_addr, instr0, instr1) {
                // Check if this address is within our image
                let is_external = !ctx.macho.contains_addr(current_got_addr);

                if is_external {
                    // Read the pointer value from the shared region in the cache
                    if let Ok(ptr_data) = ctx.cache.data_at_addr(current_got_addr, 8) {
                        let encoded_value = u64::from_le_bytes(ptr_data.try_into().unwrap());

                        if encoded_value != 0 {
                            // Decode the slide info v5 pointer
                            let ptr = SlidePointer5(encoded_value);
                            let decoded_value = if ptr.is_auth() {
                                ptr.runtime_offset() + value_add
                            } else {
                                let runtime_offset = ptr.runtime_offset();
                                let high8 = (ptr.high8() as u64) << 56;
                                runtime_offset + value_add + high8
                            };

                            debug!(
                                "Stub {} at 0x{:x}: external GOT 0x{:x} -> local GOT 0x{:x}, value 0x{:x} -> 0x{:x}",
                                i,
                                stub_addr,
                                current_got_addr,
                                ptr_addr,
                                encoded_value,
                                decoded_value
                            );

                            // Write the decoded value to our local GOT
                            if ptr_offset + 8 <= ctx.macho.data.len() {
                                ctx.macho.data[ptr_offset..ptr_offset + 8]
                                    .copy_from_slice(&decoded_value.to_le_bytes());
                            }

                            // Rewrite the stub to use the local GOT
                            let new_stub = generate_stub_auth(stub_addr, ptr_addr);
                            let mut padded = vec![0u8; stub_info.stub_size];
                            padded[..16].copy_from_slice(&new_stub);

                            // Fill remaining with NOPs
                            for j in (16..stub_info.stub_size).step_by(4) {
                                let nop = arm64::encode_nop();
                                if j + 4 <= stub_info.stub_size {
                                    padded[j..j + 4].copy_from_slice(&nop.to_le_bytes());
                                }
                            }

                            ctx.macho.data[stub_offset..stub_offset + stub_info.stub_size]
                                .copy_from_slice(&padded);
                            fixed += 1;
                        }
                    }
                    continue;
                }
            }
        }

        // Check if stub needs fixing (legacy optimized stub handling)
        let needs_fix = match format {
            StubFormat::Optimized => !is_arm64e,
            StubFormat::AuthOptimized => is_arm64e,
            StubFormat::Branch => true,
            _ => false,
        };

        if needs_fix && stub_info.stub_size >= expected_stub_size {
            // Generate new stub
            let new_stub: Vec<u8> = if is_arm64e {
                generate_stub_auth(stub_addr, ptr_addr).to_vec()
            } else {
                generate_stub_normal(stub_addr, ptr_addr).to_vec()
            };

            // Write new stub (pad with NOPs if needed)
            let mut padded = vec![0u8; stub_info.stub_size];
            padded[..new_stub.len()].copy_from_slice(&new_stub);

            // Fill remaining with NOPs
            for j in (new_stub.len()..stub_info.stub_size).step_by(4) {
                let nop = arm64::encode_nop();
                if j + 4 <= stub_info.stub_size {
                    padded[j..j + 4].copy_from_slice(&nop.to_le_bytes());
                }
            }

            ctx.macho.data[stub_offset..stub_offset + stub_info.stub_size].copy_from_slice(&padded);
            fixed += 1;
        }
    }

    Ok(fixed)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_format_detection() {
        // Branch instruction (B #0)
        let branch = [
            0x00, 0x00, 0x00, 0x14, // B #0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(detect_stub_format(&branch, false), StubFormat::Branch);

        // Too short
        let short = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_stub_format(&short, false), StubFormat::Unknown);
    }

    #[test]
    fn test_stub_generation() {
        // Normal stub should be 12 bytes
        let stub = generate_stub_normal(0x100000, 0x200000);
        assert_eq!(stub.len(), 12);

        // Auth stub should be 16 bytes
        let auth_stub = generate_stub_auth(0x100000, 0x200000);
        assert_eq!(auth_stub.len(), 16);

        // Verify ADRP is first instruction
        let instr0 = u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]);
        assert!(arm64::is_adrp(instr0));
    }

    #[test]
    fn test_normal_stub_structure() {
        let stub = generate_stub_normal(0x1000, 0x2000);

        let instr0 = u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]);
        let instr1 = u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]);
        let instr2 = u32::from_le_bytes([stub[8], stub[9], stub[10], stub[11]]);

        assert!(arm64::is_adrp(instr0), "First instruction should be ADRP");
        assert!(
            arm64::is_ldr_unsigned_imm(instr1),
            "Second instruction should be LDR"
        );
        assert!(arm64::is_br(instr2), "Third instruction should be BR");
    }
}
