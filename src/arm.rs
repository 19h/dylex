//! AArch32 direct branch decoding. Addresses retain the target Thumb state bit.
//! Instruction masks follow ARM ARM encodings and dyld's ARM stub optimizer.

/// Length of the next Thumb instruction, in bytes. Returns None when truncated.
/// O(1) time and space; instruction halfwords use little-endian byte order.
pub fn thumb_instruction_size(data: &[u8]) -> Option<usize> {
    let h = u16::from_le_bytes(data.get(..2)?.try_into().ok()?);
    let size = if h >> 11 >= 0b11101 { 4 } else { 2 };
    (data.len() >= size).then_some(size)
}

/// Decodes unconditional B, BL, and immediate BLX in ARM or Thumb mode.
/// Includes 16-bit Thumb B and 32-bit Thumb-2 B.W/BL/BLX. PC arithmetic wraps
/// at 32 bits. Conditional branches and register targets return None.
/// O(1) time and space; callers establish instruction boundaries and mode.
pub fn branch_target(data: &[u8], pc: u32, thumb: bool) -> Option<u32> {
    if !thumb {
        let instruction = u32::from_le_bytes(data.get(..4)?.try_into().ok()?);
        if instruction & 0xfe00_0000 == 0xfa00_0000 {
            let immediate = ((instruction & 0x00ff_ffff) << 2) | ((instruction >> 23) & 2);
            let delta = ((immediate << 6) as i32) >> 6;
            return Some(pc.wrapping_add(8).wrapping_add_signed(delta) | 1);
        }
        if instruction & 0xfe00_0000 != 0xea00_0000 {
            return None;
        }
        let delta = ((instruction << 8) as i32) >> 6;
        return Some(pc.wrapping_add(8).wrapping_add_signed(delta));
    }
    let first = u16::from_le_bytes(data.get(..2)?.try_into().ok()?) as u32;
    if first & 0xf800 == 0xe000 {
        let delta = (((first & 0x7ff) << 21) as i32) >> 20;
        return Some(pc.wrapping_add(4).wrapping_add_signed(delta) | 1);
    }
    if first & 0xf800 != 0xf000 {
        return None;
    }
    let second = u16::from_le_bytes(data.get(2..4)?.try_into().ok()?) as u32;
    let kind = second & 0xd000;
    if !matches!(kind, 0x9000 | 0xd000 | 0xc000) {
        return None;
    }
    let s = (first >> 10) & 1;
    let i1 = ((second >> 13) & 1) ^ s ^ 1;
    let i2 = ((second >> 11) & 1) ^ s ^ 1;
    let immediate =
        (s << 24) | (i1 << 23) | (i2 << 22) | ((first & 0x3ff) << 12) | ((second & 0x7ff) << 1);
    let delta = ((immediate << 7) as i32) >> 7;
    if kind == 0xc000 {
        if second & 1 != 0 {
            return None;
        }
        Some((pc.wrapping_add(4) & !3).wrapping_add_signed(delta))
    } else {
        Some(pc.wrapping_add(4).wrapping_add_signed(delta) | 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_arm_encodings_include_negative_offsets_and_state_changes() {
        for (instruction, target) in [
            (0xea000000u32, 0x1008),
            (0xebfffffe, 0x1000),
            (0xfa000000, 0x1009),
            (0xfb000000, 0x100b),
        ] {
            assert_eq!(
                branch_target(&instruction.to_le_bytes(), 0x1000, false),
                Some(target)
            );
        }
        for instruction in [0x1a000000u32, 0xe12fff1e, 0xe1a00000] {
            assert_eq!(
                branch_target(&instruction.to_le_bytes(), 0x1000, false),
                None
            );
        }
    }
    #[test]
    fn literal_thumb_encodings_respect_halfwords_and_blx_pc_alignment() {
        for (halfwords, pc, target) in [
            ([0xe000u16, 0], 0x1000, 0x1005),
            ([0xe7fe, 0], 0x1000, 0x1001),
            ([0xf000, 0xb800], 0x1000, 0x1005),
            ([0xf000, 0xf800], 0x1000, 0x1005),
            ([0xf7ff, 0xfffe], 0x1000, 0x1001),
            ([0xf000, 0xe800], 0x1002, 0x1004),
        ] {
            let bytes: Vec<_> = halfwords.iter().flat_map(|h| h.to_le_bytes()).collect();
            assert_eq!(branch_target(&bytes, pc, true), Some(target));
        }
        assert_eq!(thumb_instruction_size(&[0x00, 0xf0]), None);
        assert_eq!(thumb_instruction_size(&[0x70, 0x47, 0x00, 0xf0]), Some(2));
        assert_eq!(branch_target(&[0x00, 0xf0, 0x01, 0xe8], 0x1000, true), None);
    }
}
