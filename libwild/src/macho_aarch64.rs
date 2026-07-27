use crate::bail;
use crate::ensure;
use crate::error;
use crate::macho::MachO;
use linker_utils::elf::AArch64Instruction;
use linker_utils::elf::AllowedRange;
use linker_utils::elf::PAGE_MASK_4KB;
use linker_utils::elf::PageMask;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::elf::SIZE_4KB;
use linker_utils::elf::Sign;
use std::borrow::Cow;

pub(crate) struct MachOAArch64;

// ADRP+ADD+BR symbol stub template.
const STUB_TEMPLATE: &[u8] = &[
    0x10, 0x00, 0x00, 0x90, // ADRP x16, page(got)
    0x10, 0x02, 0x40, 0xf9, // LDR  x16, [x16, #off]
    0x00, 0x02, 0x1f, 0xd6, // BR   x16
];

/// How far a `BRANCH26` reaches. Below this much executable input no branch can be out of range,
/// so thunks can be skipped entirely.
const MIN_BRANCH_RANGE: u64 = 128 * 1024 * 1024;

/// ADRP+ADD+BR: form the target's address relative to the island, then jump to it.
const THUNK_TEMPLATE: &[u8] = &[
    0x10, 0x00, 0x00, 0x90, // ADRP x16, 0
    0x10, 0x02, 0x00, 0x91, // ADD  x16, x16, #0
    0x00, 0x02, 0x1F, 0xD6, // BR   x16
];

const _ASSERTS: () = {
    assert!(STUB_TEMPLATE.len() as u64 == crate::macho::PLT_ENTRY_SIZE);
};

/// Bits [31:22] of a load/store or add/sub immediate instruction - everything above the 12-bit
/// immediate. Rn and Rd live below the immediate and so survive a rewrite of these bits.
const LDR_UIMM_MASK: u32 = 0xffc0_0000;

/// `LDR <Xt>, [<Xn|SP>{, #imm}]` - C6.2.192, size=0b11, V=0, opc=0b01.
const LDR_UIMM_64: u32 = 0xf940_0000;

/// `ADD <Xd|SP>, <Xn|SP>, #imm` - C6.2.5, sf=1, op=0, S=0, sh=0.
const ADD_IMM_64: u32 = 0x9100_0000;

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {}

impl crate::platform::Relaxation for Relaxation {
    fn apply(&self, _section_bytes: &mut [u8], _offset_in_section: &mut u64, _addend: &mut i64) {
        todo!()
    }

    fn rel_info(&self) -> linker_utils::elf::RelocationKindInfo {
        todo!()
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        todo!()
    }

    fn next_modifier(&self) -> linker_utils::relaxation::RelocationModifier {
        todo!()
    }

    fn is_mandatory(&self) -> bool {
        todo!()
    }
}

impl crate::platform::Arch for MachOAArch64 {
    type Relaxation = Relaxation;

    type Platform = MachO;
    fn start_memory_address(_output_kind: crate::output_kind::OutputKind) -> u64 {
        crate::macho::MACHO_START_MEM_ADDRESS
    }
    fn arch_identifier() -> <Self::Platform as crate::platform::Platform>::ArchIdentifier {
        todo!()
    }

    fn get_dynamic_relocation_type(
        _relocation: linker_utils::elf::DynamicRelocationKind,
    ) -> object::macho::RelocationInfo {
        todo!()
    }

    fn write_plt_entry(
        plt_entry: &mut [u8],
        got_address: u64,
        plt_address: u64,
    ) -> crate::error::Result {
        // TODO: For simplicity, we assume now the PLT entry precedes the GOT entry, so we can
        // make the offset calculation in the unsigned type.
        debug_assert!(plt_address < got_address);

        plt_entry.copy_from_slice(STUB_TEMPLATE);
        let plt_page_address = plt_address & !PAGE_MASK_4KB;
        let offset = got_address.wrapping_sub(plt_page_address);
        ensure!(
            offset < (1 << 32),
            "Mach-O stub is more than 4GiB away from GOT"
        );
        AArch64Instruction::Adr.write_to_value(offset / SIZE_4KB, false, &mut plt_entry[0..4]);
        AArch64Instruction::MachOLow12.write_to_value(
            offset & PAGE_MASK_4KB,
            false,
            &mut plt_entry[4..8],
        );
        Ok(())
    }

    fn relocation_from_raw(
        rel: object::macho::RelocationInfo,
    ) -> crate::error::Result<RelocationKindInfo> {
        let rel_size_in_bytes = 1 << rel.r_length;
        let rel_size = RelocationSize::ByteSize(rel_size_in_bytes);
        let rel_kind = if rel.r_pcrel {
            RelocationKind::Relative
        } else {
            RelocationKind::Absolute
        };

        // Only a branch has a reach short enough to need one, and only a branch can be redirected
        // to an island without changing what the instruction means.
        let mut is_thunkable = false;

        let (kind, size, mask, range, alignment) = match rel.r_type {
            object::macho::ARM64_RELOC_UNSIGNED => {
                (rel_kind, rel_size, None, AllowedRange::no_check(), 1)
            }
            object::macho::ARM64_RELOC_BRANCH26 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                is_thunkable = true;
                (
                    rel_kind,
                    RelocationSize::bit_mask_aarch64(2, 28, AArch64Instruction::JumpCall),
                    None,
                    AllowedRange::from_bit_size(28, Sign::Signed),
                    4,
                )
            }
            object::macho::ARM64_RELOC_PAGE21 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    rel_kind,
                    RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
                    Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
                    AllowedRange::from_bit_size(33, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_PAGEOFF12 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationKind::AbsoluteLowPart,
                    RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::MachOLow12),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            object::macho::ARM64_RELOC_GOT_LOAD_PAGE21 => {
                debug_assert_eq!(rel_kind, RelocationKind::Relative);
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationKind::GotRelative,
                    RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
                    Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
                    AllowedRange::from_bit_size(33, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationKind::Got,
                    RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::MachOLow12),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            // A thread-local reference names the variable's `tlv_descriptor` in `__thread_vars`
            // rather than the variable itself. The addressing sequence is the same shape as a GOT
            // load, and because the descriptor is always defined in this image, it relaxes the
            // same way - see `relax_got_load`.
            object::macho::ARM64_RELOC_TLVP_LOAD_PAGE21 => {
                debug_assert_eq!(rel_kind, RelocationKind::Relative);
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationKind::GotRelative,
                    RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
                    Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
                    AllowedRange::from_bit_size(33, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationKind::Got,
                    RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::MachOLow12),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            object::macho::ARM64_RELOC_POINTER_TO_GOT => {
                // Stores the address of the symbol's GOT entry rather than the symbol itself.
                // When PC-relative it's the usual 4-byte delta from the place, which is what
                // `__gcc_except_tab` uses to reach typeinfo that lives in another image.
                let kind = if rel.r_pcrel {
                    RelocationKind::GotRelative
                } else {
                    RelocationKind::Got
                };
                (kind, rel_size, None, AllowedRange::no_check(), 1)
            }
            // Half of a pair: the following `ARM64_RELOC_UNSIGNED` at the same address names the
            // other end, and the slot gets the distance between them. Layout only needs to know
            // that the symbol is referenced by address and wants no indirection, which is what this
            // kind says; the writer applies the two together (`apply_subtractor_pair`), so nothing
            // ever asks this arm to produce a value on its own.
            object::macho::ARM64_RELOC_SUBTRACTOR => (
                RelocationKind::AbsoluteSubtraction,
                rel_size,
                None,
                AllowedRange::no_check(),
                1,
            ),
            _ => bail!("Unknown relocation: {}", rel.r_type),
        };
        Ok(RelocationKindInfo {
            alignment,
            bias: 0,
            kind,
            mask,
            range,
            size,
            thunkable: is_thunkable,
        })
    }

    fn thunk_config() -> Option<crate::platform::ThunkConfig> {
        Some(crate::platform::ThunkConfig {
            primary_function_part_id: const {
                crate::output_section_id::TEXT
                    .part_id_with_alignment(crate::alignment::Alignment { exponent: 2 })
            },
            min_branch_range: MIN_BRANCH_RANGE,
            thunk_size: THUNK_TEMPLATE.len() as u64,
        })
    }

    /// Writes a branch island: compute the target's page, add its offset, and jump there.
    ///
    /// PC-relative throughout, which matters because a Mach-O executable is always position
    /// independent - an absolute sequence would need a rebase, and a rebase in `__TEXT` is not
    /// something dyld will apply.
    fn write_thunk(thunk_address: u64, target_address: u64, buf: &mut [u8]) {
        buf.copy_from_slice(THUNK_TEMPLATE);

        let thunk_page = thunk_address & !PAGE_MASK_4KB;
        let target_page = target_address & !PAGE_MASK_4KB;
        let page_diff = (target_page as i64).wrapping_sub(thunk_page as i64);
        let page_count = (page_diff / SIZE_4KB as i64) as u64 & 0x1F_FFFF;

        AArch64Instruction::Adr.write_to_value(page_count, false, &mut buf[0..4]);
        AArch64Instruction::Add.write_to_value(
            target_address & PAGE_MASK_4KB,
            false,
            &mut buf[4..8],
        );
    }

    fn relax_got_load(
        rel: object::macho::RelocationInfo,
        instruction: &mut [u8],
    ) -> crate::error::Result {
        match rel.r_type {
            // The ADRP half needs no rewrite: it forms a page address either way, and the
            // relocation value it is given is now the symbol's page rather than the GOT slot's.
            object::macho::ARM64_RELOC_GOT_LOAD_PAGE21
            | object::macho::ARM64_RELOC_TLVP_LOAD_PAGE21 => Ok(()),

            // `ldr xD, [xN, #imm]` becomes `add xD, xN, #imm`. Rn/Rd are kept; the immediate is
            // filled in afterwards by `AArch64Instruction::MachOLow12`, which derives its scaling
            // from the opcode, so the opcode has to be rewritten first.
            object::macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12
            | object::macho::ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => {
                let bytes: [u8; 4] = instruction
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| error!("Truncated ARM64 instruction"))?;
                let value = u32::from_le_bytes(bytes);

                ensure!(
                    value & LDR_UIMM_MASK == LDR_UIMM_64,
                    "Expected a 64-bit LDR (immediate) for {}, found instruction 0x{value:08x}",
                    Self::rel_type_to_string(rel),
                );

                let relaxed = ADD_IMM_64 | (value & !LDR_UIMM_MASK);
                instruction[..4].copy_from_slice(&relaxed.to_le_bytes());

                Ok(())
            }

            _ => bail!(
                "Cannot relax non GOT-load relocation: {}",
                Self::rel_type_to_string(rel)
            ),
        }
    }

    fn rel_type_to_string(info: object::macho::RelocationInfo) -> Cow<'static, str> {
        let r_type = info.r_type;
        if let Some(name) = object::macho::NAMES_ARM64_RELOC.name(r_type) {
            Cow::Borrowed(name)
        } else {
            Cow::Owned(format!("Unknown arm64 relocation type 0x{r_type:x}"))
        }
    }

    fn tp_offset_start(_layout: &crate::layout::Layout<Self::Platform>) -> u64 {
        todo!()
    }

    fn get_property_class(_property_type: u32) -> Option<crate::elf::PropertyClass> {
        todo!()
    }

    fn merge_eflags(_eflags: impl Iterator<Item = u32>) -> crate::error::Result<u32> {
        todo!()
    }

    fn high_part_relocations() -> &'static [object::macho::RelocationInfo] {
        todo!()
    }

    fn get_source_info<'data>(
        _object: &<Self::Platform as crate::platform::Platform>::File<'data>,
        _relocations: &<Self::Platform as crate::platform::Platform>::RelocationSections,
        _section: &<Self::Platform as crate::platform::Platform>::SectionHeader,
        _offset_in_section: u64,
    ) -> crate::error::Result<crate::platform::SourceInfo> {
        Ok(crate::platform::SourceInfo(None))
    }

    fn new_relaxation(
        _relocation_kind: object::macho::RelocationInfo,
        _section_bytes: &[u8],
        _offset_in_section: u64,
        _flags: crate::value_flags::ValueFlags,
        _output_kind: crate::output_kind::OutputKind,
        _section_flags: <Self::Platform as crate::platform::Platform>::SectionFlags,
        _non_zero_address: bool,
        _relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Arch as _;

    fn relocation(r_type: u8) -> object::macho::RelocationInfo {
        object::macho::RelocationInfo {
            r_address: 0,
            r_symbolnum: 0,
            r_pcrel: false,
            r_length: 2,
            r_extern: true,
            r_type,
        }
    }

    /// The relaxed sequence has to be exactly what ld64 emits, since the same test programs are
    /// diffed against it. `add x8, x8, #0x8` is what ld64 produces where the unrelaxed form would
    /// have been `ldr x8, [x8, #<got slot>]`.
    #[test]
    fn got_load_pageoff12_becomes_add() {
        // `ldr x8, [x8, #0x8]`. The immediate is scaled by 8 in this encoding, hence imm12 == 1.
        let mut instruction = 0xf940_0508_u32.to_le_bytes();

        MachOAArch64::relax_got_load(
            relocation(object::macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12),
            &mut instruction,
        )
        .unwrap();

        // Writing the relocation value is what the caller does next. It has to land unscaled now
        // that the instruction is an ADD, which `MachOLow12` works out from the opcode.
        AArch64Instruction::MachOLow12.write_to_value(0x8, false, &mut instruction);

        // `add x8, x8, #0x8`
        assert_eq!(u32::from_le_bytes(instruction), 0x9100_2108);
    }

    /// The ADRP of the pair is already correct; only the value written into it changes.
    #[test]
    fn got_load_page21_is_left_alone() {
        // `adrp x8, #0`
        let mut instruction = 0x9000_0008_u32.to_le_bytes();

        MachOAArch64::relax_got_load(
            relocation(object::macho::ARM64_RELOC_GOT_LOAD_PAGE21),
            &mut instruction,
        )
        .unwrap();

        assert_eq!(u32::from_le_bytes(instruction), 0x9000_0008);
    }

    /// Silently leaving an unrecognised instruction alone would produce a binary that loads
    /// through a symbol's address instead of using it, so refuse instead.
    #[test]
    fn unexpected_instruction_is_rejected() {
        // `add x8, x8, #0x8` - already relaxed, so not something we should be asked to relax.
        let mut instruction = 0x9100_2108_u32.to_le_bytes();

        assert!(
            MachOAArch64::relax_got_load(
                relocation(object::macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12),
                &mut instruction,
            )
            .is_err()
        );
    }
}
