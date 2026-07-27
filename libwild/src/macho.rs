use crate::OutputKind;
use crate::alignment;
use crate::alignment::Alignment;
use crate::alignment::MACHO_PAGE_ALIGNMENT;
use crate::args::macho::MachOArgs;
use crate::ensure;
use crate::error;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::file_writer::copy_section_data;
use crate::grouping::SequencedInput;
use crate::input_data::FileId;
use crate::layout;
use crate::layout::HandlerData as _;
use crate::layout::Layout;
use crate::layout::OutputRecordLayout;
use crate::layout::Resolution;
use crate::layout::StubLibraryLayoutState;
use crate::layout::SymbolCopyInfo;
use crate::layout::SymbolResolutions;
use crate::layout_rules::SectionKind;
use crate::layout_rules::SectionRule;
use crate::layout_rules::SectionRuleOutcome;
use crate::macho_object::CodeSignatureBlobIndex;
use crate::macho_object::CodeSignatureCodeDirectory;
use crate::macho_object::CodeSignatureSuperBlob;
use crate::macho_object::DyldChainedFixupsHeader;
use crate::macho_object::DyldChainedStartsInSegment;
use crate::macho_writer;
use crate::output_section_id;
use crate::output_section_id::NUM_BUILT_IN_SECTIONS;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrderBuilder;
use crate::output_section_id::SectionName;
use crate::output_section_id::SectionOutputInfo;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::part_id;
use crate::part_id::PartId;
use crate::platform;
use crate::platform::Args;
use crate::platform::ObjectFile;
use crate::resolution;
use crate::symbol_db::SymbolId;
use crate::symbol_db::Visibility;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use anyhow::Context;
use itertools::Itertools;
use object::Endianness;
use object::SymbolIndex;
use object::macho;
use object::macho::N_ABS;
use object::macho::N_EXT;
use object::macho::N_PEXT;
use object::macho::N_SECT;
use object::macho::N_WEAK_DEF;
use object::macho::SEG_LINKEDIT;
use object::macho::Section64;
pub use object::macho::SectionFlags;
use object::read::macho::MachHeader;
use object::read::macho::Nlist;
use object::read::macho::Section;
use object::read::macho::Segment;
use std::borrow::Cow;
use std::num::NonZeroU8;
use std::num::NonZeroU64;
use std::ops::Range;

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct MachO;

const LE: Endianness = Endianness::Little;

/// Mach-O uses a zero page for all 32bit addresses and thus we begin the memory
/// offsets right after that (1GiB).
pub(crate) const MACHO_START_MEM_ADDRESS: u64 = 0x1_0000_0000;

/// The command alignment is 8B for 64-bit platforms.
pub(crate) const MACHO_COMMAND_ALIGNMENT: usize = 8;

/// A path to the default dynamic linker.
pub(crate) const DYLINKER_PATH: &[u8] = b"/usr/lib/dyld";

// TODO: Getting the number of active segments in epilogue depends on determine_header_size
// which is called later for the prologue. We potentially over-allocate a couple of bytes.
pub(crate) const MAX_SEGMENT_COUNT: usize = 6;

/// The number of segments that can hold chained fixups, and therefore the number of
/// `dyld_chained_starts_in_segment` records the fixup table might have to hold. Applying a fixup
/// is a store into the segment, so only the writable data segments qualify: `__DATA` and
/// `__DATA_CONST`.
pub(crate) const MAX_FIXUP_SEGMENT_COUNT: usize = 2;

pub(crate) const CHAINED_FIXUP_TABLE_BASE_SIZE: u64 = (size_of::<ChainedFixupsHeader>()
    + size_of::<u32>() * (MAX_SEGMENT_COUNT + /* leading segment count */ 1)
    + MAX_FIXUP_SEGMENT_COUNT * size_of::<DyldChainedStartsInSegment>()
    // The imports table is aligned, so there may be padding before it.
    + size_of::<u32>()) as u64;
pub(crate) const CHAINED_FIXUP_IMPORT_SIZE: u64 = size_of::<u32>() as u64;
pub(crate) const CHAINED_FIXUP_PAGE_START_SIZE: u64 = size_of::<u16>() as u64;
pub(crate) const GOT_ENTRY_SIZE: u64 = 8;
/// One `u32` symbol index per symbol-pointer or stub slot.
pub(crate) const INDIRECT_SYMTAB_ENTRY_SIZE: u64 = size_of::<u32>() as u64;
pub(crate) const PLT_ENTRY_SIZE: u64 = 12;

/// One `compact_unwind_entry`: the function's address, its length, how to unwind it, and where its
/// personality routine and language-specific data are.
pub(crate) const COMPACT_UNWIND_ENTRY_SIZE: u64 = 32;
/// Offset of the personality field within an entry.
pub(crate) const COMPACT_UNWIND_PERSONALITY_OFFSET: u64 = 16;
/// Offset of the language-specific data area field within an entry.
pub(crate) const COMPACT_UNWIND_LSDA_OFFSET: u64 = 24;

/// What one function costs in `__unwind_info`: eight bytes for its second-level entry, and eight
/// more for an LSDA index entry in case it has one. Reserving the LSDA entry for every function
/// rather than counting them means the size is known from the entry count alone, which is what lets
/// it be reserved before the table is built. The slack is at most eight bytes per function.
pub(crate) const UNWIND_INFO_BYTES_PER_ENTRY: u64 = 16;

/// `unwind_info_section_header`: version, then a (offset, count) pair for each of the common
/// encodings, the personalities and the index.
pub(crate) const UNWIND_INFO_HEADER_SIZE: u64 = 7 * size_of::<u32>() as u64;
/// An entry's encoding names its personality by a two-bit index into the personality array, so
/// there is no room for a fourth.
pub(crate) const UNWIND_INFO_MAX_PERSONALITIES: u64 = 3;
/// `unwind_info_section_header_index_entry`: the first function on the page, where the page is, and
/// where its LSDA index starts.
pub(crate) const UNWIND_INFO_INDEX_ENTRY_SIZE: u64 = 3 * size_of::<u32>() as u64;
/// `unwind_info_regular_second_level_page_header`: the kind, then where its entries start and how
/// many there are.
pub(crate) const UNWIND_INFO_PAGE_HEADER_SIZE: u64 = 2 * size_of::<u32>() as u64;
/// How many functions one second-level page describes. The page is addressed by 16-bit offsets, so
/// it can't exceed 64 KiB; ld64 uses 4 KiB pages and so do we.
pub(crate) const UNWIND_INFO_PAGE_CAPACITY: u64 =
    (4096 - UNWIND_INFO_PAGE_HEADER_SIZE) / UNWIND_INFO_ENTRY_SIZE;
/// `unwind_info_regular_second_level_entry`: the function's address and how to unwind it.
pub(crate) const UNWIND_INFO_ENTRY_SIZE: u64 = 2 * size_of::<u32>() as u64;
/// `unwind_info_section_header_lsda_index_entry`: the function's address and its LSDA's.
pub(crate) const UNWIND_INFO_LSDA_ENTRY_SIZE: u64 = 2 * size_of::<u32>() as u64;
/// The only version of the format there has ever been.
pub(crate) const UNWIND_SECTION_VERSION: u32 = 1;
/// A second-level page whose entries each carry their own encoding, as opposed to the compressed
/// form, where they carry an index into the common encodings array instead.
pub(crate) const UNWIND_SECOND_LEVEL_REGULAR: u32 = 2;
/// Selects which of the four ways of describing a function an encoding uses.
pub(crate) const UNWIND_ARM64_MODE_MASK: u32 = 0x0f00_0000;
/// The function can't be described compactly, so the encoding names a DWARF frame in `__eh_frame`
/// instead - by its offset, in the remaining bits.
pub(crate) const UNWIND_ARM64_MODE_DWARF: u32 = 0x0300_0000;
pub(crate) const UNWIND_ARM64_DWARF_SECTION_OFFSET: u32 = 0x00ff_ffff;
/// Position of the personality index within a compact unwind encoding. Two bits wide, which is what
/// limits an image to three personality routines.
pub(crate) const UNWIND_PERSONALITY_SHIFT: u32 = 28;

pub(crate) const SEG_DATA_CONST: &str = "__DATA_CONST";

type SectionHeader = Section64<crate::macho::Endianness>;
type SectionTable<'data> = &'data [Section64<crate::macho::Endianness>];
type SymbolTable<'data> = object::read::macho::SymbolTable<'data, macho::MachHeader64<Endianness>>;
type SymtabEntry = object::macho::Nlist64<Endianness>;
type Relocation = object::macho::Relocation<Endianness>;

pub(crate) type FileHeader = object::macho::MachHeader64<Endianness>;
pub(crate) type SegmentCommand = object::macho::SegmentCommand64<Endianness>;
pub(crate) type SectionEntry = object::macho::Section64<Endianness>;
pub(crate) type EntryPointCommand = object::macho::EntryPointCommand<Endianness>;
pub(crate) type DylinkerCommand = object::macho::DylinkerCommand<Endianness>;
pub(crate) type DylibCommand = object::macho::DylibCommand<Endianness>;
pub(crate) type CodeSignatureCommand = object::macho::LinkeditDataCommand<Endianness>;
pub(crate) type DyldChainedFixupsCommand = object::macho::LinkeditDataCommand<Endianness>;
pub(crate) type ChainedFixupsHeader = DyldChainedFixupsHeader;
pub(crate) type SymtabCommand = object::macho::SymtabCommand<Endianness>;
pub(crate) type DysymtabCommand = object::macho::DysymtabCommand<Endianness>;
pub(crate) type BuildVersionCommand = object::macho::BuildVersionCommand<Endianness>;
pub(crate) type UuidCommand = object::macho::UuidCommand<Endianness>;

// TODO: move the following data types to object crate

pub(crate) const CS_SECTION_ALIGNMENT_EXP: u8 = 4;
pub(crate) const CS_SECTION_ALIGNMENT: u64 = 2u64.pow(CS_SECTION_ALIGNMENT_EXP as u32);

pub(crate) const CS_BLOB_HEADERS_SIZE: u64 =
    (size_of::<CodeSignatureSuperBlob>() + size_of::<CodeSignatureBlobIndex>()) as u64;
const _: () = assert!(CS_BLOB_HEADERS_SIZE.is_multiple_of(8));
pub(crate) const CS_HEADERS_SIZE: u64 =
    CS_BLOB_HEADERS_SIZE + size_of::<CodeSignatureCodeDirectory>() as u64;
pub(crate) const CS_BLOCK_SIZE_EXP: u8 = 12;
pub(crate) const CS_BLOCK_SIZE: usize = 2usize.pow(CS_BLOCK_SIZE_EXP as u32);
// SHA-256 is being used
pub(crate) const CS_HASH_SIZE: u8 = 32;

pub(crate) fn code_signature_identifier(args: &MachOArgs) -> &[u8] {
    args.output()
        .file_name()
        .expect("File name should be present at this point")
        .as_encoded_bytes()
}

pub(crate) fn code_signature_padded_identifier_size(args: &MachOArgs) -> u64 {
    (code_signature_identifier(args).len() as u64 + 1).next_multiple_of(CS_SECTION_ALIGNMENT)
}

pub(crate) fn load_dylib_command_size(path: &[u8]) -> usize {
    (size_of::<DylibCommand>() + path.len() + 1).next_multiple_of(MACHO_COMMAND_ALIGNMENT)
}

#[derive(Debug, Default)]
pub(crate) struct LayoutExt {
    /// Imported STUB library symbols, sorted by GOT.
    pub(crate) imported_symbols: Vec<ImportedSymbolWithResolution>,

    /// Symbols defined in this image that were nonetheless given a `__got` slot, because something
    /// stores the address of the slot rather than reading through it. Sorted by slot address.
    /// Unlike an import, the slot's contents are known at link time - it holds the symbol's own
    /// address, and needs a rebase so that it follows the image when dyld slides it.
    pub(crate) local_got_symbols: Vec<LocalGotSymbol>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LocalGotSymbol {
    pub(crate) got_address: NonZeroU64,
    pub(crate) value: u64,
}

#[derive(Debug, Default)]
pub(crate) struct FinaliseSizesExt {
    imported_libraries: Vec<FileId>,
    imported_symbols: Vec<SymbolId>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PreludeLayoutExt {
    pub(crate) imported_library_file_ids: Vec<FileId>,
    pub(crate) load_dylib_command_sizes: Vec<usize>,
    pub(crate) load_command_count: usize,
}

#[derive(derive_more::Debug, Clone, Copy)]
pub(crate) struct ImportedSymbolWithResolution {
    pub(crate) symbol_id: SymbolId,
    pub(crate) got_address: NonZeroU64,
    pub(crate) plt_address: Option<NonZeroU64>,
}

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],
    #[debug(skip)]
    pub(crate) symbols: SymbolTable<'data>,
    #[allow(unused)]
    pub(crate) flags: object::macho::FileFlags,
    kind: ObjectKind<'data>,
}

/// The pieces an input object is split into so that unreferenced ones can be dropped.
///
/// A Mach-O object puts every function in one `__text` rather than one section each, and marks the
/// header `MH_SUBSECTIONS_VIA_SYMBOLS` to say that the sections may be cut at symbol boundaries.
/// Splitting there is what lets the rest of the linker - which reasons about whole sections - drop
/// an individual function, because after the split a function *is* a whole section.
#[derive(Debug)]
struct Atoms {
    /// One synthesised section per atom, in address order within each parent.
    sections: Vec<SectionHeader>,

    /// Which real section each atom came from, so its relocations can be found.
    parents: Vec<u32>,

    /// The atoms belonging to each real section, as a range into the two vectors above.
    by_parent: Vec<Range<u32>>,
}

impl Atoms {
    /// Splits every section of `sections` at the addresses in `symbol_addresses`.
    ///
    /// `symbol_addresses` holds, for each real section, the addresses of the symbols defined in it.
    /// It doesn't need to be sorted or free of duplicates.
    fn split(
        sections: &[SectionHeader],
        symbol_addresses: &mut [Vec<u64>],
        subsections_via_symbols: bool,
    ) -> Self {
        let mut atoms = Atoms {
            sections: Vec::with_capacity(sections.len()),
            parents: Vec::with_capacity(sections.len()),
            by_parent: Vec::with_capacity(sections.len()),
        };

        for (index, section) in sections.iter().enumerate() {
            let start = atoms.sections.len() as u32;
            atoms.push_atoms_of(
                section,
                index as u32,
                &mut symbol_addresses[index],
                subsections_via_symbols,
            );
            atoms.by_parent.push(start..atoms.sections.len() as u32);
        }

        atoms
    }

    fn push_atoms_of(
        &mut self,
        section: &SectionHeader,
        parent: u32,
        addresses: &mut Vec<u64>,
        subsections_via_symbols: bool,
    ) {
        let base = section.addr.get(LE);
        let size = section.size.get(LE);

        if !subsections_via_symbols || !is_splittable_section_type(section.section_type(LE)) {
            self.push_atom(section, parent, 0, size);
            return;
        }

        addresses.sort_unstable();
        addresses.dedup();

        // Anything before the first symbol has no name to be reached by, so it stays with the
        // section rather than becoming droppable on its own.
        let mut offset = 0;
        let mut cuts = addresses
            .iter()
            .filter_map(|address| address.checked_sub(base))
            .filter(|cut| *cut > 0 && *cut < size)
            .peekable();

        if cuts.peek().is_none() {
            self.push_atom(section, parent, 0, size);
            return;
        }

        for cut in cuts {
            self.push_atom(section, parent, offset, cut - offset);
            offset = cut;
        }

        self.push_atom(section, parent, offset, size - offset);
    }

    /// Returns the atom of `parent` that `address` falls in.
    fn atom_containing(
        &self,
        parent: object::SectionIndex,
        address: u64,
        file_sections: &[SectionHeader],
    ) -> Option<object::SectionIndex> {
        let range = self.by_parent.get(parent.0)?.clone();
        let candidates = &self.sections[range.start as usize..range.end as usize];

        // Atoms of a section are contiguous and in address order, so the one we want is the last
        // that starts at or before the address. A symbol exactly on a boundary belongs to the atom
        // it opens, which is what `partition_point` gives.
        let found = candidates.partition_point(|atom| atom.addr.get(LE) <= address);

        if found == 0 {
            // Before the first atom, which can only happen if the address is outside the section.
            let _ = file_sections;
            return None;
        }

        Some(object::SectionIndex(range.start as usize + found - 1))
    }

    fn push_atom(&mut self, section: &SectionHeader, parent: u32, offset: u64, size: u64) {
        let mut atom = *section;
        atom.addr.set(LE, section.addr.get(LE) + offset);
        atom.size.set(LE, size);

        // A zerofill section has no bytes in the file, so its `offset` names nothing and must stay
        // as it is rather than being advanced past the end of the file.
        if !is_no_bits_section_type(section.section_type(LE)) {
            atom.offset.set(LE, section.offset.get(LE) + offset as u32);
        }

        // Only the first atom can rely on the section's alignment; the rest begin wherever a symbol
        // did, so they can promise no more than the address itself provides.
        if offset != 0 {
            let from_address = offset.trailing_zeros().min(section.align.get(LE));
            atom.align.set(LE, from_address);
        }

        self.sections.push(atom);
        self.parents.push(parent);
    }
}

/// Returns whether a section of this type may be cut at symbol boundaries.
///
/// The literal sections may not: their contents are deduplicated by the string merger, which owns
/// how they're divided, and a symbol in one names a string rather than a region.
fn is_splittable_section_type(section_type: macho::SectionType) -> bool {
    !matches!(
        section_type,
        macho::S_CSTRING_LITERALS
            | macho::S_4BYTE_LITERALS
            | macho::S_8BYTE_LITERALS
            | macho::S_16BYTE_LITERALS
            | macho::S_LITERAL_POINTERS
    )
}

#[derive(Debug)]
enum ObjectKind<'data> {
    Regular(RegularObject<'data>),
    Dylib,
}

#[derive(derive_more::Debug)]
struct RegularObject<'data> {
    /// The sections as the object file records them. Kept because relocations and section
    /// numbering are expressed against these, not against the atoms.
    #[debug(skip)]
    pub(crate) sections: SectionTable<'data>,

    /// The same content divided into independently droppable pieces. This is what the rest of the
    /// linker sees as "the sections of this object".
    #[debug(skip)]
    atoms: Atoms,
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = MachO;

    fn parse_bytes(input: &'data [u8], is_dynamic: bool) -> crate::error::Result<Self> {
        let header = macho::MachHeader64::<object::Endianness>::parse(input, 0)?;
        let mut commands = header.load_commands(LE, input, 0)?;

        let mut symbols = None;
        let mut sections = None;

        while let Some(command) = commands.next()? {
            if let Some(symtab_command) = command.symtab()? {
                ensure!(symbols.is_none(), "At most one symtab command expected");
                symbols = Some(symtab_command.symbols::<macho::MachHeader64<_>, _>(LE, input)?);
            } else if !is_dynamic
                && let Some((segment_command, segment_data)) = command.segment_64()?
            {
                ensure!(sections.is_none(), "At most one segment command expected");
                let section_list = segment_command.sections(LE, segment_data)?;
                sections = Some(section_list);
            }
        }

        let symbols = symbols.ok_or("Missing symbol table")?;

        let kind = if is_dynamic {
            ObjectKind::Dylib
        } else {
            let sections = sections.ok_or("Missing segment command")?;

            // Where each section may be cut. A symbol marks the start of an independently
            // droppable region, so gathering the defined symbols by section is what determines the
            // atoms - see `Atoms::split`.
            let mut addresses_by_section = vec![Vec::new(); sections.len()];
            for symbol in symbols.iter() {
                if symbol.n_type.typ() != N_SECT || symbol.n_sect == 0 {
                    continue;
                }
                if let Some(addresses) =
                    addresses_by_section.get_mut(usize::from(symbol.n_sect - 1))
                {
                    addresses.push(symbol.n_value.get(LE));
                }
            }

            // The flag is the object saying its sections are safe to cut this way. Without it the
            // compiler has made no such promise - data may be addressed across what looks like a
            // symbol boundary - so each section stays whole.
            let subsections_via_symbols =
                header.flags(LE).0 & object::macho::MH_SUBSECTIONS_VIA_SYMBOLS.0 != 0;

            ObjectKind::Regular(RegularObject {
                atoms: Atoms::split(sections, &mut addresses_by_section, subsections_via_symbols),
                sections,
            })
        };

        Ok(File {
            data: input,
            symbols,
            flags: header.flags(LE),
            kind,
        })
    }

    fn parse(
        input: &crate::input_data::InputBytes<'data>,
        _args: &<Self::Platform as platform::Platform>::Args,
    ) -> crate::error::Result<Self> {
        // TODO
        Self::parse_bytes(input.data, input.kind == FileKind::MachODylib)
    }

    fn is_dynamic(&self) -> bool {
        matches!(self.kind, ObjectKind::Dylib)
    }

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &SymtabEntry> {
        self.symbols.iter()
    }

    fn symbol(
        &self,
        index: object::SymbolIndex,
    ) -> crate::error::Result<&<Self::Platform as platform::Platform>::SymtabEntry> {
        Ok(self.symbols.symbol(index)?)
    }

    fn section_size(
        &self,
        header: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        Ok(header.size.get(LE))
    }

    fn symbol_name(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
    ) -> crate::error::Result<&'data [u8]> {
        Ok(symbol.name(LE, self.symbols.strings())?)
    }

    fn symbol_offset_in_section(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        section_index: object::SectionIndex,
    ) -> crate::error::Result<u64> {
        let section = self.section(section_index)?;
        // On Mach-O the symbol value is the global offset, not a relative to the start of a
        // section.
        symbol
            .n_value
            .get(LE)
            .checked_sub(section.addr.get(LE))
            .ok_or_else(|| error!("Mach-O symbol value is before its section address"))
    }

    fn num_sections(&self) -> usize {
        self.sections().len()
    }

    fn section_iter<'a>(&'a self) -> <Self::Platform as platform::Platform>::SectionIterator<'a> {
        self.sections().iter()
    }

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<
        Item = (
            object::SectionIndex,
            &<Self::Platform as platform::Platform>::SectionHeader,
        ),
    > {
        self.sections()
            .iter()
            .enumerate()
            .map(|(i, section)| (object::SectionIndex(i), section))
    }

    fn section(
        &self,
        index: object::SectionIndex,
    ) -> crate::error::Result<&<Self::Platform as platform::Platform>::SectionHeader> {
        self.sections()
            .get(index.0)
            .ok_or(error!("section index out of range"))
    }

    fn section_by_name(
        &self,
        _name: &str,
    ) -> Option<(
        object::SectionIndex,
        &<Self::Platform as platform::Platform>::SectionHeader,
    )> {
        todo!()
    }

    fn symbol_section(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _index: object::SymbolIndex,
    ) -> crate::error::Result<Option<object::SectionIndex>> {
        if symbol.n_type.typ() != N_SECT || symbol.n_sect == 0 {
            // NO_SECT is zero, so a section number of zero means the symbol has none.
            return Ok(None);
        }

        // The number is one-based and names a section of the file. What the linker wants is the
        // atom that section was cut into at this symbol's address.
        let parent = object::SectionIndex(usize::from(symbol.n_sect - 1));

        let Some(atoms) = self.atoms() else {
            return Ok(Some(parent));
        };

        Ok(atoms.atom_containing(parent, symbol.n_value.get(LE), self.file_sections()))
    }

    fn is_symbol_thread_local(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        index: object::SymbolIndex,
    ) -> crate::error::Result<bool> {
        // We take a dylib's exported symbols without parsing its section table, so there's nothing
        // to consult. That costs nothing: a thread-local in another image is reached through a
        // descriptor over there, never by taking its address from here.
        if self.is_dynamic() {
            return Ok(false);
        }

        // An nlist entry says nothing about thread-locality; the section type does. So a symbol is
        // thread-local exactly when it's defined in one of the thread-local sections, which also
        // means an undefined symbol can't be recognised as one until it's been resolved.
        let Some(section_index) = self.symbol_section(symbol, index)? else {
            return Ok(false);
        };

        Ok(platform::SectionHeader::is_tls(
            self.section(section_index)?,
        ))
    }

    fn symbol_versions(&self) -> &[<Self::Platform as platform::Platform>::SymbolVersionIndex] {
        todo!()
    }

    fn dynamic_symbol_used(
        &self,
        symbol_index: object::SymbolIndex,
        file: &mut layout::DynamicLayoutState<'data, MachO>,
    ) -> crate::error::Result {
        file.format_specific
            .imported_symbols
            .push(file.symbol_id_range.input_to_id(symbol_index));
        Ok(())
    }

    fn finalise_sizes_dynamic(
        &self,
        _lib_name: &[u8],
        _state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        _indexes: &mut <Self::Platform as platform::Platform>::NonAddressableIndexes,
        _counts: &mut <Self::Platform as platform::Platform>::NonAddressableCounts,
        _state: &mut <Self::Platform as platform::Platform>::DynamicLayoutStateExt<'data>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn section_name(&self, index: object::SectionIndex) -> crate::error::Result<&'data [u8]> {
        // An atom carries its parent's name, and the parent is borrowed from the file, so the name
        // outlives us. The atom's own copy of the header does not.
        Ok(self.atom_parent_section(index)?.name())
    }

    fn raw_section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<&'data [u8]> {
        section
            .data(LE, self.data)
            .map_err(|()| error!("Cannot get section data"))
    }

    fn section_data(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
        _member: &bumpalo_herd::Member<'data>,
        loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> crate::error::Result<&'data [u8]> {
        // Nothing to decompress: Mach-O has no equivalent of ELF's compressed sections, so the
        // bytes in the file are the bytes of the section and no scratch allocation is needed.
        let data = self.raw_section_data(section)?;

        loaded_metrics
            .loaded_bytes
            .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);

        Ok(data)
    }

    fn copy_section_data(&self, section: &SectionHeader, out: &mut [u8]) -> Result {
        let data = section
            .data(LE, self.data)
            .map_err(|_e| error!("cannot get section data"))?;
        copy_section_data(data, out);

        Ok(())
    }

    fn section_data_cow(
        &self,
        _section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<std::borrow::Cow<'data, [u8]>> {
        todo!()
    }

    fn section_alignment(
        &self,
        section: &<Self::Platform as platform::Platform>::SectionHeader,
    ) -> crate::error::Result<u64> {
        Ok(2u64.pow(section.align(LE)))
    }

    /// Returns the relocations of the section an atom was cut from.
    ///
    /// Not just the atom's own: relocations are recorded against the whole section and are not in
    /// address order, so an atom's are not a contiguous run that could be handed back on its own.
    /// Callers narrow them with `atom_span_in_parent`, and `r_address` stays relative to the parent
    /// so that it still lines up with the list.
    fn relocations(
        &self,
        index: object::SectionIndex,
        _relocations: &<Self::Platform as platform::Platform>::RelocationSections,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationList<'data>> {
        Ok(RelocationList {
            relocations: self
                .atom_parent_section(index)?
                .relocations(LE, self.data)?,
        })
    }

    fn parse_relocations(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RelocationSections> {
        Ok(())
    }

    fn symbol_version_debug(&self, _symbol_index: object::SymbolIndex) -> Option<String> {
        None
    }

    fn section_display_name(&self, index: object::SectionIndex) -> Cow<'data, str> {
        self.section_name(index).map_or_else(
            |_| format!("<index {}>", index.0).into(),
            String::from_utf8_lossy,
        )
    }

    fn dynamic_tag_values(
        &self,
    ) -> Option<<Self::Platform as platform::Platform>::DynamicTagValues<'data>> {
        match self.kind {
            ObjectKind::Regular(_) => None,
            ObjectKind::Dylib => Some(DynamicTagValues::default()),
        }
    }

    fn get_version_names(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::VersionNames<'data>> {
        Ok(())
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &<Self::Platform as platform::Platform>::SymtabEntry,
        _local_index: usize,
        _version_names: &<Self::Platform as platform::Platform>::VersionNames<'data>,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::RawSymbolName<'data>> {
        Ok(RawSymbolName {
            name: self.symbol_name(symbol)?,
        })
    }

    fn should_enforce_undefined(
        &self,
        _resources: &crate::layout::GraphResources<'data, '_, Self::Platform>,
    ) -> bool {
        todo!()
    }

    fn verneed_table(
        &self,
    ) -> crate::error::Result<<Self::Platform as platform::Platform>::VerneedTable<'data>> {
        Ok(VerneedTable { _phantom: &[] })
    }

    fn process_gnu_note_section(
        &self,
        _state: &mut <Self::Platform as platform::Platform>::ObjectLayoutStateExt<'data>,
        _section_index: object::SectionIndex,
    ) -> crate::error::Result {
        todo!()
    }

    fn dynamic_tags(
        &self,
    ) -> crate::error::Result<&'data [<Self::Platform as platform::Platform>::DynamicEntry]> {
        todo!()
    }
}

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        // TODO: Surely not everything is alloc. But this is for now consistent with
        // SectionFlags::is_alloc.
        true
    }

    fn is_writable(&self) -> bool {
        false
    }

    fn is_executable(&self) -> bool {
        self.sectname.starts_with(b"__text")
    }

    fn is_tls(&self) -> bool {
        matches!(
            self.section_type(LE),
            macho::S_THREAD_LOCAL_REGULAR
                | macho::S_THREAD_LOCAL_ZEROFILL
                | macho::S_THREAD_LOCAL_VARIABLES
                | macho::S_THREAD_LOCAL_VARIABLE_POINTERS
                | macho::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS
        )
    }

    fn is_merge_section(&self) -> bool {
        // A literal section holds constants the compiler put in their own section precisely so the
        // linker could drop the duplicates - the same string appears in every object that mentions
        // it. Which of these actually get merged is narrowed further by `should_merge_sections`,
        // which currently only takes sections aligned to a byte, so in practice this means
        // `__cstring`.
        matches!(
            self.section_type(LE),
            macho::S_CSTRING_LITERALS
                | macho::S_4BYTE_LITERALS
                | macho::S_8BYTE_LITERALS
                | macho::S_16BYTE_LITERALS
        )
    }

    fn is_strings(&self) -> bool {
        self.section_type(LE) == macho::S_CSTRING_LITERALS
    }

    fn should_retain(&self) -> bool {
        // TODO
        false
    }

    fn should_exclude(&self) -> bool {
        // TODO
        false
    }

    fn is_group(&self) -> bool {
        // Mach-O has no equivalent of ELF section groups. Answering `false` rather than panicking
        // matters because the duplicate-symbol diagnostic asks this to work out whether a repeated
        // definition is a legitimate COMDAT merge or a genuine clash.
        false
    }

    fn is_note(&self) -> bool {
        false
    }

    fn is_prog_bits(&self) -> bool {
        !self.is_no_bits()
    }

    fn is_no_bits(&self) -> bool {
        is_no_bits_section_type(self.section_type(LE))
    }
}

/// Returns whether a section of this type occupies address space without occupying any space in the
/// file, which is what ELF calls `SHT_NOBITS`.
///
/// Both an input section header and an output section's attributes answer `is_no_bits` from here,
/// so that a zerofill section can't be read as having file content and then written as not having
/// any, or the other way around.
pub(crate) fn is_no_bits_section_type(section_type: macho::SectionType) -> bool {
    matches!(
        section_type,
        macho::S_ZEROFILL | macho::S_GB_ZEROFILL | macho::S_THREAD_LOCAL_ZEROFILL
    )
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionType {}

impl platform::SectionType for SectionType {
    fn is_rela(&self) -> bool {
        todo!()
    }

    fn is_rel(&self) -> bool {
        todo!()
    }

    fn is_symtab(&self) -> bool {
        todo!()
    }

    fn is_strtab(&self) -> bool {
        todo!()
    }
}

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        true
    }
}

// Documentation link for Nlist64 type: https://leopard-adc.pepas.com/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html
impl platform::Symbol for SymtabEntry {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        // TODO
        None
    }

    fn is_undefined(&self) -> bool {
        Nlist::is_undefined(self)
    }

    fn is_local(&self) -> bool {
        !self.n_type.contains(N_EXT)
    }

    fn is_absolute(&self) -> bool {
        self.n_type.typ() == N_ABS
    }

    fn is_weak(&self) -> bool {
        self.n_desc.get(LE).contains(N_WEAK_DEF)
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        if self.n_type.contains(N_PEXT) {
            Visibility::Hidden
        } else {
            Visibility::Default
        }
    }

    fn value(&self) -> u64 {
        self.n_value.get(LE)
    }

    fn size(&self) -> u64 {
        // An nlist entry records where a symbol starts but not how far it extends - the size is
        // implied by where the next symbol begins. Nothing needs it yet; dead stripping will, since
        // it is what bounds the region a symbol keeps alive.
        0
    }

    fn has_name(&self) -> bool {
        self.n_strx.get(LE) != 0
    }

    fn is_default_strippable(&self, name: &[u8]) -> bool {
        // A leading `l` marks a label the assembler made for its own use - string constants,
        // section anchors, jump tables. It carries no meaning outside the object it came from, and
        // ld64 drops these from the linked image, so keeping them only inflates the symbol table.
        // Nothing a user writes lands here: C and C++ names reach the assembler with a leading
        // underscore, so only generated labels start with a letter at all.
        self.is_local() && name.starts_with(b"l")
    }

    fn debug_string(&self) -> String {
        // Only used to add detail to diagnostics. An nlist entry has no field that would say more
        // than the name and address the caller already prints.
        String::new()
    }

    fn is_tls(&self) -> bool {
        // Unanswerable from an nlist entry, which says nothing about thread-locality - the section
        // the symbol is defined in does. `ObjectFile::is_symbol_thread_local` is the query that has
        // the object to hand and so can answer it; this exists only for the platforms where the
        // symbol alone is enough.
        false
    }

    fn is_interposable(&self) -> bool {
        self.visibility() == Visibility::Default
    }

    fn is_func(&self) -> bool {
        // Only ever asked of symbols taken from a dylib, whose export list we read without parsing
        // its sections - so there is nothing here that distinguishes code from data. What needs the
        // distinction infers it instead from the relocation referring to the symbol: a branch means
        // a function, and that is what decides whether it gets a stub.
        false
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        self.visibility() == Visibility::Hidden
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }

    fn with_hidden(mut self, hidden: bool) -> Self {
        if hidden {
            self.n_type.insert(N_PEXT);
        } else {
            self.n_type.remove(N_PEXT);
        }
        self
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionAttributes {
    pub(crate) flags: SectionFlags,
}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = MachO;

    fn merge(&mut self, rhs: Self) {
        self.flags |= rhs.flags;
    }

    fn apply(
        &self,
        _output_sections: &mut crate::output_section_id::OutputSections<Self::Platform>,
        _section_id: crate::output_section_id::OutputSectionId,
    ) {
    }

    fn is_null(&self) -> bool {
        false
    }

    fn is_alloc(&self) -> bool {
        false
    }

    fn is_executable(&self) -> bool {
        false
    }

    fn is_tls(&self) -> bool {
        // Layout only asks this in order to give ELF's `.tbss` its special treatment: there, a
        // no-bits TLS section occupies no address space in the image, so layout rewinds over it.
        // Mach-O's `__thread_bss` is not like that - it's the tail of the template block that dyld
        // copies per thread, and ld64 gives it an address directly after `__thread_data` - so
        // answering `false` keeps it laid out as an ordinary zerofill section.
        false
    }

    fn is_writable(&self) -> bool {
        false
    }

    fn is_no_bits(&self) -> bool {
        is_no_bits_section_type(self.flags.typ())
    }

    fn flags(&self) -> <Self::Platform as platform::Platform>::SectionFlags {
        self.flags
    }

    fn ty(&self) -> <Self::Platform as platform::Platform>::SectionType {
        SectionType {}
    }

    fn set_to_default_type(&mut self) {}
}

pub(crate) struct NonAddressableIndexes {}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(_symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        NonAddressableIndexes {}
    }
}

// TODO: update comment

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub(crate) enum SegmentType {
    Text,
    LoadCommands,
    TextSections,
    DataSections,
    DataConstSections,
    LinkeditSections,
    // The other ELF-specific (or unused) parts/sections will be collected here.
    #[default]
    Unused,
}

impl platform::SegmentType for SegmentType {}

/// Returns the segment that the supplied output section belongs to. `SegmentType::Unused` means
/// that the section isn't part of the Mach-O output at all.
fn mapped_segment_type(section_id: crate::output_section_id::OutputSectionId) -> SegmentType {
    match section_id {
        output_section_id::FILE_HEADER => SegmentType::Text,
        output_section_id::LOAD_COMMANDS => SegmentType::LoadCommands,
        output_section_id::TEXT
        | output_section_id::CSTRING
        | output_section_id::GCC_EXCEPT_TABLE
        | output_section_id::UNWIND_INFO
        | output_section_id::MACHO_EH_FRAME
        | output_section_id::PLT_GOT => SegmentType::TextSections,
        // `__const` holds constants, but constants include pointers, and a pointer has to be
        // rebased before it's read - which means living somewhere dyld can write to. ld64 sorts the
        // input sections: the ones with relocations go to `__DATA_CONST,__const` and the rest stay
        // in `__TEXT,__const`. We don't sort them yet, so they all go to the segment that can hold
        // either. That costs a dirty page where ld64 would have kept the data shared, but the
        // alternative is a pointer in a read-only segment, which simply doesn't work.
        output_section_id::CONST => SegmentType::DataConstSections,
        output_section_id::DATA
        | output_section_id::INIT_ARRAY
        | output_section_id::FINI_ARRAY
        | output_section_id::THREAD_VARS
        | output_section_id::TDATA
        | output_section_id::TBSS
        | output_section_id::COMMON
        | output_section_id::BSS => SegmentType::DataSections,
        output_section_id::GOT => SegmentType::DataConstSections,
        output_section_id::CHAINED_FIXUP_TABLE
        | output_section_id::SYMTAB_LOCAL
        | output_section_id::SYMTAB_GLOBAL
        | output_section_id::INDIRECT_SYMTAB
        | output_section_id::STRTAB
        | output_section_id::CODE_SIGNATURE => SegmentType::LinkeditSections,

        // A section we have no built-in ID for still has to land somewhere. Answering `Unused`
        // would leave it out of the output order, and so out of the file layout, while each object
        // would still have reserved bytes for it - which shows up as the output buffer running out
        // partway through the write. `__DATA` is the safe home: it's writable, so nothing that ends
        // up there can fault on a store, and it's the segment ld64 uses for sections it doesn't
        // recognise either.
        _ if section_id.as_usize() >= crate::output_section_id::NUM_BUILT_IN_SECTIONS => {
            SegmentType::DataSections
        }

        _ => SegmentType::Unused,
    }
}

/// Returns whether the supplied output section is emitted as a real Mach-O section, i.e. it gets a
/// `section_64` entry in the section list of its `LC_SEGMENT_64` load command. The remaining output
/// sections are regions that we generate ourselves - the header, the load commands and the contents
/// of `__LINKEDIT` - and are not sections as far as the file format is concerned.
fn is_emitted_as_macho_section(section_id: crate::output_section_id::OutputSectionId) -> bool {
    matches!(
        mapped_segment_type(section_id),
        SegmentType::TextSections | SegmentType::DataSections | SegmentType::DataConstSections
    )
}

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub(crate) struct ProgramSegmentDef {
    pub(crate) segment_type: SegmentType,
    pub(crate) count_as_segment: bool,
}

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.segment_type)
    }
}

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    type Platform = MachO;

    fn is_writable(self) -> bool {
        false
    }

    fn is_executable(self) -> bool {
        false
    }

    fn always_keep(self) -> bool {
        matches!(
            self.segment_type,
            SegmentType::Text
                | SegmentType::LoadCommands
                | SegmentType::TextSections
                | SegmentType::LinkeditSections
        )
    }

    fn is_loadable(self) -> bool {
        true
    }

    fn is_stack(self) -> bool {
        false
    }

    fn is_tls(self) -> bool {
        false
    }

    fn order_key(self) -> usize {
        self.segment_type as usize
    }

    fn should_include_section(
        self,
        _section_info: &crate::output_section_id::SectionOutputInfo<Self::Platform>,
        section_id: crate::output_section_id::OutputSectionId,
        _rosegment: bool,
    ) -> bool {
        let mapped_segment = mapped_segment_type(section_id);

        match (self.segment_type, mapped_segment) {
            (SegmentType::Text, SegmentType::LoadCommands | SegmentType::TextSections) => true,
            _ => self.segment_type == mapped_segment,
        }
    }
}

pub(crate) struct BuiltInSectionDetails {
    pub(crate) kind: SectionKind<'static>,
    pub(crate) section_flags: SectionFlags,
    pub(crate) min_alignment: Alignment,
}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    kind: SectionKind::Primary(SectionName(&[])),
    section_flags: SectionFlags(0),
    min_alignment: alignment::MIN,
};

#[allow(unused)]
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct DynamicTagValues<'data> {
    phantom: &'data [u8],
}

#[derive(Debug)]
pub(crate) struct RelocationList<'data> {
    pub(crate) relocations: &'data [Relocation],
}

impl<'data> platform::RelocationList<'data> for RelocationList<'data> {
    fn num_relocations(&self) -> usize {
        self.relocations.len()
    }
}

impl<'data> platform::DynamicTagValues<'data> for DynamicTagValues<'data> {
    fn lib_name(&self, _input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        &[]
    }
}

#[derive(Debug)]
pub(crate) struct RawSymbolName<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> platform::RawSymbolName<'data> for RawSymbolName<'data> {
    fn parse(bytes: &'data [u8]) -> Self {
        Self { name: bytes }
    }

    fn name(&self) -> &'data [u8] {
        self.name
    }

    fn version_name(&self) -> Option<&'data [u8]> {
        None
    }

    fn is_default(&self) -> bool {
        // This port does not use symbol versioning, so every symbol is treated as
        // the default version.
        true
    }
}

impl std::fmt::Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&String::from_utf8_lossy(self.name), f)
    }
}

pub(crate) struct VerneedTable<'data> {
    // TODO
    _phantom: &'data [u8],
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, _local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        todo!()
    }
}

impl platform::Platform for MachO {
    type File<'data> = File<'data>;
    type FileFlags = u32;
    type SymtabEntry = SymtabEntry;
    type PlatformSpecificSymbol = core::convert::Infallible;
    type SectionHeader = SectionHeader;
    type SectionFlags = SectionFlags;
    type SectionAttributes = SectionAttributes;
    type SectionType = SectionType;
    type SegmentType = SegmentType;
    type ProgramSegmentDef = ProgramSegmentDef;
    type BuiltInSectionDetails = BuiltInSectionDetails;
    type RelocationSections = ();
    type DynamicEntry = ();
    type DynamicSymbolDefinitionExt = ();
    type RelocationInfo = object::macho::RelocationInfo;
    type NonAddressableIndexes = NonAddressableIndexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = EpilogueLayoutExt;
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type StubLibraryLayoutStateExt = DynamicLayoutStateExt;
    type StubLibraryLayoutExt = DynamicLayoutExt;
    type ArchIdentifier = ();
    type Args = MachOArgs;
    type ResolutionExt = ResolutionExt;
    type SymtabShndxEntry = ();
    type SymbolVersionIndex = ();
    type FinaliseSizesExt<'data> = FinaliseSizesExt;
    type LayoutExt<'data> = LayoutExt;
    type GdbIndexScanResult<'data> = ();
    type SectionIterator<'a> = core::slice::Iter<'a, SectionHeader>;
    type DynamicTagValues<'data> = DynamicTagValues<'data>;
    type RelocationList<'data> = RelocationList<'data>;
    type DynamicLayoutStateExt<'data> = DynamicLayoutStateExt;
    type DynamicLayoutExt<'data> = DynamicLayoutExt;
    type LayoutResourcesExt<'data> = ();
    type PreludeLayoutStateExt = PreludeLayoutExt;
    type PreludeLayoutExt = PreludeLayoutExt;
    type ObjectLayoutStateExt<'data> = ();
    type RawSymbolName<'data> = RawSymbolName<'data>;
    type VersionNames<'data> = ();
    type VerneedTable<'data> = VerneedTable<'data>;
    type ResolvedObjectExt<'data> = ();

    // ELF reserves symbol index 0 for a null entry, so resolution skips it. Mach-O has no such
    // reservation - index 0 is an ordinary symbol - and answering `true` here made us drop whatever
    // symbol happened to be first from resolution entirely.
    const HAS_NULL_SYMBOL_ENTRY: bool = false;

    fn link_for_arch<'data>(
        linker: &'data crate::Linker,
        args: &'data Self::Args,
    ) -> crate::error::Result<crate::LinkerOutput<'data>> {
        if !cfg!(feature = "macho") {
            crate::bail!(
                "Mach-O support is still experimental. Rebuild with `--features macho` to enable it."
            );
        }

        linker.link_for_arch::<MachO, crate::macho_aarch64::MachOAArch64>(args)
    }

    fn write_output_file<'data, A: platform::Arch<Platform = Self>>(
        output: &crate::file_writer::Output,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> crate::error::Result {
        output.write(layout, macho_writer::write::<A>)
    }

    fn section_attributes(_header: &Self::SectionHeader) -> Self::SectionAttributes {
        Default::default()
    }

    fn apply_force_keep_sections(
        _keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        _args: &Self::Args,
    ) {
    }

    fn is_zero_sized_section_content(
        section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        // An input section that happens to be empty is still a section. ld64 keeps it: linking an
        // object whose only `__DATA,__data` and `__DATA,__mycustom` sections are zero sized still
        // produces an output with both of those sections (size 0) and hence a `__DATA` segment.
        // Compilers routinely emit empty sections - a translation unit with no code still gets a
        // zero-sized `__TEXT,__text` - so this path is reached by perfectly ordinary inputs.
        //
        // Note that this hook is only about a *zero sized* input section. It says nothing about
        // Mach-O zerofill sections (`S_ZEROFILL` / `S_THREAD_LOCAL_ZEROFILL`), which have a
        // non-zero size but no bytes in the file; those are sized from the section header like any
        // other section and never reach here just because they lack file content. We don't
        // currently map them to an output section at all.
        //
        // The output sections that aren't emitted as Mach-O sections (the header, the load
        // commands and the `__LINKEDIT` contents) are generated by us rather than copied from an
        // input, so nothing should ever be destined for them. Answer `false` for those so that an
        // empty input section can't resurrect a region that we'd otherwise leave out.
        is_emitted_as_macho_section(section_id)
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &SECTION_DEFINITIONS
    }

    fn finalise_group_layout(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Self::GroupLayoutExt {
    }

    /// The address a `__compact_unwind` section would have been given, had we emitted one.
    ///
    /// We don't: the entries are read during layout and become `__unwind_info`, so the input
    /// section has no place in the output and nothing resolves against its address. ELF needs this
    /// because it copies `.eh_frame` through and its frames refer to each other by offset within
    /// it.
    fn frame_data_base_address(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> u64 {
        0
    }

    fn activate_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        _prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _resources: &crate::layout::GraphResources<'data, 'scope, Self>,
    ) {
    }

    fn finalise_sizes_dynamic<'data>(
        _object: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_object_sizes<'data>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn finalise_object_layout<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn finalise_layout_dynamic<'data>(
        state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> crate::error::Result<Option<Self::DynamicLayoutExt<'data>>> {
        layout::default_create_resolutions(
            memory_offsets,
            resolutions_out,
            resources,
            state.symbol_id_range,
        )?;

        create_dynamic_layout_ext(state.file_id(), resources)
    }

    fn finalise_layout_stub<'data>(
        state: layout::StubLibraryLayoutState<'data, Self>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> Result<Option<Self::StubLibraryLayoutExt>> {
        layout::default_create_resolutions(
            memory_offsets,
            resolutions_out,
            resources,
            state.symbol_id_range,
        )?;

        create_dynamic_layout_ext(state.file_id(), resources)
    }

    fn take_dynsym_index(
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> crate::error::Result<u32> {
        todo!()
    }

    fn compute_object_addresses<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        todo!()
    }

    fn layout_resources_ext<'data>(
        _groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        state: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _section: crate::layout::Section,
        section_index: object::SectionIndex,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        let span = state.object.atom_span_in_parent(section_index)?;

        for rel in state.relocations(section_index)?.relocations {
            if !span.contains(&u64::from(rel.info(LE).r_address)) {
                continue;
            }

            process_relocation::<A>(state, rel, section_index, resources, queue, scope)?;
        }

        Ok(())
    }

    fn create_dynamic_symbol_definition<'data>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
    ) -> crate::error::Result<crate::layout::DynamicSymbolDefinition<'data, Self>> {
        todo!()
    }

    fn update_segment_keep_list(
        _program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        _keep_segments: &mut [bool],
        _args: &Self::Args,
    ) {
    }

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        PROGRAM_SEGMENT_DEFS
    }

    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    /// Mach-O only ever holds arm64 code here, so the thunk shape never varies by object the way
    /// it does for ELF, where one link can mix architectures.
    fn file_thunk_config<'data>(_file: &Self::File<'data>) -> Option<crate::platform::ThunkConfig> {
        <crate::macho_aarch64::MachOAArch64 as platform::Arch>::thunk_config()
    }

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder<Self>,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
        // Symbol ID 0 means "undefined" everywhere in the linker, so it must not name a real
        // symbol. The prelude is allocated ids first, so claiming one here is what reserves it.
        // ELF gets this for free from its null symbol table entry; Mach-O has no such entry, so
        // without this the first symbol of the first object would land on the sentinel and read
        // back as undefined.
        symbols
            .add_symbol(crate::parsing::InternalSymDefInfo::new(
                crate::parsing::SymbolPlacement::Undefined,
                b"",
            ))
            .hide();

        // Both name the address the mach header is loaded at, which is also the image's base.
        // `__mh_execute_header` is how code finds its own header; `___dso_handle` is what
        // `__cxa_atexit` is handed to say which image a destructor belongs to, so anything with a
        // static or thread-local destructor references it - which is most C++ programs.
        symbols.section_start(output_section_id::FILE_HEADER, "__mh_execute_header");
        symbols.section_start(output_section_id::FILE_HEADER, "___dso_handle");
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        SECTION_DEFINITIONS
            .iter()
            .map(|d| SectionOutputInfo {
                section_attributes: SectionAttributes {
                    flags: d.section_flags,
                },
                kind: d.kind,
                min_alignment: d.min_alignment,
                location_info: None,
                secondary_order: None,
                region_name: None,
                fill: None,
                phdrs: Vec::new(),
            })
            .collect()
    }

    fn create_finalise_sizes_ext<'data, 'states, 'files, A: platform::Arch<Platform = Self>>(
        _args: &Self::Args,
        groups: &'files [layout::GroupState<'data, Self>],
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) -> crate::error::Result<Self::FinaliseSizesExt<'data>>
    where
        'data: 'files,
        'data: 'states,
    {
        let mut imported_libraries = Vec::new();
        let mut imported_symbols = Vec::new();

        for group in groups {
            for file in &group.files {
                match file {
                    layout::FileLayoutState::StubLibrary(state) => {
                        if state.format_specific.loaded {
                            imported_libraries.push(state.file_id());
                        }
                        imported_symbols
                            .extend_from_slice(state.format_specific.imported_symbols.as_slice());
                    }
                    layout::FileLayoutState::Dynamic(state) => {
                        if state.format_specific.loaded {
                            imported_libraries.push(state.file_id());
                        }
                        imported_symbols
                            .extend_from_slice(state.format_specific.imported_symbols.as_slice());
                    }
                    _ => {}
                }
            }
        }

        Ok(FinaliseSizesExt {
            imported_libraries,
            imported_symbols,
        })
    }

    fn create_layout_ext<'data>(
        finalise_sizes_ext: Self::FinaliseSizesExt<'data>,
        resolutions: &SymbolResolutions<Self>,
    ) -> Result<Self::LayoutExt<'data>> {
        let mut layout_ext = LayoutExt::default();

        let imported_symbols = finalise_sizes_ext
            .imported_symbols
            .iter()
            .map(|&symbol_id| {
                let resolution = resolutions
                    .get(symbol_id)
                    .with_context(|| "missing resolution for a stub library symbol".to_string())?;

                let got_address = resolution
                    .format_specific
                    .got_address
                    .ok_or_else(|| error!("missing GOT entry for a stub library symbol"))?;

                Ok(ImportedSymbolWithResolution {
                    symbol_id,
                    got_address,
                    plt_address: resolution.format_specific.plt_address,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        layout_ext.imported_symbols = imported_symbols
            .into_iter()
            .sorted_by_key(|symbol| symbol.got_address)
            .collect();

        // Everything else that was given a slot is defined here, so the slot's contents are known
        // now rather than at load time. `is_dynamic` is what separates the two: an import's slot is
        // filled in by dyld from the bind, this one we write ourselves.
        layout_ext.local_got_symbols = resolutions
            .iter()
            .filter(|(_, resolution)| !resolution.flags.is_dynamic())
            .filter_map(|(_, resolution)| {
                Some(LocalGotSymbol {
                    got_address: resolution.format_specific.got_address?,
                    value: resolution.raw_value,
                })
            })
            .sorted_by_key(|symbol| symbol.got_address)
            .collect();

        Ok(layout_ext)
    }

    /// Accounts for one input `__LD,__compact_unwind` section.
    ///
    /// Each entry describes one function, and becomes one entry of the `__unwind_info` table we
    /// build in its place. Nothing is copied: what's reserved here is space in that table, and what
    /// the relocations are walked for is the symbols they name - the personality routines in
    /// particular, which the table reaches through the GOT and so need slots.
    fn load_exception_frame_data<'data, 'scope, A: platform::Arch<Platform = Self>>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        eh_frame_section_index: object::SectionIndex,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        let section = object.object.section(eh_frame_section_index)?;
        let data = object.object.raw_section_data(section)?;

        let entry_count = data.len() as u64 / COMPACT_UNWIND_ENTRY_SIZE;
        common.allocate(
            part_id::UNWIND_INFO,
            entry_count * UNWIND_INFO_BYTES_PER_ENTRY,
        );

        let relocations = object
            .object
            .relocations(eh_frame_section_index, &object.relocations)?
            .relocations;

        for relocation in relocations {
            let info = relocation.info(LE);

            process_relocation::<A>(
                object,
                relocation,
                eh_frame_section_index,
                resources,
                queue,
                scope,
            )?;

            // The personality is reached through a slot rather than directly, because the entry
            // stores where the routine's address is rather than the address itself - so it needs a
            // GOT entry even when the routine is defined right here, which is how Rust's is.
            if info.r_extern
                && u64::from(info.r_address) % COMPACT_UNWIND_ENTRY_SIZE
                    == COMPACT_UNWIND_PERSONALITY_OFFSET
            {
                let local_symbol_id = object
                    .symbol_id_range
                    .input_to_id(SymbolIndex(info.r_symbolnum as usize));
                let symbol_id = resources.symbol_db.definition(local_symbol_id);

                resources
                    .per_symbol_flags
                    .get_atomic(symbol_id)
                    .fetch_or(ValueFlags::GOT_ENTRY_REQUIRED);
            }
        }

        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _unloaded: crate::resolution::UnloadedSection,
        _resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn new_epilogue_layout<'data>(
        _args: &Self::Args,
        _output_kind: crate::output_kind::OutputKind,
        _dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'data, Self>],
        group_states: &[layout::GroupState<'data, Self>],
    ) -> Self::EpilogueLayoutExt {
        verbose_timing_phase!("Gather imported symbol IDs");

        let imported_symbols = group_states
            .iter()
            .flat_map(|group| {
                group.files.iter().flat_map(|file| match file {
                    layout::FileLayoutState::StubLibrary(file) => {
                        file.format_specific.imported_symbols.as_slice()
                    }
                    layout::FileLayoutState::Dynamic(file) => {
                        file.format_specific.imported_symbols.as_slice()
                    }
                    _ => &[],
                })
            })
            .copied()
            .collect();

        EpilogueLayoutExt { imported_symbols }
    }

    fn apply_non_addressable_indexes_epilogue(
        _counts: &mut Self::NonAddressableCounts,
        _state: &mut Self::EpilogueLayoutExt,
    ) {
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _counts: &Self::NonAddressableCounts,
        _mem_sizes_iter: impl Iterator<
            Item = &'groups mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        >,
    ) {
    }

    fn finalise_sizes_epilogue<'data>(
        state: &mut Self::EpilogueLayoutExt,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _dynamic_symbol_definitions: &[crate::layout::DynamicSymbolDefinition<'data, Self>],
        _format_specific: &Self::FinaliseSizesExt<'data>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
        let mut fixup_table_size = CHAINED_FIXUP_TABLE_BASE_SIZE;

        fixup_table_size += state
            .imported_symbols
            .iter()
            .map(|&s| {
                CHAINED_FIXUP_IMPORT_SIZE
                    + symbol_db.symbol_name(s).unwrap().bytes().len() as u64
                    + 1
            })
            .sum::<u64>();

        // The space taken by the per-page start information is added by
        // `apply_late_size_adjustments_epilogue`, which is the first point at which the sizes of
        // the writable segments are known.

        mem_sizes.increment(
            part_id::CHAINED_FIXUP_TABLE,
            alignment::USIZE.align_up(fixup_table_size),
        );

        // Every imported symbol also gets an undefined entry in the symbol table. Mach-O requires
        // the undefined symbols to be contiguous and last, which they are because the epilogue is
        // the last thing laid out, and `LC_DYSYMTAB` names that run by index.
        let symtab_size = state.imported_symbols.len() as u64 * size_of::<SymtabEntry>() as u64;
        let strings_size = state
            .imported_symbols
            .iter()
            .map(|&s| symbol_db.symbol_name(s).unwrap().bytes().len() as u64 + 1)
            .sum::<u64>();

        mem_sizes.increment(part_id::SYMTAB_GLOBAL, symtab_size);
        mem_sizes.increment(part_id::STRTAB, strings_size);
    }

    fn apply_late_size_adjustments_epilogue(
        _state: &mut Self::EpilogueLayoutExt,
        current_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
        extra_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
        _format_specific: &Self::FinaliseSizesExt<'_>,
        _args: &Self::Args,
    ) -> Result {
        // A `dyld_chained_starts_in_segment` record holds one `page_start` entry for every page of
        // the segment it describes, whether or not that page has any fixups on it. How much space
        // the fixup table needs therefore depends on the sizes of the writable segments, which
        // aren't known until every group's sizes have been merged - later than
        // `finalise_sizes_epilogue` runs.
        // Both writable segments are described, so both have to be measured in full. Asking
        // `mapped_segment_type` which segment each section belongs to keeps this in step with the
        // layout: naming the sections directly meant that every section added to `__DATA` or
        // `__DATA_CONST` afterwards went uncounted, and the table came up short by two bytes per
        // uncounted page only once the link was big enough for those sections to span one.
        let mut data_size = 0;
        let mut data_const_size = 0;

        for part_index in 0..current_sizes.num_parts() {
            let part_id = PartId::from_usize(part_index);
            let size = *current_sizes.get(part_id);

            match mapped_segment_type(part_id.output_section_id()) {
                SegmentType::DataSections => data_size += size,
                SegmentType::DataConstSections => data_const_size += size,
                _ => {}
            }
        }

        // One extra page per segment covers it being padded out to an alignment boundary.
        let page_start_count = [data_size, data_const_size]
            .into_iter()
            .map(|size| size.div_ceil(MACHO_PAGE_ALIGNMENT.value()) + 1)
            .sum::<u64>();

        extra_sizes.increment(
            part_id::CHAINED_FIXUP_TABLE,
            alignment::USIZE.align_up(page_start_count * CHAINED_FIXUP_PAGE_START_SIZE),
        );

        // The indirect symbol table holds one symbol index for every slot of every section whose
        // type says its contents are symbol pointers or stubs - `__got` and `__stubs` here. Like
        // the page starts above, that's a function of those sections' sizes, so it can't be
        // counted until they've been merged.
        let mut indirect_entry_count = 0;

        for (section_id, entry_size) in [
            (output_section_id::GOT, GOT_ENTRY_SIZE),
            (output_section_id::PLT_GOT, PLT_ENTRY_SIZE),
        ] {
            let mut section_size = 0;

            for part_index in 0..current_sizes.num_parts() {
                let part_id = PartId::from_usize(part_index);
                if part_id.output_section_id() == section_id {
                    section_size += *current_sizes.get(part_id);
                }
            }

            indirect_entry_count += section_size / entry_size;
        }

        extra_sizes.increment(
            part_id::INDIRECT_SYMTAB,
            indirect_entry_count * INDIRECT_SYMTAB_ENTRY_SIZE,
        );

        // The per-function part of `__unwind_info` was reserved as the input sections were read;
        // what's left is the part that depends on how many functions there are in total - the
        // header, and the index of the pages they're split across.
        let unwind_entry_count =
            *current_sizes.get(part_id::UNWIND_INFO) / UNWIND_INFO_BYTES_PER_ENTRY;

        if unwind_entry_count > 0 {
            let pages = unwind_entry_count.div_ceil(UNWIND_INFO_PAGE_CAPACITY);

            extra_sizes.increment(
                part_id::UNWIND_INFO,
                UNWIND_INFO_HEADER_SIZE
                    + UNWIND_INFO_MAX_PERSONALITIES * size_of::<u32>() as u64
                    // One index entry per page, plus a sentinel that marks the end of the last
                    // function.
                    + (pages + 1) * UNWIND_INFO_INDEX_ENTRY_SIZE
                    + pages * UNWIND_INFO_PAGE_HEADER_SIZE,
            );
        }

        Ok(())
    }

    fn finalise_sizes_all<'data>(
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn finalise_layout_epilogue<'data>(
        _epilogue_state: &mut Self::EpilogueLayoutExt,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _format_specific: &Self::FinaliseSizesExt<'data>,
        _dynsym_start_index: u32,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
    ) -> crate::error::Result {
        Ok(())
    }

    fn is_symbol_non_interposable<'data>(
        _object: &Self::File<'data>,
        _args: &Self::Args,
        _sym: &Self::SymtabEntry,
        _output_kind: crate::output_kind::OutputKind,
        _export_list: Option<&crate::export_list::ExportList>,
        _lib_name: &[u8],
        _archive_semantics: bool,
        _is_undefined: bool,
    ) -> bool {
        // TODO
        true
    }

    fn allocate_header_sizes<'data>(
        prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        header_info: &crate::layout::HeaderInfo,
        output_sections: &crate::output_section_id::OutputSections<Self>,
        resources: &layout::FinaliseSizesResources<'data, '_, Self>,
        args: &Self::Args,
    ) {
        sizes.increment(part_id::FILE_HEADER, size_of::<FileHeader>() as u64);

        let mut allocate_load_cmd = |command_size| {
            sizes.increment(part_id::LOAD_COMMANDS, command_size as u64);
            prelude.format_specific.load_command_count += 1;
        };

        allocate_load_cmd(size_of::<SegmentCommand>());
        allocate_load_cmd(
            size_of::<SegmentCommand>()
                + size_of::<SectionEntry>()
                    * count_sections_for_segment_type(output_sections, SegmentType::TextSections),
        );
        if has_active_segment(header_info, SegmentType::DataSections) {
            allocate_load_cmd(
                size_of::<SegmentCommand>()
                    + size_of::<SectionEntry>()
                        * count_sections_for_segment_type(
                            output_sections,
                            SegmentType::DataSections,
                        ),
            );
        }
        if has_active_segment(header_info, SegmentType::DataConstSections) {
            allocate_load_cmd(
                size_of::<SegmentCommand>()
                    + size_of::<SectionEntry>()
                        * count_sections_for_segment_type(
                            output_sections,
                            SegmentType::DataConstSections,
                        ),
            );
        }
        allocate_load_cmd(size_of::<SegmentCommand>());
        allocate_load_cmd(size_of::<EntryPointCommand>());
        allocate_load_cmd(
            (size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
                .next_multiple_of(MACHO_COMMAND_ALIGNMENT),
        );

        prelude.format_specific.imported_library_file_ids =
            resources.format_specific.imported_libraries.clone();

        prelude.format_specific.load_dylib_command_sizes = prelude
            .format_specific
            .imported_library_file_ids
            .iter()
            .map(|&file_id| load_dylib_command_size(install_name(file_id, resources.symbol_db)))
            .collect();
        let load_dylib_command_sizes = prelude.format_specific.load_dylib_command_sizes.clone();
        for command_size in load_dylib_command_sizes {
            allocate_load_cmd(command_size);
        }

        allocate_load_cmd(size_of::<DyldChainedFixupsCommand>());
        allocate_load_cmd(size_of::<SymtabCommand>());
        allocate_load_cmd(size_of::<DysymtabCommand>());
        allocate_load_cmd(size_of::<CodeSignatureCommand>());
        allocate_load_cmd(size_of::<UuidCommand>());
        if args.platform_version.is_some() {
            allocate_load_cmd(size_of::<BuildVersionCommand>());
        }
    }

    fn new_stub_library_layout_state_ext<'data>(
        _stub: &resolution::ResolvedStubLibrary<'data>,
        args: &Self::Args,
    ) -> Self::StubLibraryLayoutStateExt {
        DynamicLayoutStateExt::new(args)
    }

    fn new_dynamic_layout_state_ext<'data>(
        _file: &resolution::ResolvedDynamic<'data, Self>,
        args: &Self::Args,
    ) -> Self::DynamicLayoutStateExt<'data> {
        DynamicLayoutStateExt::new(args)
    }

    fn load_stub_library_symbol<'data>(
        state: &mut StubLibraryLayoutState<Self>,
        symbol_id: SymbolId,
    ) -> Result {
        state.format_specific.loaded = true;
        state.format_specific.imported_symbols.push(symbol_id);

        Ok(())
    }

    fn finalise_sizes_for_symbol<'data>(
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
        _flags: crate::value_flags::ValueFlags,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_resolution(
        flags: crate::value_flags::ValueFlags,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
        let indirection = Indirection::for_symbol(flags);

        if indirection.plt {
            mem_sizes.increment(part_id::PLT_GOT, PLT_ENTRY_SIZE);
        }
        if indirection.got {
            mem_sizes.increment(part_id::GOT, GOT_ENTRY_SIZE);
        }
    }

    fn allocate_object_symtab_space<'data>(
        state: &crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        per_symbol_flags: &crate::value_flags::AtomicPerSymbolFlags,
    ) -> Result {
        // Mach-O requires the symbol table to be partitioned - all local symbols, then all
        // externally defined ones, then all undefined ones - because `LC_DYSYMTAB` names each run
        // by a start index and a count. Objects are laid out one after another, so keeping the two
        // kinds in separate output sections is what makes the runs contiguous across objects
        // rather than only within each one.
        let mut num_locals = 0;
        let mut num_globals = 0;
        let mut strings_size = 0;
        for ((sym_index, sym), flags) in state
            .object
            .enumerate_symbols()
            .zip(per_symbol_flags.range(state.symbol_id_range))
        {
            let symbol_id = state.symbol_id_range.input_to_id(sym_index);
            if let Some(info) = SymbolCopyInfo::new(
                state.object,
                sym_index,
                sym,
                symbol_id,
                symbol_db,
                flags.get(),
                &state.sections,
            ) {
                if platform::Symbol::is_local(sym) {
                    num_locals += 1;
                } else {
                    num_globals += 1;
                }
                strings_size += info.name.len() + 1;
            }
        }
        let entry_size = size_of::<SymtabEntry>() as u64;
        common.allocate(part_id::SYMTAB_LOCAL, num_locals * entry_size);
        common.allocate(part_id::SYMTAB_GLOBAL, num_globals * entry_size);
        common.allocate(part_id::STRTAB, strings_size as u64);

        Ok(())
    }

    fn allocate_internal_symbol(
        _symbol_id: crate::symbol_db::SymbolId,
        _def_info: &crate::parsing::InternalSymDefInfo<Self>,
        _sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) -> crate::error::Result {
        // Linker-defined symbols resolve references but aren't written to the symbol table, so they
        // need no space in it. Reserving some would leave a hole, since nothing in the writer emits
        // them. ld64 does list `__mh_execute_header`, so this is a difference from its output;
        // fixing it means emitting these symbols, not just allocating for them.
        Ok(())
    }

    fn allocate_prelude(
        common: &mut crate::layout::CommonGroupState<Self>,
        symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) {
        // Allocate one extra character as n_strx == 0 is treated as unnamed.
        common.allocate(part_id::STRTAB, 1);
        common.allocate(
            part_id::CODE_SIGNATURE,
            CS_HEADERS_SIZE + code_signature_padded_identifier_size(symbol_db.args),
        );
    }

    fn finalise_prelude_layout<'data>(
        prelude: &crate::layout::PreludeLayoutState<Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> crate::error::Result<Self::PreludeLayoutExt> {
        Ok(prelude.format_specific.clone())
    }

    fn create_resolution(
        flags: crate::value_flags::ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _args: &<Self as crate::platform::Platform>::Args,
        _output_kind: crate::OutputKind,
    ) -> crate::layout::Resolution<Self> {
        let mut resolution: Resolution<MachO> = Resolution {
            raw_value,
            dynamic_symbol_index,
            format_specific: ResolutionExt {
                got_address: None,
                plt_address: None,
            },
            flags,
        };

        let indirection = Indirection::for_symbol(flags);

        if indirection.plt {
            let plt_address = allocate_plt(memory_offsets);
            resolution.raw_value = plt_address.get();
            resolution.format_specific.plt_address = Some(plt_address);
        }
        if indirection.got {
            let got_address = allocate_got(memory_offsets);
            resolution.format_specific.got_address = Some(got_address);

            // An imported symbol has no address of its own until dyld binds it, so `raw_value` is
            // free to stand in for the indirection that reaches it. A locally defined one does have
            // an address, and references that aren't going through the GOT still need it, so
            // leaving `raw_value` alone is what lets a symbol have both.
            if !indirection.plt && flags.is_dynamic() {
                resolution.raw_value = got_address.get();
            }
        }

        resolution
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        _verneed_table: &Self::VerneedTable<'data>,
        _symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        RawSymbolName { name: name_bytes }
    }

    fn default_layout_rules(_args: &Self::Args) -> Vec<crate::layout_rules::SectionRule<'static>> {
        DEFAULT_SECTION_RULES.to_vec()
    }

    fn build_output_order_and_program_segments<'data>(
        custom: &crate::output_section_id::CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
        _location_counters: &[crate::layout_rules::LocationCounter<'data>],
    ) -> (
        crate::output_section_id::OutputOrder<'data>,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        let mut builder =
            OutputOrderBuilder::<Self>::new(output_kind, output_sections, secondary, false, &[]);

        // File header and all load commands.
        builder.add_section(output_section_id::FILE_HEADER);
        builder.add_section(output_section_id::LOAD_COMMANDS);
        // Content of the sections (e.g. __text, __data).
        builder.add_section(output_section_id::TEXT);
        builder.add_section(output_section_id::CSTRING);
        builder.add_section(output_section_id::GCC_EXCEPT_TABLE);
        builder.add_section(output_section_id::UNWIND_INFO);
        builder.add_section(output_section_id::MACHO_EH_FRAME);
        builder.add_section(output_section_id::PLT_GOT);
        builder.add_section(output_section_id::DATA);
        builder.add_section(output_section_id::INIT_ARRAY);
        builder.add_section(output_section_id::FINI_ARRAY);
        // Sections we have no built-in ID for are mapped to `__DATA` by `mapped_segment_type`, so
        // they have to be added here or the segment's section count and its contents disagree.
        // They go before the zerofill sections below because they do have file content, and a
        // zerofill section is only free of a file offset while nothing follows it in the segment.
        //
        // Mach-O attributes report neither `alloc` nor `writable`, so the generic classifier puts
        // every custom section in the `nonalloc` bucket; there's nothing to read from the other
        // buckets.
        builder.add_sections(&custom.nonalloc);
        // ld64 puts the descriptors ahead of the thread-local data they point at. `__thread_data`
        // and `__thread_bss` are the template dyld copies for each thread, and a descriptor names
        // its variable by an offset into that template - so nothing may come between them, or the
        // offsets run past the end of what dyld allocated and it refuses to load the image.
        builder.add_section(output_section_id::THREAD_VARS);
        builder.add_section(output_section_id::TDATA);
        builder.add_section(output_section_id::TBSS);
        builder.add_section(output_section_id::COMMON);
        builder.add_section(output_section_id::BSS);
        builder.add_section(output_section_id::GOT);
        builder.add_section(output_section_id::CONST);
        // The rest (e.g. symbol table, string table).
        builder.add_section(output_section_id::STRTAB);
        builder.add_section(output_section_id::CHAINED_FIXUP_TABLE);
        // The local symbols have to precede the external ones for `LC_DYSYMTAB` to be able to name
        // each run as a contiguous range.
        builder.add_section(output_section_id::SYMTAB_LOCAL);
        builder.add_section(output_section_id::SYMTAB_GLOBAL);
        builder.add_section(output_section_id::INDIRECT_SYMTAB);
        builder.add_section(output_section_id::CODE_SIGNATURE);

        builder.build()
    }

    fn align_load_segment_start(
        segment_def: ProgramSegmentDef,
        segment_alignment: Alignment,
        file_offset: &mut usize,
        mem_offset: &mut u64,
    ) {
        match segment_def.segment_type {
            SegmentType::Text
            | SegmentType::DataSections
            | SegmentType::DataConstSections
            | SegmentType::LinkeditSections => {
                *file_offset = segment_alignment.align_up(*file_offset as u64) as usize;
                *mem_offset = segment_alignment.align_up(*mem_offset);
            }
            _ => {}
        }
    }

    fn default_symtab_entry() -> Self::SymtabEntry {
        Self::SymtabEntry {
            n_strx: Default::default(),
            n_type: Default::default(),
            n_sect: Default::default(),
            n_desc: Default::default(),
            n_value: Default::default(),
        }
    }

    fn last_part_size_to_extend(
        record: &OutputRecordLayout,
        last_part_id: part_id::PartId,
    ) -> Result<usize> {
        ensure!(
            last_part_id == part_id::CODE_SIGNATURE,
            "code signature must be last part_id"
        );
        // The CODE_SIGNATURE size depends on the final file size, excluding the
        // signature itself. Compute it after layout because there is one SHA hash
        // per file block (4 KiB) covered by the signature.
        Ok(record.file_offset.div_ceil(CS_BLOCK_SIZE) * CS_HASH_SIZE as usize)
    }

    fn is_allowed_in_archive(kind: crate::file_kind::FileKind) -> bool {
        kind == crate::file_kind::FileKind::MachOObject
    }
}

pub(crate) fn install_name<'data>(
    file_id: FileId,
    symbol_db: &crate::symbol_db::SymbolDb<'data, MachO>,
) -> &'data [u8] {
    match symbol_db.file(file_id) {
        SequencedInput::StubLibrary(stub) => stub.defined_symbols.install_name.as_bytes(),
        SequencedInput::Object(obj) => obj.parsed.input.lib_name(),
        _ => {
            panic!("Internal error: Expected StubLibrary or Dynamic");
        }
    }
}

fn create_dynamic_layout_ext<'data>(
    target_file_id: FileId,
    resources: &layout::FinaliseLayoutResources<'_, 'data, MachO>,
) -> Result<Option<DynamicLayoutExt>> {
    let Some(index) = resources
        .format_specific
        .imported_libraries
        .iter()
        .position(|file_id| *file_id == target_file_id)
    else {
        return Ok(None);
    };

    Ok(Some(DynamicLayoutExt {
        ordinal: NonZeroU8::new(u8::try_from(index + 1).context("Too many loaded stub libraries")?)
            .unwrap(),
    }))
}

const SECTION_DEFINITIONS: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] = {
    let mut defs: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] =
        [DEFAULT_DEFS; NUM_BUILT_IN_SECTIONS];

    defs[output_section_id::FILE_HEADER.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"FILE_HEADER")),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::LOAD_COMMANDS.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"LOAD_COMMANDS")),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::LINK_EDIT_SEGMENT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(SEG_LINKEDIT.as_bytes())),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::STRTAB.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"STRTAB")),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CHAINED_FIXUP_TABLE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"DYLD_CHAINED_FIXUPS_TABLE")),
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::INDIRECT_SYMTAB.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"INDIRECT_SYMTAB")),
        min_alignment: alignment::SYMTAB_SHNDX_ENTRY,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::SYMTAB_GLOBAL.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"SYMTAB")),
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    };
    defs[output_section_id::UNWIND_INFO.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__unwind_info")),
        section_flags: macho::S_REGULAR.to_flags(),
        min_alignment: Alignment { exponent: 2 },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CODE_SIGNATURE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"CODE_SIGNATURE")),
        min_alignment: Alignment {
            exponent: CS_SECTION_ALIGNMENT_EXP,
        },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::GOT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__got")),
        // Says the section is an array of symbol pointers, which is what makes `reserved1` mean an
        // index into the indirect symbol table. Only correct because we now emit that table.
        section_flags: macho::S_NON_LAZY_SYMBOL_POINTERS.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::PLT_GOT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__stubs")),
        section_flags: macho::S_SYMBOL_STUBS
            .to_flags()
            .with(macho::S_ATTR_PURE_INSTRUCTIONS)
            .with(macho::S_ATTR_SOME_INSTRUCTIONS),
        min_alignment: Alignment { exponent: 2 },
        ..DEFAULT_DEFS
    };
    // Multi-part generated sections
    // Start of regular sections
    defs[output_section_id::TEXT.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__text")),
        section_flags: macho::S_REGULAR
            .to_flags()
            .with(macho::S_ATTR_PURE_INSTRUCTIONS)
            .with(macho::S_ATTR_SOME_INSTRUCTIONS),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CSTRING.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__cstring")),
        section_flags: macho::S_CSTRING_LITERALS.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::CONST.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__const")),
        section_flags: macho::S_REGULAR.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::GCC_EXCEPT_TABLE.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__gcc_except_tab")),
        section_flags: macho::S_REGULAR.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::DATA.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__data")),
        section_flags: macho::S_REGULAR.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::THREAD_VARS.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__thread_vars")),
        section_flags: macho::S_THREAD_LOCAL_VARIABLES.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::TDATA.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__thread_data")),
        section_flags: macho::S_THREAD_LOCAL_REGULAR.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::TBSS.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__thread_bss")),
        section_flags: macho::S_THREAD_LOCAL_ZEROFILL.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::INIT_ARRAY.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__mod_init_func")),
        // The type is what makes dyld call these rather than just map them, so it has to survive
        // into the output - a `S_REGULAR` section of the same name is just an array of pointers
        // nobody reads.
        section_flags: macho::S_MOD_INIT_FUNC_POINTERS.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::FINI_ARRAY.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__mod_term_func")),
        section_flags: macho::S_MOD_TERM_FUNC_POINTERS.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::MACHO_EH_FRAME.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__eh_frame")),
        section_flags: macho::S_REGULAR.to_flags().with(macho::S_ATTR_LIVE_SUPPORT),
        min_alignment: Alignment { exponent: 3 },
        ..DEFAULT_DEFS
    };
    defs[output_section_id::COMMON.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__common")),
        section_flags: macho::S_ZEROFILL.to_flags(),
        ..DEFAULT_DEFS
    };
    defs[output_section_id::BSS.as_usize()] = BuiltInSectionDetails {
        kind: SectionKind::Primary(SectionName(b"__bss")),
        section_flags: macho::S_ZEROFILL.to_flags(),
        ..DEFAULT_DEFS
    };

    defs
};

#[derive(Debug, Default)]
pub(crate) struct EpilogueLayoutExt {
    imported_symbols: Vec<SymbolId>,
}

#[derive(Debug)]
pub(crate) struct DynamicLayoutStateExt {
    imported_symbols: Vec<SymbolId>,
    loaded: bool,
}

#[derive(Debug)]
pub(crate) struct DynamicLayoutExt {
    pub(crate) ordinal: NonZeroU8,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ResolutionExt {
    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
}

/// Which pieces of indirection a symbol gets: a `__stubs` (PLT) entry and/or a `__got` entry.
///
/// This exists so that the two passes that care can't drift apart. `allocate_resolution` runs
/// during sizing and reserves the bytes; `create_resolution` runs during address assignment and
/// hands out the addresses. If they disagree, addresses run past the space that was reserved and
/// `OffsetVerifier` reports "Unexpected memory offsets" for `__got`.
#[derive(Clone, Copy)]
struct Indirection {
    plt: bool,
    got: bool,
}

impl Indirection {
    /// A symbol imported from a dylib needs indirection because its address isn't known until dyld
    /// binds it. A symbol defined in the output doesn't: a `GOT_LOAD` relocation against it is
    /// relaxed into direct addressing when the relocation is applied (`Arch::relax_got_load`),
    /// which is what ld64 does too.
    ///
    /// The exception is a reference that stores the address of the slot rather than reading through
    /// it, since something else will dereference what it finds there. That can't be relaxed away,
    /// so the slot has to exist even for a symbol we know the address of - which is how a CIE
    /// reaches a personality routine defined in this image.
    fn for_symbol(flags: ValueFlags) -> Self {
        let indirect = flags.is_dynamic();

        Self {
            plt: indirect && flags.needs_plt(),
            got: (indirect && (flags.needs_got() || flags.needs_plt())) || flags.needs_got_entry(),
        }
    }
}

fn allocate_got(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let got_address = NonZeroU64::new(*memory_offsets.get(part_id::GOT)).unwrap();
    memory_offsets.increment(part_id::GOT, GOT_ENTRY_SIZE);
    got_address
}

fn allocate_plt(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let plt_address = NonZeroU64::new(*memory_offsets.get(part_id::PLT_GOT)).unwrap();
    memory_offsets.increment(part_id::PLT_GOT, PLT_ENTRY_SIZE);
    plt_address
}

// TODO: sort properly
const DEFAULT_SECTION_RULES: &[SectionRule<'static>] = &[
    SectionRule::exact_section(b"__text", crate::output_section_id::TEXT),
    // Also code: clang puts the functions that run global constructors here rather than in
    // `__text`. Getting this wrong is not a size difference - the catch-all below sends what it
    // doesn't recognise to `__DATA`, and a function there faults on the first instruction fetched.
    SectionRule::exact_section(b"__StaticInit", crate::output_section_id::TEXT),
    SectionRule::exact_section(b"__cstring", crate::output_section_id::CSTRING),
    SectionRule::exact_section(b"__ustring", crate::output_section_id::CONST),
    SectionRule::prefix_section(b"__objc_meth", crate::output_section_id::CSTRING),
    SectionRule::exact_section(b"__objc_classname", crate::output_section_id::CSTRING),
    SectionRule::exact_section(b"__const", crate::output_section_id::CONST),
    SectionRule::exact_section_keep(
        b"__gcc_except_tab",
        crate::output_section_id::GCC_EXCEPT_TABLE,
    ),
    SectionRule::exact_section(b"__data", crate::output_section_id::DATA),
    SectionRule::exact_section(b"__thread_vars", crate::output_section_id::THREAD_VARS),
    SectionRule::exact_section(b"__thread_data", crate::output_section_id::TDATA),
    SectionRule::exact_section(b"__thread_bss", crate::output_section_id::TBSS),
    // Roots. Nothing in the image refers to these, so without `keep` they are unreachable by
    // definition and would be dropped: dyld finds the initialiser lists from the section type, and
    // `__unwind_info` reaches into `__eh_frame` by offset rather than through a symbol.
    //
    // `__gcc_except_tab` is a root for a narrower reason: the only thing naming a landing pad is a
    // `__compact_unwind` entry, and those name it with a section-relative relocation, which the
    // reachability walk doesn't follow. Keeping it whole is larger than ld64's output but correct;
    // making it droppable needs the walk to follow those relocations first.
    SectionRule::exact_section_keep(b"__mod_init_func", crate::output_section_id::INIT_ARRAY),
    SectionRule::exact_section_keep(b"__mod_term_func", crate::output_section_id::FINI_ARRAY),
    SectionRule::exact_section(b"__common", crate::output_section_id::COMMON),
    SectionRule::exact_section(b"__bss", crate::output_section_id::BSS),
    // The literal pools are read-only constants that the assembler kept apart only so that the
    // linker could deduplicate them by size. We don't deduplicate them yet, and ld64 doesn't carry
    // the names through to the output either - it folds all three into `__TEXT,__const` - so
    // sending them there costs no fidelity.
    SectionRule::exact_section(b"__literal4", crate::output_section_id::CONST),
    SectionRule::exact_section(b"__literal8", crate::output_section_id::CONST),
    SectionRule::exact_section(b"__literal16", crate::output_section_id::CONST),
    // `__LD,__compact_unwind` is input to the linker, not output from it: ld64 consumes it to
    // build `__TEXT,__unwind_info` and emits no `__compact_unwind`. We can't build
    // `__unwind_info` yet (`warn_if_unwind_info_needed` says so when it matters), but copying
    // the raw input through would be wrong whether or not we could.
    // Not copied through: `SectionRuleOutcome::EhFrame` hands the section to
    // `load_exception_frame_data`, which is what we want for two reasons. Its relocations point
    // into `__text`, so copying it as an ordinary section would try to rebase pointers inside a
    // read-only segment; and the output we want from it isn't the input bytes at all, but the
    // `__unwind_info` table we build from them.
    SectionRule::exact(b"__compact_unwind", SectionRuleOutcome::EhFrame),
    // A root, like the initialiser lists: nothing in the image refers to `__eh_frame`, because the
    // `__unwind_info` entries that need it reach in by offset rather than by symbol.
    SectionRule::exact_section_keep(b"__eh_frame", crate::output_section_id::MACHO_EH_FRAME),
    // Debug info stays in the object files for `dsymutil` to collect into a .dSYM bundle; a linked
    // Mach-O image carries none of it. `__bitcode` and `__cmdline` are likewise only there to feed
    // LTO - `__bitcode` alone is 5 MiB in Rust's libstd.
    SectionRule::prefix(b"__debug_", SectionRuleOutcome::Discard),
    SectionRule::prefix(b"__apple_", SectionRuleOutcome::Discard),
    SectionRule::exact(b"__bitcode", SectionRuleOutcome::Discard),
    SectionRule::exact(b"__cmdline", SectionRuleOutcome::Discard),
];

pub(crate) const PROGRAM_SEGMENT_DEFS: &[ProgramSegmentDef] = &[
    ProgramSegmentDef {
        segment_type: SegmentType::Text,
        // Not a real segment from the Macho-O definition.
        count_as_segment: true,
    },
    ProgramSegmentDef {
        // Not a real segment from the Macho-O definition.
        segment_type: SegmentType::LoadCommands,
        // included in SegmentType::Text
        count_as_segment: false,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::TextSections,
        // included in SegmentType::Text
        count_as_segment: false,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::DataSections,
        count_as_segment: true,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::DataConstSections,
        count_as_segment: true,
    },
    ProgramSegmentDef {
        segment_type: SegmentType::LinkeditSections,
        count_as_segment: true,
    },
];

fn has_active_segment(header_info: &crate::layout::HeaderInfo, segment_type: SegmentType) -> bool {
    header_info.active_segment_ids.iter().any(|id| {
        PROGRAM_SEGMENT_DEFS
            .get(id.as_usize())
            .is_some_and(|def| def.segment_type == segment_type)
    })
}

fn count_sections_for_segment_type(
    output_sections: &crate::output_section_id::OutputSections<MachO>,
    segment_type: SegmentType,
) -> usize {
    let segment_def = ProgramSegmentDef {
        segment_type,
        count_as_segment: false,
    };
    output_sections
        .ids_with_info()
        .filter(|(section_id, _)| {
            output_sections.should_include_in_segment(*section_id, segment_def)
        })
        .count()
}

pub(crate) struct SegmentSectionsInfo<'data> {
    pub(crate) segment_size: OutputRecordLayout,
    pub(crate) segment_sections:
        Vec<(OutputRecordLayout, Option<SectionName<'data>>, SectionFlags)>,
    /// The same sections, in the same order, identified rather than measured. A symbol table entry
    /// names the section it's in by its position among the sections actually emitted, so that
    /// position has to come from here rather than from a separate walk that might disagree.
    pub(crate) section_ids: Vec<crate::output_section_id::OutputSectionId>,
}

pub(crate) fn get_segment_sections<'data>(
    layout: &Layout<'data, MachO>,
    segment_type: SegmentType,
) -> Option<SegmentSectionsInfo<'data>> {
    let mut in_matching_segment = false;
    let mut sections = Vec::new();
    let mut section_ids = Vec::new();
    let mut segment_id = None;

    for event in &layout.output_order {
        match event {
            OrderEvent::SegmentStart(seg_id)
                if layout.program_segments.segment_def(seg_id).segment_type == segment_type =>
            {
                segment_id = Some(seg_id);
                in_matching_segment = true;
            }
            OrderEvent::SegmentEnd(seg_id)
                if layout.program_segments.segment_def(seg_id).segment_type == segment_type
                    && in_matching_segment =>
            {
                break;
            }
            OrderEvent::Section(section_id) if in_matching_segment => {
                let sizes = *layout.section_layouts.get(section_id);
                sections.push((
                    sizes,
                    layout.output_sections.name(section_id),
                    layout.output_sections.section_flags(section_id),
                ));
                section_ids.push(section_id);
            }
            _ => {}
        }
    }

    let segment_id = segment_id.expect("must be visited in the output order");
    let segment_size = layout
        .segment_layouts
        .segments
        .iter()
        .find(|seg| seg.id == segment_id)
        .map(|seg| seg.sizes);

    segment_size.map(|segment_size| SegmentSectionsInfo {
        segment_sections: sections,
        section_ids,
        segment_size,
    })
}

#[inline(always)]
fn process_relocation<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    object: &layout::ObjectLayoutState<'data, MachO>,
    rel: &Relocation,
    section_index: object::SectionIndex,
    resources: &'scope layout::GraphResources<'data, '_, MachO>,
    queue: &mut layout::LocalWorkQueue,
    scope: &rayon::Scope<'scope>,
) -> Result {
    let rel_info = rel.info(LE);
    // r_extern == true if the reference points to a symbol
    if rel_info.r_extern {
        let local_sym_index = SymbolIndex(rel_info.r_symbolnum as usize);
        let symbol_db = resources.symbol_db;
        let local_symbol_id = object.symbol_id_range.input_to_id(local_sym_index);
        let symbol_id = symbol_db.definition(local_symbol_id);
        let mut flags = resources.local_flags_for_symbol(symbol_id);
        flags.merge(resources.local_flags_for_symbol(local_symbol_id));

        let relocation = A::relocation_from_raw(rel_info)?;
        let mut flags_to_add = layout::resolution_flags(relocation.kind);

        // The GOT-load relocations are written in a GOT-addressing form but don't require the slot
        // to exist - if the symbol's address is known at link time, `relax_got_load` rewrites the
        // instruction to address it directly. This one is different: it stores the address of the
        // slot for something else to dereference, so the slot has to be there.
        if rel_info.r_type == object::macho::ARM64_RELOC_POINTER_TO_GOT {
            flags_to_add |= ValueFlags::GOT_ENTRY_REQUIRED;
        }
        if is_dynamic_library(&symbol_db.file(symbol_db.file_id_for_symbol(symbol_id))) {
            flags_to_add |= ValueFlags::GOT;
            // TODO: classify symbols more reliably, likely by checking whether their section is
            // __text.
            if rel_info.r_type == object::macho::ARM64_RELOC_BRANCH26 {
                flags_to_add |= ValueFlags::FUNCTION | ValueFlags::PLT;
            }
        }

        let atomic_flags = &resources.per_symbol_flags.get_atomic(symbol_id);
        let previous_flags = atomic_flags.fetch_or(flags_to_add);

        // A branch can only reach so far. This records that the target is branched to, so that
        // layout can reserve an island for it if it turns out to land out of range - by the time
        // relocations are applied it is far too late to make room for one.
        crate::thunks::handle_thunk_extensions_for_relocation::<A>(
            object.section_part_id(section_index, &symbol_db.section_part_ids),
            resources,
            local_symbol_id,
            symbol_id,
            rel_info,
        );

        layout::check_for_undefined::<A>(
            object,
            object.object.section(section_index)?,
            rel_info.r_address.into(),
            local_sym_index,
            flags,
            symbol_id,
            resources,
        )?;

        if !previous_flags.has_resolution() {
            queue.send_symbol_request::<A>(symbol_id, resources, scope);
        }
    }

    Ok(())
}

fn is_dynamic_library(file: &SequencedInput<MachO>) -> bool {
    match file {
        SequencedInput::StubLibrary(_) => true,
        SequencedInput::Object(obj) => obj.is_dynamic(),
        _ => false,
    }
}

impl<'data> File<'data> {
    /// The object's sections as the linker sees them: one per atom.
    fn sections(&self) -> &[SectionHeader] {
        match &self.kind {
            ObjectKind::Regular(regular) => &regular.atoms.sections,
            ObjectKind::Dylib => &[],
        }
    }

    /// The sections as the file records them. Relocation offsets and the `n_sect` of a symbol are
    /// both expressed against these.
    fn file_sections(&self) -> &'data [SectionHeader] {
        match &self.kind {
            ObjectKind::Regular(regular) => regular.sections,
            ObjectKind::Dylib => &[],
        }
    }

    /// Returns the atom of real section `section` that `address` falls in, where `address` is in
    /// the object's own addressing.
    ///
    /// A relocation that names a section rather than a symbol gives a real section number, but
    /// everything downstream is indexed by atom, so the two have to be bridged.
    pub(crate) fn atom_for_address(
        &self,
        section: object::SectionIndex,
        address: u64,
    ) -> Option<object::SectionIndex> {
        self.atoms()?
            .atom_containing(section, address, self.file_sections())
    }

    fn atoms(&self) -> Option<&Atoms> {
        match &self.kind {
            ObjectKind::Regular(regular) => Some(&regular.atoms),
            ObjectKind::Dylib => None,
        }
    }

    /// Returns where an atom sits within the section it was cut from, and how long it is. Used to
    /// pick out the relocations that fall inside it, which are still recorded against the whole
    /// section.
    pub(crate) fn atom_span_in_parent(
        &self,
        index: object::SectionIndex,
    ) -> crate::error::Result<Range<u64>> {
        let atom = self.section(index)?;
        let parent = self.atom_parent_section(index)?;
        let offset = atom.addr.get(LE) - parent.addr.get(LE);
        Ok(offset..offset + atom.size.get(LE))
    }

    /// Returns the real section an atom was cut from.
    pub(crate) fn atom_parent_section(
        &self,
        index: object::SectionIndex,
    ) -> crate::error::Result<&'data SectionHeader> {
        let atoms = self
            .atoms()
            .ok_or_else(|| error!("Dylibs have no sections"))?;
        let parent = *atoms
            .parents
            .get(index.0)
            .ok_or_else(|| error!("Atom index out of range"))?;

        self.file_sections()
            .get(parent as usize)
            .ok_or_else(|| error!("Atom names a section that doesn't exist"))
    }
}

impl DynamicLayoutStateExt {
    fn new(args: &MachOArgs) -> Self {
        Self {
            imported_symbols: Default::default(),
            loaded: !args.dead_strip_dylibs,
        }
    }
}
