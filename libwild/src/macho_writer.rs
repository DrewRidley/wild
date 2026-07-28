use crate::alignment::MACHO_PAGE_ALIGNMENT;
use crate::bail;
use crate::elf::get_page_mask;
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use crate::file_writer::SizedOutput;
use crate::file_writer::split_buffers_by_alignment;
use crate::file_writer::split_output_by_group;
use crate::file_writer::split_output_into_sections;
use crate::layout::FileLayout;
use crate::layout::Layout;
use crate::layout::ObjectLayout;
use crate::layout::OutputRecordLayout;
use crate::layout::PreludeLayout;
use crate::layout::Resolution;
use crate::layout::Section;
use crate::layout::SymbolCopyInfo;
use crate::macho::BuildVersionCommand;
use crate::macho::CHAINED_FIXUP_PAGE_START_SIZE;
use crate::macho::COMPACT_UNWIND_ENTRY_SIZE;
use crate::macho::COMPACT_UNWIND_LSDA_OFFSET;
use crate::macho::COMPACT_UNWIND_PERSONALITY_OFFSET;
use crate::macho::CS_BLOB_HEADERS_SIZE;
use crate::macho::CS_BLOCK_SIZE;
use crate::macho::CS_BLOCK_SIZE_EXP;
use crate::macho::CS_HASH_SIZE;
use crate::macho::CS_HEADERS_SIZE;
use crate::macho::ChainedFixupsHeader;
use crate::macho::CodeSignatureCommand;
use crate::macho::DYLINKER_PATH;
use crate::macho::DyldChainedFixupsCommand;
use crate::macho::DylibCommand;
use crate::macho::DylinkerCommand;
use crate::macho::DysymtabCommand;
use crate::macho::EH_FRAME_PART_ID;
use crate::macho::EH_FRAME_SECTION_NAME;
use crate::macho::EhFrameRecord;
use crate::macho::EntryPointCommand;
use crate::macho::FDE_PC_BEGIN_OFFSET;
use crate::macho::FileHeader;
use crate::macho::GOT_ENTRY_SIZE;
use crate::macho::INDIRECT_SYMTAB_ENTRY_SIZE;
use crate::macho::MACHO_COMMAND_ALIGNMENT;
use crate::macho::MACHO_START_MEM_ADDRESS;
use crate::macho::MAX_SEGMENT_COUNT;
use crate::macho::MachO;
use crate::macho::PLT_ENTRY_SIZE;
use crate::macho::PROGRAM_SEGMENT_DEFS;
use crate::macho::Relocation as MachORelocation;
use crate::macho::RpathCommand;
use crate::macho::SEG_DATA_CONST;
use crate::macho::SectionEntry;
use crate::macho::SegmentCommand;
use crate::macho::SegmentSectionsInfo;
use crate::macho::SegmentType;
use crate::macho::SymtabCommand;
use crate::macho::UNWIND_ARM64_DWARF_SECTION_OFFSET;
use crate::macho::UNWIND_ARM64_MODE_DWARF;
use crate::macho::UNWIND_ARM64_MODE_MASK;
use crate::macho::UNWIND_INFO_COMPRESSED_ENCODING_SHIFT;
use crate::macho::UNWIND_INFO_COMPRESSED_ENTRY_SIZE;
use crate::macho::UNWIND_INFO_COMPRESSED_FUNCTION_OFFSET_MASK;
use crate::macho::UNWIND_INFO_COMPRESSED_PAGE_HEADER_SIZE;
use crate::macho::UNWIND_INFO_ENTRY_SIZE;
use crate::macho::UNWIND_INFO_HEADER_SIZE;
use crate::macho::UNWIND_INFO_INDEX_ENTRY_SIZE;
use crate::macho::UNWIND_INFO_LSDA_ENTRY_SIZE;
use crate::macho::UNWIND_INFO_MAX_COMMON_ENCODINGS;
use crate::macho::UNWIND_INFO_MAX_ENCODINGS_PER_PAGE;
use crate::macho::UNWIND_INFO_MAX_PERSONALITIES;
use crate::macho::UNWIND_INFO_PAGE_CAPACITY;
use crate::macho::UNWIND_INFO_PAGE_HEADER_SIZE;
use crate::macho::UNWIND_PERSONALITY_SHIFT;
use crate::macho::UNWIND_SECOND_LEVEL_COMPRESSED;
use crate::macho::UNWIND_SECOND_LEVEL_REGULAR;
use crate::macho::UNWIND_SECTION_VERSION;
use crate::macho::UuidCommand;
use crate::macho::code_signature_identifier;
use crate::macho::code_signature_padded_identifier_size;
use crate::macho::eh_frame_records;
use crate::macho::get_segment_sections;
use crate::macho::is_no_bits_section_type;
use crate::macho::load_dylib_command_size;
use crate::macho::relocations_by_record;
use crate::macho::rpath_command_size;
use crate::macho_debug_map::N_BNSYM;
use crate::macho_debug_map::N_ENSYM;
use crate::macho_debug_map::N_FUN;
use crate::macho_debug_map::N_GSYM;
use crate::macho_debug_map::N_OSO;
use crate::macho_debug_map::N_SO;
use crate::macho_debug_map::N_STSYM;
use crate::macho_object::CS_ADHOC;
use crate::macho_object::CS_EXECSEG_MAIN_BINARY;
use crate::macho_object::CS_HASHTYPE_SHA256;
use crate::macho_object::CS_LINKER_SIGNED;
use crate::macho_object::CS_SUPPORTSEXECSEG;
use crate::macho_object::CSMAGIC_CODEDIRECTORY;
use crate::macho_object::CSMAGIC_EMBEDDED_SIGNATURE;
use crate::macho_object::CSSLOT_CODEDIRECTORY;
use crate::macho_object::CodeSignatureBlobIndex;
use crate::macho_object::CodeSignatureCodeDirectory;
use crate::macho_object::CodeSignatureSuperBlob;
use crate::macho_object::DYLD_CHAINED_IMPORT;
use crate::macho_object::DYLD_CHAINED_PTR_64_OFFSET;
use crate::macho_object::DyldChainedStartsInSegment;
use crate::malfunction;
use crate::output_section_id;
use crate::output_section_id::SectionName;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::output_trace::HexU64;
use crate::output_trace::TraceOutput;
use crate::part_id;
use crate::platform::Arch;
use crate::platform::Args;
use crate::platform::ObjectFile;
use crate::platform::Symbol;
use crate::resolution::SectionSlot;
use crate::symbol_db::SymbolId;
use crate::timing_phase;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use hashbrown::HashMap;
use itertools::Itertools;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::utils::slice_from_all_bytes_mut;
use object::BigEndian;
use object::Endianness;
use object::SymbolIndex;
use object::U32;
use object::from_bytes_mut;
use object::macho;
use object::macho::CPU_SUBTYPE_ARM64_ALL;
use object::macho::CPU_TYPE_ARM64;
use object::macho::LC_BUILD_VERSION;
use object::macho::LC_CODE_SIGNATURE;
use object::macho::LC_DYLD_CHAINED_FIXUPS;
use object::macho::LC_DYSYMTAB;
use object::macho::LC_LOAD_DYLIB;
use object::macho::LC_LOAD_DYLINKER;
use object::macho::LC_MAIN;
use object::macho::LC_RPATH;
use object::macho::LC_SEGMENT_64;
use object::macho::LC_SYMTAB;
use object::macho::LC_UUID;
use object::macho::LoadCommand;
use object::macho::MH_CIGAM_64;
use object::macho::MH_EXECUTE;
use object::macho::N_ABS;
use object::macho::N_SECT;
use object::macho::PLATFORM_MACOS;
use object::macho::RelocationInfo;
use object::macho::SEG_DATA;
use object::macho::SEG_LINKEDIT;
use object::macho::SEG_PAGEZERO;
use object::macho::SEG_TEXT;
use object::macho::SegmentFlags;
use object::slice_from_bytes_mut;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use rayon::slice::ParallelSliceMut;
use sha2::Digest;
use sha2::Sha256;
use std::ops::BitAnd;
use std::sync::Mutex;
use tracing::debug_span;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

const LE: Endianness = Endianness::Little;

type MachOLayout<'data> = Layout<'data, MachO>;
type SymtabEntry = object::macho::Nlist64<Endianness>;

pub(crate) fn write<'data, A: Arch<Platform = MachO>>(
    sized_output: &mut SizedOutput,
    layout: &MachOLayout<'data>,
) -> Result {
    timing_phase!("Write data to file");

    let (mut section_buffers, mut padding) =
        split_output_into_sections(layout, &mut sized_output.out);
    padding.fill_zero();

    // Pointer-sized slots that dyld has to write to at load time: rebases, for slots holding an
    // address within this image that has to be slid by the load bias, and binds, for slots holding
    // the address of a symbol in another image. The `__got` binds are added later by
    // `write_chained_fixups`, since they follow from the import list rather than from a
    // relocation. These are discovered while relocations are applied, which happens in parallel,
    // so each group accumulates its own list and merges it in once.
    let fixup_sites = Mutex::new(Vec::new());

    let section_indices = build_section_index_map(layout)?;

    let mut writable_buckets = split_buffers_by_alignment(&mut section_buffers, layout);
    let groups_and_buffers = split_output_by_group(layout, &mut writable_buckets);
    groups_and_buffers
        .into_par_iter()
        .try_for_each(|(group, mut buffers)| -> Result {
            verbose_timing_phase!("Write group");

            let mut symbol_writer = MachOSymbolTableWriter {
                next_strtab_offset: group.strtab_start_offset,
                section_indices: &section_indices,
            };
            let mut group_fixups = Vec::new();
            for file in &group.files {
                write_file::<A>(
                    file,
                    &mut buffers,
                    layout,
                    &sized_output.trace,
                    &mut symbol_writer,
                    &mut group_fixups,
                )
                .with_context(|| format!("Failed copying from {file} to output file"))?;
            }
            if !group_fixups.is_empty() {
                fixup_sites
                    .lock()
                    .expect("Fixup site list mutex was poisoned")
                    .append(&mut group_fixups);
            }
            Ok(())
        })?;

    let mut fixup_sites = fixup_sites
        .into_inner()
        .expect("Fixup site list mutex was poisoned");

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    write_got_entries(
        layout,
        section_buffers.get_mut(output_section_id::GOT),
        &mut fixup_sites,
    )?;
    write_plt_entries::<A>(layout, section_buffers.get_mut(output_section_id::PLT_GOT))?;
    write_indirect_symtab(
        layout,
        section_buffers.get_mut(output_section_id::INDIRECT_SYMTAB),
    )?;
    write_unwind_info(
        layout,
        section_buffers.get_mut(output_section_id::UNWIND_INFO),
    )?;
    drop(section_buffers);

    write_chained_fixups(layout, sized_output, fixup_sites)?;

    // Not part of the image: an account of what ended up where, for whoever asked for one.
    if let Some(path) = &layout.args().map_path {
        crate::macho_map::write_link_map(layout, path)?;
    }

    write_code_signature_metadata(layout, sized_output)?;
    write_uuid(layout, sized_output)?;
    write_code_signature_hashes(layout, sized_output)?;

    Ok(())
}

/// Fails the link when the output contains thread-local variables.
///
/// The addressing side of thread-local storage works: `__thread_vars`, `__thread_data` and
/// `__thread_bss` are laid out into `__DATA`, and the TLVP relocation pair relaxes to a direct
/// reference to the descriptor exactly as ld64 does. What is missing is the descriptor contents.
fn write_file<'data, A: Arch<Platform = MachO>>(
    file: &FileLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    _trace: &TraceOutput,
    symbol_writer: &mut MachOSymbolTableWriter<'_>,
    fixup_sites: &mut Vec<FixupSite>,
) -> Result {
    match file {
        FileLayout::Object(s) => {
            write_object::<A>(s, buffers, layout, symbol_writer, fixup_sites)?;
        }
        FileLayout::Prelude(s) => write_prelude(s, buffers, layout)?,
        FileLayout::Epilogue(epilogue) => {
            write_epilogue(epilogue, buffers, layout, symbol_writer)?;
        }

        // Nothing of a dylib is copied into the image. What we take from one is the names of the
        // symbols it supplies, and those are written by the epilogue as undefined entries.
        FileLayout::Dynamic(_) | FileLayout::StubLibrary(_) => {}

        // A file that was never loaded contributes nothing by definition.
        FileLayout::NotLoaded => {}

        // Linker-defined symbols resolve references but are not written to the symbol table, so
        // there is nothing here either - `allocate_internal_symbol` reserves no space for them for
        // the same reason.
        FileLayout::SyntheticSymbols(_) => {}

        FileLayout::LinkerScript(_) => {
            bail!("Linker scripts are not supported for Mach-O")
        }
    }
    Ok(())
}

/// Writes the table dyld searches to find what this image exports.
///
/// The addresses are known now, so the trie is rebuilt with the real ones rather than the widest
/// possible ones it was measured with. That can only make it smaller, so it fits the space
/// reserved; whatever is left over stays zero, which reads as a trie with nothing beyond its root.
fn write_export_trie(
    epilogue: &crate::layout::EpilogueLayout<MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'_>,
) -> Result {
    let exports = &epilogue.format_specific.exported_symbols;

    if exports.is_empty() {
        return Ok(());
    }

    let image_base = layout
        .section_layouts
        .get(output_section_id::FILE_HEADER)
        .mem_offset;

    let mut entries = Vec::with_capacity(exports.len());

    for &symbol_id in exports {
        let name = layout.symbol_db.symbol_name(symbol_id)?.bytes();

        let Some(resolution) = layout.merged_symbol_resolution(symbol_id) else {
            continue;
        };

        // What dyld stores is where the symbol sits in the image, not where it happened to be laid
        // out, because the image can be loaded anywhere.
        let address = resolution
            .raw_value
            .checked_sub(image_base)
            .with_context(|| {
                format!(
                    "Exported symbol {} is before the image base",
                    layout.symbol_db.symbol_name_for_display(symbol_id)
                )
            })?;

        entries.push((name, address));
    }

    let trie = crate::macho_export_trie::ExportTrie::build(&entries);
    let out = buffers.get_mut(part_id::EXPORT_TRIE);

    trie.write(out)
}

fn write_epilogue(
    epilogue: &crate::layout::EpilogueLayout<MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'_>,
    symbol_writer: &mut MachOSymbolTableWriter<'_>,
) -> Result {
    verbose_timing_phase!("Write epilogue");

    write_export_trie(epilogue, buffers, layout)?;

    for imported_symbol in &layout.format_specific.imported_symbols {
        let name = layout
            .symbol_db
            .symbol_name(imported_symbol.symbol_id)?
            .bytes();

        let file_id = layout
            .symbol_db
            .file_id_for_symbol(imported_symbol.symbol_id);

        let dynamic = match layout.file_layout(file_id) {
            FileLayout::StubLibrary(file) => &file.format_specific,
            FileLayout::Dynamic(file) => &file.format_specific,
            _ => bail!(
                "Imported symbol `{}` is not from a dylib",
                String::from_utf8_lossy(name)
            ),
        };

        // A two-level namespace binary records which dylib each undefined symbol is expected to
        // come from, in the same 1-based numbering the chained-fixup imports use.
        let desc = macho::SymbolDesc::from(macho::SymbolLibrary(dynamic.ordinal.get()));

        symbol_writer.define_symbol(
            buffers,
            name,
            0,
            macho::SymbolFlags(macho::N_EXT.0).with_type(macho::N_UNDF),
            desc,
            0,
        )?;
    }

    Ok(())
}

/// Takes enough bytes from `bytes` for a T, returning those bytes as an `&mut T`.
fn take_mut<'out, T: object::Pod>(bytes: &mut &'out mut [u8]) -> Result<&'out mut T> {
    let bytes = bytes
        .split_off_mut(..size_of::<T>())
        .context("Insufficient allocation")?;
    from_bytes_mut::<T>(bytes)
        .map_err(|()| error!("Unaligned write"))
        .map(|(a, _)| a)
}

fn write_prelude<'data>(
    prelude: &PreludeLayout<MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
) -> Result {
    verbose_timing_phase!("Write prelude");

    // The deduplicated strings are laid out as one block per output section, and sized into the
    // prelude's share of it, so the prelude is what writes them.
    layout.merged_strings.for_each(|section_id, merged| {
        if merged.len() > 0 {
            let buffer = buffers.get_mut(section_id.part_id_with_alignment(crate::alignment::MIN));
            crate::elf_writer::write_merged_strings_to_buffer(merged, buffer);
        }
    });

    debug_assert_eq!(
        prelude.format_specific.imported_library_file_ids.len(),
        prelude.format_specific.load_dylib_command_sizes.len()
    );

    let header_buffer = buffers.get_mut(part_id::FILE_HEADER);
    populate_file_header(layout, prelude, take_mut(header_buffer)?)?;
    ensure!(header_buffer.is_empty(), "Excess FILE_HEADER allocation");

    let mut load_command_buffer = slice_from_all_bytes_mut(buffers.get_mut(part_id::LOAD_COMMANDS));
    write_segment_commands(layout, &mut load_command_buffer)?;

    if layout.args().is_executable() {
        write_entry_point_command(layout, take_mut(&mut load_command_buffer)?)?;
    } else {
        // Nothing enters a dylib or a bundle at one address - callers arrive through its exports -
        // so instead of an entry point it records where the table of those exports is. A dylib also
        // records the name it will be found by; a bundle is opened by path and has none.
        if layout.args().dylib {
            write_id_dylib_command(layout, &mut load_command_buffer)?;
        }

        write_exports_trie_command(layout, take_mut(&mut load_command_buffer)?);
    }

    write_uuid_command(take_mut(&mut load_command_buffer)?);

    if layout.args().platform_version.is_some() {
        let build_version_command = take_mut(&mut load_command_buffer)?;
        write_build_version_command(layout, build_version_command)?;
    }

    let command_size = (size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
        .next_multiple_of(MACHO_COMMAND_ALIGNMENT);
    let mut command_buffer = load_command_buffer.split_off_mut(..command_size).unwrap();
    let dylinker_command = take_mut(&mut command_buffer)?;
    write_dylinker_command(dylinker_command, command_buffer);

    for (&file_id, &command_size) in prelude
        .format_specific
        .imported_library_file_ids
        .iter()
        .zip(&prelude.format_specific.load_dylib_command_sizes)
    {
        let mut command_buffer = load_command_buffer.split_off_mut(..command_size).unwrap();
        let dylib_command = take_mut(&mut command_buffer)?;
        let path = crate::macho::install_name(file_id, &layout.symbol_db);
        let versions = crate::macho::dylib_versions(file_id, &layout.symbol_db);
        let is_weak = crate::macho::is_weak_library(file_id, &layout.symbol_db);

        write_dylib_command(dylib_command, command_buffer, path, versions, is_weak);
    }

    for rpath in &layout.args().rpaths {
        let command_size = rpath_command_size(rpath);
        let mut command_buffer = load_command_buffer.split_off_mut(..command_size).unwrap();
        let rpath_command = take_mut(&mut command_buffer)?;

        write_rpath_command(rpath_command, command_buffer, rpath);
    }

    write_dyld_chained_fixups_command(layout, take_mut(&mut load_command_buffer)?);

    write_symtab_command(layout, take_mut(&mut load_command_buffer)?);

    write_dysymtab_command(layout, take_mut(&mut load_command_buffer)?);

    write_code_signature_command(layout, take_mut(&mut load_command_buffer)?);

    ensure!(
        load_command_buffer.is_empty(),
        "Excess LOAD_COMMANDS allocation"
    );

    // Fill up one extra character as n_strx == 0 is treated as unnamed.
    buffers.get_mut(part_id::STRTAB).fill(0);

    Ok(())
}

fn write_got_entries(
    layout: &MachOLayout<'_>,
    got: &mut [u8],
    fixup_sites: &mut Vec<FixupSite>,
) -> Result {
    let got_layout = layout.section_layouts.get(output_section_id::GOT);

    // Slots for symbols defined here hold the symbol's own address rather than a bind, so we fill
    // them in and record a rebase, the same as any other pointer we write into the image.
    for local in &layout.format_specific.local_got_symbols {
        let offset = local
            .got_address
            .get()
            .checked_sub(got_layout.mem_offset)
            .ok_or_else(|| error!("GOT entry address is before __got"))?
            as usize;

        let slot = got
            .get_mut(offset..offset + GOT_ENTRY_SIZE as usize)
            .ok_or_else(|| error!("GOT entry is outside __got"))?;
        slot.copy_from_slice(&local.value.to_le_bytes());

        // A resolution of zero is an undefined weak reference; it stays null rather than becoming
        // a pointer to the image base.
        if local.value != 0 {
            fixup_sites.push(FixupSite {
                address: local.got_address.get(),
                is_bind: false,
            });
        }
    }

    let sorted_symbols = &layout.format_specific.imported_symbols;
    for (i, imported_symbol) in sorted_symbols.iter().enumerate() {
        let offset = imported_symbol
            .got_address
            .get()
            .checked_sub(got_layout.mem_offset)
            .ok_or_else(|| error!("GOT entry address is before __got"))?
            as usize;
        let end = offset + GOT_ENTRY_SIZE as usize;

        /* DYLD_CHAINED_PTR_64 format:
        uint64_t dyld_chained_ptr_64_bind:
          ordinal: 24
          addend: 8 // 0 thru 255
          reserved: 19 // all zeros
          next: 12 // 4-byte stride
          bind: 1 // == 1
        */
        let bind = 1u64 << 63;
        let ordinal = i as u64;

        // The `next` field is deliberately left as zero here. Binds and rebases share a single
        // chain per page, so the distance to the following link can only be computed once every
        // fixup in the image is known. `write_chained_fixups` fills it in.
        got[offset..end].copy_from_slice(&(bind | ordinal).to_le_bytes());
    }

    Ok(())
}

fn write_plt_entries<A: Arch<Platform = MachO>>(
    layout: &MachOLayout<'_>,
    plt: &mut [u8],
) -> Result {
    let plt_layout = layout.section_layouts.get(output_section_id::PLT_GOT);

    for imported_symbol in &layout.format_specific.imported_symbols {
        let Some(stub_address) = imported_symbol.plt_address else {
            continue;
        };

        let offset = stub_address
            .get()
            .checked_sub(plt_layout.mem_offset)
            .ok_or_else(|| error!("STUB entry address is before __stubs"))?
            as usize;
        let end = offset + PLT_ENTRY_SIZE as usize;

        A::write_plt_entry(
            &mut plt[offset..end],
            imported_symbol.got_address.get(),
            stub_address.get(),
        )?;
    }

    Ok(())
}

fn populate_file_header(
    layout: &MachOLayout,
    prelude: &PreludeLayout<MachO>,
    header: &mut FileHeader,
) -> Result {
    let load_commands_info = get_segment_sections(layout, SegmentType::LoadCommands)
        .ok_or_else(|| error!("LoadCommands segment is mandatory"))?;

    header.magic.set(BigEndian, MH_CIGAM_64);
    header.cputype.set(LE, CPU_TYPE_ARM64);
    header.cpusubtype.set(LE, CPU_SUBTYPE_ARM64_ALL.into());
    header.filetype.set(
        LE,
        if layout.args().dylib {
            macho::MH_DYLIB
        } else if layout.args().bundle {
            macho::MH_BUNDLE
        } else {
            MH_EXECUTE
        },
    );
    header
        .ncmds
        .set(LE, prelude.format_specific.load_command_count as u32);
    header
        .sizeofcmds
        .set(LE, load_commands_info.segment_size.file_size as u32);
    // `MH_PIE` says an executable may be loaded anywhere; a dylib always may, and setting it there
    // is meaningless. `MH_NOUNDEFS` claims nothing is left unresolved, which only holds when there
    // are no imports to bind.
    let mut flags = macho::MH_DYLDLINK | macho::MH_TWOLEVEL;

    if layout.args().is_executable() {
        flags |= macho::MH_PIE;
    }

    if layout.format_specific.imported_symbols.is_empty() {
        flags |= macho::MH_NOUNDEFS;
    }

    // dyld only walks `__thread_vars` and fills in each descriptor's thunk and key if this flag
    // says the image has descriptors to fill in. Without it the descriptors keep whatever the
    // linker left in them and the first access calls straight into `__tlv_bootstrap`, which aborts.
    if layout
        .section_layouts
        .get(output_section_id::THREAD_VARS)
        .mem_size
        > 0
    {
        flags |= macho::MH_HAS_TLV_DESCRIPTORS;
    }

    // Malfunction: clear MH_PIE. The binary still links and still runs, but it is no longer
    // position independent, so the loader stops applying ASLR to it. This is the archetypal
    // silent security regression, and it is invisible to anything that doesn't read the Mach-O
    // header flags.
    if malfunction::malfunction_point("macho-no-pie") {
        flags = macho::FileFlags(flags.0 & !macho::MH_PIE.0);
    }

    header.flags.set(LE, flags);
    header.reserved.set(LE, 0);
    Ok(())
}

fn split_segment_command_buffer(
    mut bytes: &mut [u8],
    section_count: usize,
) -> Result<(&mut SegmentCommand, &mut [SectionEntry])> {
    let command = take_mut(&mut bytes)?;
    let (sections, rest) = slice_from_bytes_mut(bytes, section_count)
        .map_err(|_| error!("Invalid segment section allocation"))?;
    ensure!(
        rest.is_empty(),
        "Trailing bytes in segment command allocation"
    );
    Ok((command, sections))
}

/// Writes `LC_ID_DYLIB`: the name this dylib will be looked up by.
fn write_id_dylib_command(layout: &MachOLayout<'_>, buffer: &mut &mut [u8]) -> Result {
    let name = crate::macho::own_install_name(layout.args());
    let size = crate::macho::load_dylib_command_size(name);

    let buffer = buffer
        .split_off_mut(..size)
        .ok_or_else(|| error!("Invalid LOAD_COMMANDS allocation"))?;

    let (command, path_buffer) = buffer.split_at_mut(size_of::<DylibCommand>());
    let command: &mut DylibCommand = from_bytes_mut(command)
        .map_err(|_| error!("Invalid LC_ID_DYLIB allocation"))?
        .0;

    // Ours to declare rather than to copy, and zero unless we were told otherwise - which is what
    // ld64 writes for a dylib built without `-compatibility_version` or `-current_version`.
    let zero = object::macho::Version::new(0, 0, 0);
    let versions = crate::macho::DylibVersions {
        compatibility: layout
            .args()
            .compatibility_version
            .as_ref()
            .map_or(zero, |version| version.get()),
        current: layout
            .args()
            .current_version
            .as_ref()
            .map_or(zero, |version| version.get()),
    };

    write_dylib_command(command, path_buffer, name, versions, false);
    // Same shape as a load command, differing only in which question it answers: this names the
    // library itself rather than one it depends on.
    command.cmd.set(LE, object::macho::LC_ID_DYLIB);

    Ok(())
}

/// Writes `LC_DYLD_EXPORTS_TRIE`, which points dyld at the table of what this image supplies.
fn write_exports_trie_command(
    layout: &MachOLayout<'_>,
    command: &mut object::macho::LinkeditDataCommand<Endianness>,
) {
    let trie = layout.section_layouts.get(output_section_id::EXPORT_TRIE);

    command.cmd.set(LE, object::macho::LC_DYLD_EXPORTS_TRIE);
    command.cmdsize.set(
        LE,
        size_of::<object::macho::LinkeditDataCommand<Endianness>>() as u32,
    );
    command.dataoff.set(LE, trie.file_offset as u32);
    command.datasize.set(LE, trie.file_size as u32);
}

fn write_segment_commands(layout: &MachOLayout, load_commands: &mut &mut [u8]) -> Result {
    let load_cmd_err = |()| error!("Invalid LOAD_COMMANDS allocation");
    let num_stub_slots = num_stub_slots(layout);

    // `__PAGEZERO` reserves the bottom of the address space so that a null dereference faults. That
    // is the process's address space, not the library's, so only an executable declares it - a
    // dylib is mapped into someone else's.
    let pagezero_segment = take_mut(load_commands)?;
    write_segment(
        SEG_PAGEZERO,
        macho::VmProt(0),
        pagezero_segment,
        0,
        0,
        0,
        if layout.args().is_executable() {
            MACHO_START_MEM_ADDRESS
        } else {
            0
        },
        0,
        SegmentFlags::default(),
    );

    let text_segment_sections = get_segment_sections(layout, SegmentType::TextSections)
        .ok_or_else(|| error!("TextSections segment is mandatory"))?
        .segment_sections;
    // The __TEXT segment in the layout includes also all the commands!
    let text_segment_size = get_segment_sections(layout, SegmentType::Text)
        .ok_or_else(|| error!("Text segment is mandatory"))?
        .segment_size;
    let command_size =
        size_of::<SegmentCommand>() + size_of::<SectionEntry>() * text_segment_sections.len();
    let (text_segment, text_sections) = split_segment_command_buffer(
        load_commands
            .split_off_mut(..command_size)
            .ok_or_else(|| load_cmd_err(()))?,
        text_segment_sections.len(),
    )?;
    write_segment(
        SEG_TEXT,
        macho::VM_PROT_READ | macho::VM_PROT_EXECUTE,
        text_segment,
        text_segment_size.file_offset as u64,
        text_segment_size.file_size as u64,
        text_segment_size.mem_offset,
        text_segment_size.mem_size,
        text_segment_sections.len(),
        SegmentFlags::default(),
    );
    write_sections(
        SEG_TEXT,
        num_stub_slots,
        text_sections,
        &text_segment_sections,
    )?;

    if let Some(data_segment_info) = get_segment_sections(layout, SegmentType::DataSections) {
        let data_segment_sections = data_segment_info.segment_sections;
        let data_segment_size = data_segment_info.segment_size;
        let command_size =
            size_of::<SegmentCommand>() + size_of::<SectionEntry>() * data_segment_sections.len();
        let (data_segment, data_sections) = split_segment_command_buffer(
            load_commands
                .split_off_mut(..command_size)
                .ok_or_else(|| load_cmd_err(()))?,
            data_segment_sections.len(),
        )?;
        write_segment(
            SEG_DATA,
            macho::VM_PROT_READ | macho::VM_PROT_WRITE,
            data_segment,
            data_segment_size.file_offset as u64,
            data_segment_size.file_size as u64,
            data_segment_size.mem_offset,
            data_segment_size.mem_size,
            data_segment_sections.len(),
            SegmentFlags::default(),
        );
        write_sections(
            SEG_DATA,
            num_stub_slots,
            data_sections,
            &data_segment_sections,
        )?;
    }

    if let Some(data_const_segment_info) =
        get_segment_sections(layout, SegmentType::DataConstSections)
    {
        let data_const_segment_sections = data_const_segment_info.segment_sections;
        let data_const_segment_size = data_const_segment_info.segment_size;
        let command_size = size_of::<SegmentCommand>()
            + size_of::<SectionEntry>() * data_const_segment_sections.len();
        let (data_const_segment, data_const_sections) = split_segment_command_buffer(
            load_commands
                .split_off_mut(..command_size)
                .ok_or_else(|| load_cmd_err(()))?,
            data_const_segment_sections.len(),
        )?;
        write_segment(
            SEG_DATA_CONST,
            macho::VM_PROT_READ | macho::VM_PROT_WRITE,
            data_const_segment,
            data_const_segment_size.file_offset as u64,
            data_const_segment_size.file_size as u64,
            data_const_segment_size.mem_offset,
            data_const_segment_size.mem_size,
            data_const_segment_sections.len(),
            macho::SG_READ_ONLY,
        );
        write_sections(
            SEG_DATA_CONST,
            num_stub_slots,
            data_const_sections,
            &data_const_segment_sections,
        )?;
    }

    let linkedit_segment_size = get_segment_sections(layout, SegmentType::LinkeditSections)
        .ok_or_else(|| error!("LinkeditSections segment is mandatory"))?
        .segment_size;
    let linkedit_segment = from_bytes_mut(
        load_commands
            .split_off_mut(..size_of::<SegmentCommand>())
            .ok_or_else(|| load_cmd_err(()))?,
    )
    .map_err(load_cmd_err)?
    .0;
    write_segment(
        SEG_LINKEDIT,
        macho::VM_PROT_READ,
        linkedit_segment,
        linkedit_segment_size.file_offset as u64,
        linkedit_segment_size.file_size as u64,
        linkedit_segment_size.mem_offset,
        linkedit_segment_size.mem_size,
        // The sections in the __LINKEDIT are "hidden".
        0,
        SegmentFlags::default(),
    );
    Ok(())
}

fn write_segment(
    seg_name: &str,
    prot_flags: object::macho::VmProt,
    segment_cmd: &mut SegmentCommand,
    file_offset: u64,
    file_size: u64,
    mem_offset: u64,
    mem_size: u64,
    section_count: usize,
    flags: macho::SegmentFlags,
) {
    segment_cmd.cmd.set(LE, LC_SEGMENT_64);
    segment_cmd.cmdsize.set(
        LE,
        (size_of::<SegmentCommand>() + size_of::<SectionEntry>() * section_count) as u32,
    );
    segment_cmd.segname[..seg_name.len()].copy_from_slice(seg_name.as_bytes());
    segment_cmd.segname[seg_name.len()..].zero();
    segment_cmd.fileoff.set(LE, file_offset);
    segment_cmd.filesize.set(LE, file_size);
    segment_cmd.vmaddr.set(LE, mem_offset);
    segment_cmd.vmsize.set(LE, mem_size);
    segment_cmd.maxprot.set(LE, prot_flags);
    segment_cmd.initprot.set(LE, prot_flags);
    segment_cmd.nsects.set(LE, section_count as u32);
    segment_cmd.flags.set(LE, flags);
}

fn write_sections(
    seg_name: &str,
    num_stub_slots: u32,
    sections: &mut [SectionEntry],
    segment_sections: &[(
        OutputRecordLayout,
        Option<SectionName<'_>>,
        crate::macho::SectionFlags,
    )],
) -> Result {
    for (section, (size, section_name, section_flags)) in sections.iter_mut().zip(segment_sections)
    {
        let section_name = section_name
            .ok_or_else(|| error!("section name must be known"))?
            .0;

        section.segname[..seg_name.len()].copy_from_slice(seg_name.as_bytes());
        section.segname[seg_name.len()..].zero();
        section.sectname[..section_name.len()].copy_from_slice(section_name);
        section.sectname[section_name.len()..].zero();
        section.addr.set(LE, size.mem_offset);
        section.size.set(LE, size.mem_size);

        // A zerofill section has no bytes in the file, so there's no file offset to name. ld64
        // writes zero here, and tools read the field without first checking the section type, so
        // pointing it at the byte that happens to follow the segment would misreport the contents.
        let file_offset = if is_no_bits_section_type(section_flags.typ()) {
            0
        } else {
            size.file_offset as u32
        };
        section.offset.set(LE, file_offset);
        section.align.set(LE, u32::from(size.alignment.exponent));
        section.reloff.set(LE, 0);
        section.nreloc.set(LE, 0);
        section.flags.set(LE, *section_flags);

        // For a section whose type says its contents are stubs or symbol pointers, `reserved1` is
        // where that section's run starts in the indirect symbol table. `write_indirect_symtab`
        // emits the runs in this order, so the two have to be changed together.
        let (reserved1, reserved2) = match section_flags.typ() {
            macho::S_SYMBOL_STUBS => (0, PLT_ENTRY_SIZE as u32),
            macho::S_NON_LAZY_SYMBOL_POINTERS => (num_stub_slots, 0),
            _ => (0, 0),
        };
        section.reserved1.set(LE, reserved1);
        section.reserved2.set(LE, reserved2);
        section.reserved3.set(LE, 0);
    }

    Ok(())
}

fn write_object<'data, A: Arch<Platform = MachO>>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    symbol_writer: &mut MachOSymbolTableWriter<'_>,
    fixup_sites: &mut Vec<FixupSite>,
) -> Result {
    verbose_timing_phase!("Write object", file_id = object.file_id.as_u32());

    let _span = debug_span!("write_file", filename = %object.input).entered();
    let _file_span = layout.args().common().trace_span_for_file(object.file_id);

    // Claiming each section's room advances a cursor, so it has to happen in order. Filling what
    // was claimed doesn't, and it is where the time goes - copying the bytes and applying the
    // relocations. An object built with one codegen unit is a single input holding most of the
    // program, so without this the whole of it is one thread's work while the rest wait.
    let mut claimed = Vec::new();

    for (i, slot) in object.sections.iter().enumerate() {
        match slot {
            SectionSlot::Loaded(sec) => {
                let section_index = object::SectionIndex(i);
                let allocation = take_section_buffer(object, layout, *sec, section_index, buffers)?;

                claimed.push((section_index, *sec, allocation));
            }

            // `__compact_unwind` is frame data too, but it's consumed rather than copied - it
            // becomes `__unwind_info`, which is written once for the whole image.
            SectionSlot::FrameData(section_index)
                if object.object.section_name(*section_index)? == EH_FRAME_SECTION_NAME =>
            {
                write_eh_frame::<A>(object, *section_index, layout, buffers, fixup_sites)?;
            }

            _ => (),
        }
    }

    // The fixup sites every section produces are gathered and sorted by address later, so which
    // order they arrive in doesn't matter.
    let section_fixups = claimed
        .into_par_iter()
        .map(
            |(section_index, sec, allocation)| -> Result<Vec<FixupSite>> {
                let mut fixups = Vec::new();

                write_object_section::<A>(
                    object,
                    layout,
                    sec,
                    section_index,
                    allocation,
                    &mut fixups,
                )?;

                Ok(fixups)
            },
        )
        .collect::<Result<Vec<_>>>()?;

    for mut fixups in section_fixups {
        fixup_sites.append(&mut fixups);
    }

    write_thunks::<A>(object, buffers, layout)?;
    write_symbols(object, buffers, layout, symbol_writer)?;

    Ok(())
}

/// Narrows a relocation to the atom being written, moving its address from being relative to the
/// section it was recorded against to being relative to the atom.
///
/// Returns `None` for a relocation belonging to a different atom of the same section.
fn rebase_to_atom(
    mut relocation: RelocationInfo,
    span: &std::ops::Range<u64>,
) -> Option<RelocationInfo> {
    let address = u64::from(relocation.r_address);

    if !span.contains(&address) {
        return None;
    }

    relocation.r_address = (address - span.start) as u32;
    Some(relocation)
}

fn write_object_section<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout<'data>,
    _section: Section,
    section_index: object::SectionIndex,
    allocation: &mut [u8],
    fixup_sites: &mut Vec<FixupSite>,
) -> Result {
    let out = fill_section_buffer(object_layout, section_index, allocation)?;

    let section_address = object_layout.section_resolutions[section_index.0]
        .address()
        .context("Attempted to apply relocations to a section that we didn't load")?;

    let section_part_id =
        object_layout.section_part_id(section_index, &layout.symbol_db.section_part_ids);

    // Relocations are recorded against the whole section this atom was cut from, and their
    // addresses are relative to it. Only the ones landing inside the atom apply here, and those
    // need rebasing onto its start before they can name a byte of it.
    let span = object_layout.object.atom_span_in_parent(section_index)?;
    let relocations = object_layout.relocations(section_index)?.relocations;
    let mut index = 0;

    while index < relocations.len() {
        let rel = rebase_to_atom(relocations[index].info(LE), &span);

        let Some(rel) = rel else {
            index += 1;
            continue;
        };

        // A subtractor is only half a relocation: it's always immediately followed by an unsigned
        // one at the same address, and together they mean "the distance between these two symbols".
        // They have to be applied as a unit, both because neither value alone is what goes in the
        // slot and because the result is a difference - it doesn't move when dyld slides the image,
        // so it must not get the rebase that `apply_relocation` gives a lone pointer-sized
        // absolute.
        if rel.r_type == object::macho::ARM64_RELOC_SUBTRACTOR {
            let minuend = relocations
                .get(index + 1)
                .and_then(|next| rebase_to_atom(next.info(LE), &span))
                .filter(|next| {
                    next.r_type == object::macho::ARM64_RELOC_UNSIGNED
                        && next.r_address == rel.r_address
                })
                .with_context(|| {
                    format!(
                        "ARM64_RELOC_SUBTRACTOR at offset {:#x} of `{}` is not followed by a \
                         matching ARM64_RELOC_UNSIGNED",
                        rel.r_address,
                        object_layout.object.section_display_name(section_index)
                    )
                })?;

            apply_subtractor_pair(object_layout, rel, minuend, layout, out)?;
            index += 2;
            continue;
        }

        // Also not a relocation of its own: it carries an addend for the relocation that follows
        // it, in the field that would otherwise name a symbol. The assembler uses it to reach an
        // offset inside a section that has no symbol at that point, so the target is typically a
        // section anchor plus a displacement.
        let (addend, relocation) = if rel.r_type == object::macho::ARM64_RELOC_ADDEND {
            let value = u64::from(rel.r_symbolnum);
            index += 1;

            let Some(next) = relocations
                .get(index)
                .and_then(|next| rebase_to_atom(next.info(LE), &span))
            else {
                bail!(
                    "ARM64_RELOC_ADDEND at offset {:#x} of `{}` is the last relocation",
                    rel.r_address,
                    object_layout.object.section_display_name(section_index)
                );
            };

            ensure!(
                next.r_address == rel.r_address,
                "ARM64_RELOC_ADDEND at offset {:#x} of `{}` is not followed by a relocation at the \
                 same address",
                rel.r_address,
                object_layout.object.section_display_name(section_index)
            );

            // The addend belongs to the relocation that follows it, and that is the one naming
            // the byte to patch, so it's the one to apply.
            (value, next)
        } else {
            (0, rel)
        };

        apply_relocation::<A>(
            object_layout,
            section_address,
            section_part_id,
            relocation,
            addend,
            layout,
            out,
            fixup_sites,
        )?;
        index += 1;
    }

    Ok(())
}

/// Reads the addend that the compiler left in the storage the relocation applies to.
///
/// Signed, and narrower than a `u64` for the smaller forms, so it's sign-extended - a negative
/// displacement is perfectly ordinary and must not come back as a huge positive one.
fn read_implicit_addend(out: &[u8], offset: usize, size: usize) -> Result<u64> {
    let slot = out
        .get(offset..offset + size)
        .with_context(|| format!("Relocation at offset {offset:#x} is outside its section"))?;

    Ok(match size {
        1 => i64::from(slot[0] as i8) as u64,
        2 => i64::from(i16::from_le_bytes(slot.try_into()?)) as u64,
        4 => i64::from(i32::from_le_bytes(slot.try_into()?)) as u64,
        8 => u64::from_le_bytes(slot.try_into()?),
        other => bail!("Unsupported relocation size: {other}"),
    })
}

/// Applies an `ARM64_RELOC_SUBTRACTOR` / `ARM64_RELOC_UNSIGNED` pair, which stores the distance
/// from one symbol to another.
///
/// `__eh_frame` is what needs this: an FDE records where its function starts as a delta from the
/// field holding it, and the assembler expresses that as "this function, minus the anchor symbol at
/// the start of the section", with the field's own offset within the section as the addend already
/// sitting in the slot.
fn apply_subtractor_pair(
    object_layout: &ObjectLayout<'_, MachO>,
    subtractor: RelocationInfo,
    minuend: RelocationInfo,
    layout: &MachOLayout<'_>,
    out: &mut [u8],
) -> Result {
    let offset = minuend.r_address as usize;
    let size = 1_usize << minuend.r_length;

    let (subtractor_resolution, _, subtractor_symbol) =
        get_resolution(subtractor, object_layout, layout)?;
    let (minuend_resolution, _, minuend_symbol) = get_resolution(minuend, object_layout, layout)?;

    let slot = out
        .get_mut(offset..offset + size)
        .with_context(|| format!("Subtractor pair at offset {offset:#x} is outside its section"))?;

    // Whatever the assembler left in the slot is the addend, signed, and narrower than 8 bytes for
    // the 4-byte form - so sign-extend it rather than zero-extend, or a negative addend (which is
    // the normal case here, since it cancels the field's offset) comes out enormous.
    let addend = match size {
        4 => i64::from(i32::from_le_bytes(slot[..4].try_into()?)),
        8 => i64::from_le_bytes(slot[..8].try_into()?),
        other => bail!("Unsupported subtractor pair size: {other}"),
    };

    let value = minuend_resolution
        .raw_value
        .wrapping_sub(subtractor_resolution.raw_value)
        .wrapping_add(addend as u64);

    tracing::trace!(
        minuend = %layout.symbol_db.symbol_name_for_display(minuend_symbol),
        subtractor = %layout.symbol_db.symbol_name_for_display(subtractor_symbol),
        value,
        "subtractor pair applied"
    );

    slot.copy_from_slice(&value.to_le_bytes()[..size]);

    Ok(())
}

#[inline(always)]
fn apply_relocation<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    section_address: u64,
    section_part_id: crate::part_id::PartId,
    rel: RelocationInfo,
    addend: u64,
    layout: &MachOLayout<'data>,
    out: &mut [u8],
    fixup_sites: &mut Vec<FixupSite>,
) -> Result {
    let offset_in_section = u64::from(rel.r_address);
    let place = section_address + offset_in_section;

    #[cfg(feature = "relocation-spans")]
    let _span = tracing::trace_span!(
        "relocation",
        address = place,
        address_hex = %HexU64::new(place)
    )
    .entered();

    let rel_info = A::relocation_from_raw(rel)?;
    let (mut resolution, _symbol_index, local_symbol_id) =
        get_resolution(rel, object_layout, layout)?;
    let flags = layout.flags_for_symbol(local_symbol_id);

    // Mach-O has no relocation field to put an addend in, the way ELF's `Rela` does. For a plain
    // pointer-sized slot the addend is simply already sitting in the slot, so `&array[2]` reaches
    // us as "the address of `array`" plus an 8 the compiler wrote into the storage - and dropping
    // it silently produces a pointer to the wrong element. The addressing relocations can't do that
    // (their storage holds an instruction), which is what `ARM64_RELOC_ADDEND` exists for.
    let addend = if rel_info.kind == RelocationKind::Absolute
        && let RelocationSize::ByteSize(size) = rel_info.size
    {
        addend.wrapping_add(read_implicit_addend(out, offset_in_section as usize, size)?)
    } else {
        addend
    };

    if addend != 0 {
        // `raw_value` holds the address of the symbol's `__got` slot when it has one, and an addend
        // is meant to displace the symbol, not the slot - so the two can't be combined.
        ensure!(
            !matches!(
                rel_info.kind,
                RelocationKind::Got | RelocationKind::GotRelative
            ),
            "Addend applied to an indirect relocation against {}",
            layout.symbol_debug(local_symbol_id)
        );

        // An imported symbol's address isn't known until dyld binds it, so the displacement can't
        // be folded into a value here - it has to travel to dyld in the bind itself, which is what
        // the encoding's `addend` field is for. It's applied below, once we know the slot really is
        // a bind; adding it to `raw_value` here would corrupt the ordinal.
        if !flags.is_dynamic() {
            resolution.raw_value = resolution.raw_value.wrapping_add(addend);
        }
    }

    let is_got_relocation = matches!(
        rel_info.kind,
        RelocationKind::Got | RelocationKind::GotRelative
    );

    // Layout gives a `__got` slot to symbols whose address isn't known until dyld binds them, and
    // to any symbol whose slot address is itself stored somewhere. A GOT-style relocation against
    // anything else has to be turned into a direct reference, which means rewriting the instruction
    // as well as computing a different value for it. Keying this off the resolution rather than off
    // the flags means the writer can't disagree with whatever layout decided
    // (`macho::Indirection`).
    if is_got_relocation && resolution.format_specific.got_address.is_none() {
        A::relax_got_load(rel, &mut out[offset_in_section as usize..]).with_context(|| {
            format!(
                "Failed to relax {} against {}",
                A::rel_type_to_string(rel),
                layout.symbol_debug(local_symbol_id)
            )
        })?;
    }

    // A GOT relocation names the slot, not the symbol. For an import the two coincide, because an
    // import has no address of its own to put in `raw_value`; for a locally defined symbol they
    // don't, and using `raw_value` would quietly address the symbol itself.
    let target = match resolution.format_specific.got_address {
        Some(got_address) if is_got_relocation => got_address.get(),
        _ => resolution.raw_value,
    };

    let mask = get_page_mask(rel_info.mask);
    let mut value = match rel_info.kind {
        RelocationKind::Absolute | RelocationKind::AbsoluteLowPart | RelocationKind::Got => {
            target.bitand(mask.symbol_plus_addend)
        }
        RelocationKind::Relative | RelocationKind::GotRelative => target
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        other => bail!(
            "Unsupported relocation kind {other:?} applying {} to {}",
            A::rel_type_to_string(rel),
            layout.symbol_debug(local_symbol_id)
        ),
    };

    // A branch that can't reach its target goes to an island instead, which does the long jump.
    // Recomputed rather than adjusted, because the displacement is to the island, not the target.
    if let Some(thunk_address) = thunk_address_for_relocation::<A>(
        object_layout,
        section_part_id,
        layout,
        rel_info,
        local_symbol_id,
        value,
    )? {
        value = thunk_address
            .wrapping_add(rel_info.bias)
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place));
    }

    // What a pointer-sized absolute slot needs depends on what it points at. Anything else - a
    // smaller reference, or an N_ABS symbol, which names a fixed value rather than a place in the
    // image - is written as-is and left alone.
    if rel_info.kind == RelocationKind::Absolute
        && rel_info.size == RelocationSize::ByteSize(size_of::<u64>())
        && !flags.is_absolute()
    {
        // Reported here rather than where the chain is threaded, because this is where there is
        // still something to name: a chain can only step in multiples of its stride, so a slot off
        // that grid can't be on one, and by then all that is left of it is an address.
        ensure!(
            place.is_multiple_of(CHAINED_PTR_NEXT_STRIDE),
            "Slot at {place:#x} for {} in section `{}` of `{}` needs a fixup but isn't aligned to \
             the {CHAINED_PTR_NEXT_STRIDE}-byte chain stride",
            layout.symbol_debug(local_symbol_id),
            layout
                .output_sections
                .display_name(section_part_id.output_section_id()),
            object_layout.input,
        );

        if flags.is_thread_local() {
            // The last word of a `tlv_descriptor` holds where the variable sits within the
            // thread-local block, not where the template copy of it sits in the image. dyld adds
            // that offset to the block it allocates per thread, so this must be a plain number:
            // sliding it, as a rebase would, gives every access a wild pointer.
            value = value.wrapping_sub(thread_local_block_address(layout));
        } else if flags.is_dynamic() {
            // The slot names a symbol in another image, so dyld has to bind it. Encode the import
            // ordinal the same way `write_got_entries` does for `__got`; the difference is only
            // where the slot lives. `__tlv_bootstrap`, which every `tlv_descriptor` starts with,
            // reaches us this way.
            // A displacement from an imported symbol travels in the bind's own addend field, since
            // the address it displaces isn't known until dyld resolves it. C++ needs this: a class
            // with a base stores `&vtable + 0x10` to skip the two words of header that precede the
            // first virtual function.
            ensure!(
                addend <= CHAINED_PTR_BIND_MAX_ADDEND,
                "Addend of {addend:#x} against imported symbol {} does not fit in the {} bits a \
                 chained bind has for it",
                layout.symbol_debug(local_symbol_id),
                CHAINED_PTR_BIND_ADDEND_BITS,
            );

            value = CHAINED_PTR_BIND
                | (addend << CHAINED_PTR_BIND_ADDEND_SHIFT)
                | import_ordinal(layout, local_symbol_id)?;
            fixup_sites.push(FixupSite {
                address: place,
                is_bind: true,
            });
        } else if value != 0 {
            // An address inside this image, written as the link-time address, which is only
            // correct if dyld happens to load us where we asked. Record a rebase so it gets the
            // load bias added. A resolution of zero is an undefined weak reference and stays null.
            fixup_sites.push(FixupSite {
                address: place,
                is_bind: false,
            });
        }
    }

    tracing::trace!(
            %flags,
            ?rel_info.kind,
            %rel_info.size,
            value,
            value_hex = %HexU64::new(value),
            symbol_name = %layout.symbol_db.symbol_name_for_display(local_symbol_id),
            "relocation applied");

    rel_info
        .write_to_buffer(value, &mut out[offset_in_section as usize..])
        .with_context(|| {
            format!(
                "Failed to apply relocation {} to {}",
                A::rel_type_to_string(rel),
                layout.symbol_debug(local_symbol_id)
            )
        })?;

    Ok(())
}

/// Writes `__TEXT,__unwind_info`, the table libunwind searches to find out how to unwind out of a
/// function.
///
/// The input describes each function separately, in whatever order the objects happened to be in.
/// The output is a two-level index sorted by address: a first level naming the page each range of
/// functions is on, and a second level holding the functions themselves. Anything that needs more
/// than the compact encoding can express - a personality routine, a landing pad - is named
/// indirectly, through arrays the entries hold indices into.
fn write_unwind_info(layout: &MachOLayout<'_>, out: &mut [u8]) -> Result {
    if out.is_empty() {
        return Ok(());
    }

    let entries = collect_unwind_entries(layout)?;
    if entries.is_empty() {
        return Ok(());
    }

    let image_base = layout
        .section_layouts
        .get(output_section_id::FILE_HEADER)
        .mem_offset;

    // An entry names its personality by a two-bit index, so there is room for three across the
    // whole image. In practice a program has one per language runtime it links against.
    let mut personalities: Vec<u64> = Vec::new();
    for entry in &entries {
        if let Some(address) = entry.personality_got_address
            && !personalities.contains(&address)
        {
            ensure!(
                (personalities.len() as u64) < UNWIND_INFO_MAX_PERSONALITIES,
                "More than {UNWIND_INFO_MAX_PERSONALITIES} personality routines, which is more \
                 than a compact unwind encoding can name"
            );
            personalities.push(address);
        }
    }

    // The encoding an entry actually carries, personality index folded in. Everything downstream
    // compares and shares these, so they are resolved once.
    let encodings = entries
        .iter()
        .map(|entry| {
            let personality_index = entry
                .personality_got_address
                .and_then(|address| personalities.iter().position(|p| *p == address))
                // The index is stored one-based, so that zero can mean "no personality".
                .map_or(0, |index| index as u32 + 1);

            entry.encoding | (personality_index << UNWIND_PERSONALITY_SHIFT)
        })
        .collect_vec();

    let common_encodings = common_encodings(&encodings);

    let pages = (entries.len() as u64).div_ceil(UNWIND_INFO_PAGE_CAPACITY);
    let lsda_count = entries.iter().filter(|e| e.lsda_address.is_some()).count() as u64;

    // Laid out in the order the header's offsets have to name: the personalities, then the index
    // over the pages, then the landing pads, then the pages themselves.
    let common_encodings_offset = UNWIND_INFO_HEADER_SIZE;
    let personality_offset =
        common_encodings_offset + common_encodings.len() as u64 * size_of::<u32>() as u64;
    let index_offset = personality_offset + personalities.len() as u64 * size_of::<u32>() as u64;
    // One index entry per page, plus a sentinel that marks where the last function ends.
    let lsda_offset = index_offset + (pages + 1) * UNWIND_INFO_INDEX_ENTRY_SIZE;
    let first_page_offset = lsda_offset + lsda_count * UNWIND_INFO_LSDA_ENTRY_SIZE;

    let mut writer = UnwindInfoWriter { out, offset: 0 };

    writer.u32(UNWIND_SECTION_VERSION)?;
    writer.u32(common_encodings_offset as u32)?;
    writer.u32(common_encodings.len() as u32)?;
    writer.u32(personality_offset as u32)?;
    writer.u32(personalities.len() as u32)?;
    writer.u32(index_offset as u32)?;
    writer.u32((pages + 1) as u32)?;

    // The encodings worth sharing across the whole image. A compressed entry names one of these by
    // index rather than carrying it, which is where the format's saving comes from.
    for encoding in &common_encodings {
        writer.u32(*encoding)?;
    }

    for personality in &personalities {
        writer.u32(image_relative(*personality, image_base)?)?;
    }

    // How each page will be written has to be settled before the index, which names where each one
    // begins and so depends on how large the ones before it are.
    let page_layouts = entries
        .chunks(UNWIND_INFO_PAGE_CAPACITY as usize)
        .map(|page| plan_page(page, &encodings, &common_encodings, &entries, image_base))
        .collect::<Result<Vec<_>>>()?;

    // First level: one entry per page, then the sentinel.
    let mut page_offset = first_page_offset;
    let mut lsda_cursor = lsda_offset;

    for (page, layout) in entries
        .chunks(UNWIND_INFO_PAGE_CAPACITY as usize)
        .zip(&page_layouts)
    {
        writer.u32(image_relative(page[0].function_address, image_base)?)?;
        writer.u32(page_offset as u32)?;
        writer.u32(lsda_cursor as u32)?;

        page_offset += layout.size(page.len());
        lsda_cursor += page.iter().filter(|e| e.lsda_address.is_some()).count() as u64
            * UNWIND_INFO_LSDA_ENTRY_SIZE;
    }

    // The sentinel's address is one past the last function, so that a search for an address beyond
    // everything we know about lands here and finds no page.
    let last = entries.last().expect("entries is not empty");
    writer.u32(image_relative(
        last.function_address + u64::from(last.function_length),
        image_base,
    )?)?;
    writer.u32(0)?;
    writer.u32(lsda_cursor as u32)?;

    // The landing pads, in the same order as the functions that have them.
    for entry in &entries {
        if let Some(lsda) = entry.lsda_address {
            writer.u32(image_relative(entry.function_address, image_base)?)?;
            writer.u32(image_relative(lsda, image_base)?)?;
        }
    }

    // Second level: the functions themselves, one page at a time.
    let mut first = 0;

    for (page, layout) in entries
        .chunks(UNWIND_INFO_PAGE_CAPACITY as usize)
        .zip(&page_layouts)
    {
        let page_encodings = &encodings[first..first + page.len()];

        match layout {
            PageLayout::Compressed { local_encodings } => {
                let entries_offset =
                    UNWIND_INFO_COMPRESSED_PAGE_HEADER_SIZE + local_encodings.len() as u64 * 4;

                writer.u32(UNWIND_SECOND_LEVEL_COMPRESSED)?;
                writer.u16(entries_offset as u16)?;
                writer.u16(page.len() as u16)?;
                writer.u16(UNWIND_INFO_COMPRESSED_PAGE_HEADER_SIZE as u16)?;
                writer.u16(local_encodings.len() as u16)?;

                // The encodings this page uses that aren't shared image-wide. They are numbered
                // after the shared ones, which is how one index reaches either.
                for encoding in local_encodings {
                    writer.u32(*encoding)?;
                }

                let page_base = image_relative(page[0].function_address, image_base)?;

                for (entry, encoding) in page.iter().zip(page_encodings) {
                    let index = encoding_index(*encoding, &common_encodings, local_encodings)
                        .context(
                            "An encoding went missing between planning a page and writing it",
                        )?;

                    let offset = image_relative(entry.function_address, image_base)? - page_base;

                    writer.u32((index << UNWIND_INFO_COMPRESSED_ENCODING_SHIFT) | offset)?;
                }
            }

            PageLayout::Regular => {
                writer.u32(UNWIND_SECOND_LEVEL_REGULAR)?;
                writer.u16(UNWIND_INFO_PAGE_HEADER_SIZE as u16)?;
                writer.u16(page.len() as u16)?;

                for (entry, encoding) in page.iter().zip(page_encodings) {
                    writer.u32(image_relative(entry.function_address, image_base)?)?;
                    writer.u32(*encoding)?;
                }
            }
        }

        first += page.len();
    }

    Ok(())
}

/// How one second-level page will be written.
enum PageLayout {
    /// Entries name their encoding by index and their function by an offset from the page's first,
    /// so each costs one word instead of two.
    Compressed {
        /// The encodings this page uses that aren't shared image-wide, in index order.
        local_encodings: Vec<u32>,
    },

    /// Every entry carries its own encoding and its own full offset. Twice the size, but it can say
    /// things the compressed form can't.
    Regular,
}

impl PageLayout {
    fn size(&self, entry_count: usize) -> u64 {
        match self {
            PageLayout::Compressed { local_encodings } => {
                UNWIND_INFO_COMPRESSED_PAGE_HEADER_SIZE
                    + local_encodings.len() as u64 * size_of::<u32>() as u64
                    + entry_count as u64 * UNWIND_INFO_COMPRESSED_ENTRY_SIZE
            }
            PageLayout::Regular => {
                UNWIND_INFO_PAGE_HEADER_SIZE + entry_count as u64 * UNWIND_INFO_ENTRY_SIZE
            }
        }
    }
}

/// Decides how a page will be written.
///
/// Compressed unless it can't be: an entry holds the distance from the page's first function in 24
/// bits, and names its encoding with 8, so a page covering more than 16 MiB of code or wanting more
/// encodings than an index can reach has to be written the long way instead. Both forms fit within
/// what was reserved, so the choice is free.
fn plan_page(
    page: &[UnwindEntry],
    encodings: &[u32],
    common_encodings: &[u32],
    all_entries: &[UnwindEntry],
    image_base: u64,
) -> Result<PageLayout> {
    let first = page_start_index(page, all_entries);
    let page_encodings = &encodings[first..first + page.len()];

    let mut local_encodings = Vec::new();

    for encoding in page_encodings {
        if !common_encodings.contains(encoding) && !local_encodings.contains(encoding) {
            local_encodings.push(*encoding);
        }
    }

    if common_encodings.len() + local_encodings.len() > UNWIND_INFO_MAX_ENCODINGS_PER_PAGE {
        return Ok(PageLayout::Regular);
    }

    let page_base = image_relative(page[0].function_address, image_base)?;
    let last = page.last().expect("a page always has an entry");

    if image_relative(last.function_address, image_base)? - page_base
        > UNWIND_INFO_COMPRESSED_FUNCTION_OFFSET_MASK
    {
        return Ok(PageLayout::Regular);
    }

    Ok(PageLayout::Compressed { local_encodings })
}

/// Where a page's entries start within the whole run, found by pointer rather than tracked.
fn page_start_index(page: &[UnwindEntry], all_entries: &[UnwindEntry]) -> usize {
    (page.as_ptr() as usize - all_entries.as_ptr() as usize) / size_of::<UnwindEntry>()
}

/// The index an entry uses to name its encoding: shared ones first, then the page's own.
fn encoding_index(encoding: u32, common: &[u32], local: &[u32]) -> Option<u32> {
    if let Some(index) = common.iter().position(|e| *e == encoding) {
        return Some(index as u32);
    }

    local
        .iter()
        .position(|e| *e == encoding)
        .map(|index| (common.len() + index) as u32)
}

/// Picks the encodings worth sharing across the whole image.
///
/// An encoding used by many functions costs four bytes once here instead of four in every page that
/// mentions it. There is room for a limited number, so the most used win.
fn common_encodings(encodings: &[u32]) -> Vec<u32> {
    let mut counts: HashMap<u32, usize> = HashMap::new();

    for encoding in encodings {
        *counts.entry(*encoding).or_default() += 1;
    }

    counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .sorted_unstable_by_key(|(encoding, count)| (std::cmp::Reverse(*count), *encoding))
        .take(UNWIND_INFO_MAX_COMMON_ENCODINGS)
        .map(|(encoding, _)| encoding)
        .collect()
}

/// Returns an address as an offset from the mach header, which is how `__unwind_info` names
/// everything - it has 32 bits per reference and the image can be loaded anywhere.
fn image_relative(address: u64, image_base: u64) -> Result<u32> {
    let offset = address
        .checked_sub(image_base)
        .with_context(|| format!("Address 0x{address:x} is before the image base"))?;

    u32::try_from(offset)
        .map_err(|_| error!("Address 0x{address:x} is more than 4GiB past the image base"))
}

/// Appends to `__unwind_info`, keeping track of how far in we are.
struct UnwindInfoWriter<'out> {
    out: &'out mut [u8],
    offset: usize,
}

impl UnwindInfoWriter<'_> {
    fn u32(&mut self, value: u32) -> Result {
        self.write(&value.to_le_bytes())
    }

    fn u16(&mut self, value: u16) -> Result {
        self.write(&value.to_le_bytes())
    }

    fn write(&mut self, bytes: &[u8]) -> Result {
        let end = self.offset + bytes.len();
        let slot = self
            .out
            .get_mut(self.offset..end)
            .ok_or_else(|| error!("Insufficient allocation for __unwind_info"))?;
        slot.copy_from_slice(bytes);
        self.offset = end;
        Ok(())
    }
}

/// One function's unwind information, gathered from an input `__LD,__compact_unwind` entry.
struct UnwindEntry {
    function_address: u64,
    function_length: u32,
    encoding: u32,
    /// Address of the GOT slot holding the personality routine, if the function has one. The table
    /// names personalities indirectly, which is why the slot rather than the routine is what
    /// matters here.
    personality_got_address: Option<u64>,
    lsda_address: Option<u64>,
}

/// Reads every input `__LD,__compact_unwind` section and returns one entry per function, ordered by
/// address, which is the order `__unwind_info` has to be searchable in.
fn collect_unwind_entries(layout: &MachOLayout<'_>) -> Result<Vec<UnwindEntry>> {
    verbose_timing_phase!("Collect unwind entries");

    // Objects don't depend on each other here - each one's entries are read from its own bytes -
    // so they're read in parallel and put in order afterwards. There is one entry per function in
    // the program, so on a large link this is the bulk of the work.
    let objects = layout
        .group_layouts
        .iter()
        .flat_map(|group| &group.files)
        .filter_map(|file| match file {
            FileLayout::Object(object) => Some(object),
            _ => None,
        })
        .collect_vec();

    let per_object = objects
        .into_par_iter()
        .map(|object| -> Result<Vec<UnwindEntry>> {
            let mut entries = Vec::new();

            for slot in &object.sections {
                let SectionSlot::FrameData(section_index) = slot else {
                    continue;
                };

                if object.object.section_name(*section_index)? == EH_FRAME_SECTION_NAME {
                    continue;
                }

                read_compact_unwind_section(object, *section_index, layout, &mut entries)
                    .with_context(|| format!("Failed to read __compact_unwind from {object}"))?;
            }

            Ok(entries)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut entries: Vec<UnwindEntry> = per_object.into_iter().flatten().collect();
    entries.par_sort_unstable_by_key(|entry| entry.function_address);

    Ok(entries)
}

fn read_compact_unwind_section(
    object: &ObjectLayout<'_, MachO>,
    section_index: object::SectionIndex,
    layout: &MachOLayout<'_>,
    entries: &mut Vec<UnwindEntry>,
) -> Result {
    let section = object.object.section(section_index)?;
    let data = object.object.raw_section_data(section)?;

    // An entry that can't be described compactly names a DWARF frame instead, by its offset within
    // `__eh_frame`. That offset is into *this object's* `__eh_frame`, and the output holds only the
    // frames whose functions survived, from every object at once - so the entry has to be told
    // where its frame ended up rather than shifted by any one amount.
    let eh_frame = eh_frame_output_offsets(object, layout)?;

    // A relocation names the target; the bytes it applies to hold the displacement from it. Both
    // are needed, and which field of which entry they belong to follows from the offset, so the
    // targets are gathered by offset first and the entries read from them afterwards.
    let mut targets = HashMap::new();

    // Where the entry's function sits in this object, which is a different question from where it
    // ends up and is only asked of the field at the start of an entry.
    let mut input_functions = HashMap::new();

    for relocation in object
        .object
        .relocations(section_index, &object.relocations)?
        .relocations
    {
        let info = relocation.info(LE);
        let offset = info.r_address as usize;

        let stored = data
            .get(offset..offset + size_of::<u64>())
            .map_or(0, |bytes| {
                u64::from_le_bytes(bytes.try_into().expect("slice is 8 bytes"))
            });

        if u64::from(info.r_address) % COMPACT_UNWIND_ENTRY_SIZE == 0 {
            let input_address = if info.r_extern {
                object
                    .object
                    .symbol(SymbolIndex(info.r_symbolnum as usize))?
                    .n_value
                    .get(LE)
            } else {
                stored
            };

            input_functions.insert(offset as u64, input_address);
        }

        let Some(address) = resolve_compact_unwind_target(object, layout, info, stored)? else {
            continue;
        };

        targets.insert(offset as u64, address);
    }

    for (index, entry) in data
        .as_chunks::<{ COMPACT_UNWIND_ENTRY_SIZE as usize }>()
        .0
        .iter()
        .enumerate()
    {
        let base = index as u64 * COMPACT_UNWIND_ENTRY_SIZE;

        // A function with no relocation naming it isn't one we're emitting - the entry describes
        // something that didn't make it into the output.
        let Some(&function_address) = targets.get(&base) else {
            continue;
        };

        let function_length = u32::from_le_bytes(entry[8..12].try_into()?);
        let mut encoding = u32::from_le_bytes(entry[12..16].try_into()?);

        // The entry defers to DWARF, and the field that says which frame to read is the linker's to
        // fill in: the assembler leaves it zero, because where the frame ends up isn't known until
        // every object's `__eh_frame` has been merged. The two are paired by the function they
        // describe, which is the only thing they agree on.
        if encoding & UNWIND_ARM64_MODE_MASK == UNWIND_ARM64_MODE_DWARF {
            let input_function = input_functions
                .get(&base)
                .copied()
                .context("A __compact_unwind entry defers to DWARF but names no function")?;

            // Both this entry and the frame it defers to are kept for the same reason - the
            // function survived - so a missing frame means the two disagreed about that, and the
            // entry would otherwise send the unwinder to whatever now sits at that offset.
            let frame_offset = eh_frame
                .as_ref()
                .and_then(|eh_frame| eh_frame.fde_offset(input_function))
                .with_context(|| {
                    format!(
                        "A __compact_unwind entry defers to the DWARF frame for the function at \
                         {input_function:#x}, which isn't in the output"
                    )
                })?;

            ensure!(
                frame_offset <= UNWIND_ARM64_DWARF_SECTION_OFFSET,
                "__eh_frame is too large for a DWARF unwind entry to reach into"
            );

            encoding = (encoding & !UNWIND_ARM64_DWARF_SECTION_OFFSET) | frame_offset;
        }

        let personality_got_address = targets
            .get(&(base + COMPACT_UNWIND_PERSONALITY_OFFSET))
            .copied();
        let lsda_address = targets.get(&(base + COMPACT_UNWIND_LSDA_OFFSET)).copied();

        entries.push(UnwindEntry {
            function_address,
            function_length,
            encoding,
            personality_got_address,
            lsda_address,
        });
    }

    Ok(())
}

/// Which of an object's `__eh_frame` records are being emitted, and where each one lands.
///
/// Offsets are relative to the start of this object's block, which is where its records go as a
/// run; `base` says how far that block sits into the output section.
struct EhFramePlan {
    base: u32,

    /// The output offset of each record kept, by its input offset. Records that aren't being
    /// emitted are absent.
    output_offsets: HashMap<u32, u32>,

    /// Where each emitted FDE landed, by the address its function has in this object. A
    /// `__compact_unwind` entry that defers to DWARF names its function the same way, and that is
    /// the only thing the two have in common - the entry carries no usable offset of its own.
    fde_by_function: HashMap<u64, u32>,

    /// What the object contributes, which is what layout was asked to allocate for it.
    total: u32,
}

impl EhFramePlan {
    /// Returns where the FDE for a function landed in the output section.
    fn fde_offset(&self, function_input_address: u64) -> Option<u32> {
        Some(self.base + self.fde_by_function.get(&function_input_address)?)
    }
}

/// Decides what this object contributes to `__eh_frame`.
///
/// This is the writing half of the bargain layout struck: an FDE is emitted exactly when the
/// function it describes is, which is the same question layout asked when it sized the section, and
/// the CIEs come along if any FDE did. Both halves walk the records the same way and in the same
/// order, so the two agree on the total without having to pass it between them.
fn eh_frame_plan(
    object: &ObjectLayout<'_, MachO>,
    section_index: object::SectionIndex,
    layout: &MachOLayout<'_>,
) -> Result<EhFramePlan> {
    let data = object
        .object
        .raw_section_data(object.object.section(section_index)?)?;

    let records = eh_frame_records(data)?;

    let relocations = object
        .object
        .relocations(section_index, &object.relocations)?
        .relocations;

    let by_record = relocations_by_record(&records, relocations);

    let mut functions = vec![None; records.len()];
    let mut any_fde = false;

    for (index, (record, bucket)) in records.iter().zip(&by_record).enumerate() {
        if record.cie_offset.is_none() {
            continue;
        }

        functions[index] = live_fde_function(object, record, bucket, relocations)?;
        any_fde |= functions[index].is_some();
    }

    let mut output_offsets = HashMap::new();
    let mut fde_by_function = HashMap::new();
    let mut total = 0;

    for (index, record) in records.iter().enumerate() {
        // A CIE is kept for the object rather than for any one FDE: they share it, it's small, and
        // an FDE without the CIE it names is unreadable. An object that lost all its FDEs keeps
        // none of them.
        match functions[index] {
            Some(function) => {
                fde_by_function.insert(function, total);
            }
            None if record.cie_offset.is_none() && any_fde => {}
            None => continue,
        }

        output_offsets.insert(record.offset, total);
        total += record.size;
    }

    let base = if total == 0 {
        0
    } else {
        let address = object
            .section_resolutions
            .get(section_index.0)
            .and_then(|resolution| resolution.address())
            .context("__eh_frame content to emit, but layout gave it no address")?;

        let section_start = layout
            .section_layouts
            .get(output_section_id::MACHO_EH_FRAME)
            .mem_offset;

        u32::try_from(address.saturating_sub(section_start))
            .map_err(|_| error!("__eh_frame is more than 4GiB long"))?
    };

    Ok(EhFramePlan {
        base,
        output_offsets,
        fde_by_function,
        total,
    })
}

/// Returns this object's `__eh_frame` plan, or `None` if it has no such section.
fn eh_frame_output_offsets(
    object: &ObjectLayout<'_, MachO>,
    layout: &MachOLayout<'_>,
) -> Result<Option<EhFramePlan>> {
    for slot in &object.sections {
        let SectionSlot::FrameData(section_index) = slot else {
            continue;
        };

        if object.object.section_name(*section_index)? == EH_FRAME_SECTION_NAME {
            return Ok(Some(eh_frame_plan(object, *section_index, layout)?));
        }
    }

    Ok(None)
}

/// Returns the address the function an FDE describes has in this object, if it's in the output.
///
/// The address is in the object's own numbering rather than the image's, because it is only used to
/// pair the FDE with the `__compact_unwind` entry for the same function, and that entry names it
/// the same way. An empty section is the odd case: it can be loaded and still have no code in it,
/// and layout only hangs unwind data off sections that turned out to be non-empty, so an FDE for
/// one was never paid for.
fn live_fde_function(
    object: &ObjectLayout<'_, MachO>,
    record: &EhFrameRecord,
    bucket: &[u32],
    relocations: &[MachORelocation],
) -> Result<Option<u64>> {
    let pc_begin = record.offset + FDE_PC_BEGIN_OFFSET;

    let Some(info) = bucket
        .iter()
        .map(|&index| relocations[index as usize].info(LE))
        .find(|info| {
            info.r_address == pc_begin && info.r_type == object::macho::ARM64_RELOC_UNSIGNED
        })
        .filter(|info| info.r_extern)
    else {
        return Ok(None);
    };

    let symbol_index = SymbolIndex(info.r_symbolnum as usize);
    let symbol = object.object.symbol(symbol_index)?;

    let Some(function_section) = object.object.symbol_section(symbol, symbol_index)? else {
        return Ok(None);
    };

    let is_live = object
        .section_resolutions
        .get(function_section.0)
        .and_then(|resolution| resolution.address())
        .is_some()
        && object.object.section(function_section)?.size.get(LE) != 0;

    Ok(is_live.then(|| symbol.n_value.get(LE)))
}

/// Applies the relocations of one `__eh_frame` record that has been copied into the output.
///
/// `record_out` is the record's own bytes in the output, so relocation addresses are rebased onto
/// its start and everything is measured from where it now sits.
#[expect(
    clippy::too_many_arguments,
    reason = "each is a distinct piece of context"
)]
fn apply_eh_frame_relocations<'data, A: Arch<Platform = MachO>>(
    object: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout<'data>,
    record: &EhFrameRecord,
    output_offset: u32,
    base_address: u64,
    section_index: object::SectionIndex,
    bucket: &[u32],
    relocations: &[MachORelocation],
    record_out: &mut [u8],
    fixup_sites: &mut Vec<FixupSite>,
) -> Result {
    let span = u64::from(record.offset)..u64::from(record.offset + record.size);
    let record_address = base_address + u64::from(output_offset);

    // How far the record moved. Every field an FDE stores as a distance from itself was written
    // against the input position, so each one owes this much.
    let moved = i64::from(record.offset) - i64::from(output_offset);

    let mut index = 0;

    while index < bucket.len() {
        let Some(rel) = rebase_to_atom(relocations[bucket[index] as usize].info(LE), &span) else {
            index += 1;
            continue;
        };

        if rel.r_type == object::macho::ARM64_RELOC_SUBTRACTOR {
            let minuend = bucket
                .get(index + 1)
                .and_then(|&next| rebase_to_atom(relocations[next as usize].info(LE), &span))
                .filter(|next| {
                    next.r_type == object::macho::ARM64_RELOC_UNSIGNED
                        && next.r_address == rel.r_address
                })
                .with_context(|| {
                    format!(
                        "ARM64_RELOC_SUBTRACTOR at offset {:#x} of `{}` is not followed by a \
                         matching ARM64_RELOC_UNSIGNED",
                        rel.r_address,
                        object.object.section_display_name(section_index)
                    )
                })?;

            // Anything in `__eh_frame` measured from a symbol elsewhere would have to be corrected
            // by however far that other section moved, which is not something the record knows.
            // Nothing emits such a thing: the assembler anchors these to `__eh_frame` itself.
            let subtractor_index = SymbolIndex(rel.r_symbolnum as usize);
            let is_anchored_here = rel.r_extern
                && object
                    .object
                    .symbol_section(object.object.symbol(subtractor_index)?, subtractor_index)?
                    == Some(section_index);

            ensure!(
                is_anchored_here,
                "ARM64_RELOC_SUBTRACTOR at offset {:#x} of `{}` is measured from outside \
                 __eh_frame",
                rel.r_address,
                object.object.section_display_name(section_index)
            );

            shift_addend(record_out, minuend, moved)?;

            apply_subtractor_pair(object, rel, minuend, layout, record_out)?;
            index += 2;
            continue;
        }

        ensure!(
            rel.r_type != object::macho::ARM64_RELOC_ADDEND,
            "ARM64_RELOC_ADDEND at offset {:#x} of `{}` is not something we expect in frame data",
            rel.r_address,
            object.object.section_display_name(section_index)
        );

        apply_relocation::<A>(
            object,
            record_address,
            EH_FRAME_PART_ID,
            rel,
            0,
            layout,
            record_out,
            fixup_sites,
        )?;

        index += 1;
    }

    Ok(())
}

/// Adds `delta` to the addend a relocation left in its slot.
fn shift_addend(out: &mut [u8], relocation: RelocationInfo, delta: i64) -> Result {
    if delta == 0 {
        return Ok(());
    }

    let offset = relocation.r_address as usize;
    let size = 1_usize << relocation.r_length;

    let slot = out.get_mut(offset..offset + size).with_context(|| {
        format!("Frame data addend at offset {offset:#x} is outside its record")
    })?;

    match size {
        4 => {
            let value = i32::from_le_bytes(slot.try_into()?)
                .wrapping_add(i32::try_from(delta).context("Frame data moved more than 2GiB")?);
            slot.copy_from_slice(&value.to_le_bytes());
        }
        8 => {
            let value = i64::from_le_bytes(slot.try_into()?).wrapping_add(delta);
            slot.copy_from_slice(&value.to_le_bytes());
        }
        other => bail!("Unsupported frame data relocation size: {other}"),
    }

    Ok(())
}

/// Copies this object's surviving `__eh_frame` records into the output.
///
/// The records go in input order, so what changes is only that some are missing: an FDE's back
/// reference to its CIE has to be re-measured, and every field that was stored as a distance from
/// where it sits has to be told where it sits now.
fn write_eh_frame<'data, A: Arch<Platform = MachO>>(
    object: &ObjectLayout<'data, MachO>,
    section_index: object::SectionIndex,
    layout: &MachOLayout<'data>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    fixup_sites: &mut Vec<FixupSite>,
) -> Result {
    let plan = eh_frame_plan(object, section_index, layout)?;

    if plan.total == 0 {
        return Ok(());
    }

    let data = object
        .object
        .raw_section_data(object.object.section(section_index)?)?;

    let records = eh_frame_records(data)?;

    let relocations = object
        .object
        .relocations(section_index, &object.relocations)?
        .relocations;

    let by_record = relocations_by_record(&records, relocations);

    let base_address = object.section_resolutions[section_index.0]
        .address()
        .context("__eh_frame content to emit, but layout gave it no address")?;

    let buffer = buffers.get_mut(EH_FRAME_PART_ID);

    ensure!(
        buffer.len() >= plan.total as usize,
        "Insufficient space allocated to section `__eh_frame`. Tried to take {} bytes, but only \
         {} remain",
        plan.total,
        buffer.len()
    );

    let out = buffer
        .split_off_mut(..plan.total as usize)
        .expect("just checked the length");

    for (record, bucket) in records.iter().zip(&by_record) {
        let Some(&output_offset) = plan.output_offsets.get(&record.offset) else {
            continue;
        };

        let input = record.offset as usize..record.offset as usize + record.size as usize;
        let record_out = &mut out[output_offset as usize..][..record.size as usize];
        record_out.copy_from_slice(&data[input]);

        // The distance back to the CIE is measured from the FDE, so dropping anything between the
        // two changes it. The CIE itself is always emitted when any FDE is, so a missing one means
        // the record walk disagreed with itself.
        if let Some(cie_offset) = record.cie_offset {
            let cie_output_offset = plan.output_offsets.get(&cie_offset).with_context(|| {
                format!(
                    "FDE at {:#x} names a CIE at {cie_offset:#x} that isn't being emitted",
                    record.offset
                )
            })?;

            let distance = output_offset + size_of::<u32>() as u32 - cie_output_offset;
            record_out[4..8].copy_from_slice(&distance.to_le_bytes());
        }

        apply_eh_frame_relocations::<A>(
            object,
            layout,
            record,
            output_offset,
            base_address,
            section_index,
            bucket,
            relocations,
            record_out,
            fixup_sites,
        )?;
    }

    Ok(())
}

/// Returns where a `__compact_unwind` relocation points, or `None` if its target wasn't emitted.
///
/// `stored` is what the relocation's own storage holds, which means different things depending on
/// what the relocation names - see below.
fn resolve_compact_unwind_target(
    object: &ObjectLayout<'_, MachO>,
    layout: &MachOLayout<'_>,
    relocation: RelocationInfo,
    stored: u64,
) -> Result<Option<u64>> {
    if relocation.r_extern {
        // Naming a symbol, so the stored value is a displacement from it.
        let local_symbol_id = object
            .symbol_id_range
            .input_to_id(SymbolIndex(relocation.r_symbolnum as usize));

        let Some(resolution) = layout.merged_symbol_resolution(local_symbol_id) else {
            return Ok(None);
        };

        // A personality is named by where its address is kept rather than by the address itself,
        // so for those the slot is the answer. `load_exception_frame_data` is what made sure the
        // slot exists.
        let address = resolution
            .format_specific
            .got_address
            .map_or(resolution.raw_value, |got_address| got_address.get());

        return Ok(Some(address.wrapping_add(stored)));
    }

    // Naming a section instead, numbered from one. Here the stored value is not a displacement but
    // the target's address in the object's own addressing, so what carries over to the output is
    // how far into the section it is - the object and the output place that section differently.
    let section_index = (relocation.r_symbolnum as usize)
        .checked_sub(1)
        .context("Section number zero in a __compact_unwind relocation")?;

    // The number names a section of the file, but the output places atoms, so the answer is the
    // atom holding that address - which is also what may have been dropped.
    let Some(atom_index) = object
        .object
        .atom_for_address(object::SectionIndex(section_index), stored)
    else {
        return Ok(None);
    };

    let Some(output_address) = object
        .section_resolutions
        .get(atom_index.0)
        .and_then(|resolution| resolution.address())
    else {
        return Ok(None);
    };

    let atom_address = object.object.section(atom_index)?.addr.get(LE);

    let offset_in_atom = stored.checked_sub(atom_address).with_context(|| {
        format!("__compact_unwind names 0x{stored:x}, which is before the atom holding it")
    })?;

    Ok(Some(output_address + offset_in_atom))
}

/// Claims this section's room in the output.
///
/// Buffers are handed out by advancing a cursor, so which section gets which bytes depends on the
/// order this is called in - it has to stay sequential. Filling what it hands back does not, which
/// is what lets an object's sections be written in parallel.
fn take_section_buffer<'buf, 'data>(
    object: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout,
    sec: Section,
    section_index: object::SectionIndex,
    buffers: &mut OutputSectionPartMap<&'buf mut [u8]>,
) -> Result<&'buf mut [u8]> {
    let part_id = object.section_part_id(section_index, &layout.symbol_db.section_part_ids);

    if !layout
        .output_sections
        .has_data_in_file(part_id.output_section_id())
    {
        return Ok(&mut []);
    }

    let section_buffer = buffers.get_mut(part_id);
    let allocation_size = sec.capacity(part_id, &layout.output_sections) as usize;

    if section_buffer.len() < allocation_size {
        bail!(
            "Insufficient space allocated to section `{}`. Tried to take {} bytes, but only {} remain",
            object.object.section_display_name(section_index),
            allocation_size,
            section_buffer.len()
        );
    }

    Ok(section_buffer.split_off_mut(..allocation_size).unwrap())
}

/// Copies a section's bytes into the room claimed for it, returning just the part that came from
/// the input - what follows is padding and is zeroed.
fn fill_section_buffer<'out, 'data>(
    object: &ObjectLayout<'data, MachO>,
    section_index: object::SectionIndex,
    allocation: &'out mut [u8],
) -> Result<&'out mut [u8]> {
    if allocation.is_empty() {
        return Ok(allocation);
    }

    let object_section = object.object.section(section_index)?;
    let section_size = object.object.section_size(object_section)?;
    let (out, padding) = allocation.split_at_mut(section_size as usize);

    object.object.copy_section_data(object_section, out)?;
    padding.fill(0);

    Ok(out)
}

fn get_resolution<'data>(
    rel: RelocationInfo,
    object_layout: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout,
) -> Result<(Resolution<MachO>, SymbolIndex, SymbolId)> {
    let symbol_index = SymbolIndex(rel.r_symbolnum as usize);
    let local_symbol_id = object_layout.symbol_id_range.input_to_id(symbol_index);
    let sym = object_layout.object.symbol(symbol_index)?;
    let section_index = object_layout.object.symbol_section(sym, symbol_index)?;
    let resolution = layout
        .merged_symbol_resolution(local_symbol_id)
        .or_else(|| {
            section_index.and_then(|section_index| {
                let section_address =
                    object_layout.section_resolutions[section_index.0].address()?;
                Some(Resolution {
                    raw_value: section_address,
                    dynamic_symbol_index: None,
                    flags: ValueFlags::empty(),
                    format_specific: Default::default(),
                })
            })
        })
        .with_context(|| {
            format!(
                "Missing resolution for: {}",
                layout.symbol_debug(local_symbol_id)
            )
        })?;
    Ok((resolution, symbol_index, local_symbol_id))
}

fn write_entry_point_command(layout: &MachOLayout, command: &mut EntryPointCommand) -> Result {
    // `entryoff` is relative to the address at which the mach header is loaded, since that's how
    // dyld computes the entry point (`mach_header_addr + entryoff`). `SegmentType::Text` is the
    // segment that contains the mach header and load commands, so its memory offset is the image
    // base. Note that this is deliberately not `SegmentType::TextSections`, which starts after the
    // load commands.
    let SegmentSectionsInfo { segment_size, .. } = get_segment_sections(layout, SegmentType::Text)
        .ok_or_else(|| error!("Text segment is mandatory"))?;

    let entry_address = layout.entry_symbol_address()?;

    let entryoff = entry_address
        .checked_sub(segment_size.mem_offset)
        .filter(|offset| *offset < segment_size.mem_size)
        .ok_or_else(|| {
            error!(
                "Entry point address 0x{entry_address:x} is not within the __TEXT segment \
                 (0x{:x}..0x{:x})",
                segment_size.mem_offset,
                segment_size.mem_offset + segment_size.mem_size,
            )
        })?;

    command.cmd.set(LE, LC_MAIN);
    command
        .cmdsize
        .set(LE, size_of::<EntryPointCommand>() as u32);
    command.entryoff.set(LE, entryoff);
    // Zero leaves dyld to use the system default, which is what almost every program wants.
    command
        .stacksize
        .set(LE, layout.args().stack_size.unwrap_or(0));

    // Malfunction: shift the entry point by one instruction. Deliberately expressed as a mutation
    // of whatever value was computed above rather than as part of the computation, so that this
    // stays valid if the way `entryoff` is derived changes.
    if malfunction::malfunction_point("macho-wrong-entry-point") {
        let entryoff = command.entryoff.get(LE);
        command.entryoff.set(LE, entryoff.wrapping_add(4));
    }

    Ok(())
}

fn write_build_version_command(layout: &MachOLayout, command: &mut BuildVersionCommand) -> Result {
    let platform_version = layout
        .args()
        .platform_version
        .as_ref()
        .ok_or("platform_version must be set")?;

    command.cmd.set(LE, LC_BUILD_VERSION);
    command
        .cmdsize
        .set(LE, size_of::<BuildVersionCommand>() as u32);
    command.platform.set(LE, PLATFORM_MACOS);
    command
        .minos
        .set(LE, platform_version.minimum_version.get());
    command.sdk.set(LE, platform_version.sdk_version.get());
    command.ntools.set(LE, 0);
    // TODO: We could record Wild's version here, but Mach-O only defines tool IDs
    // for Apple toolchain components, so leave the tools list empty for now.
    Ok(())
}

fn write_uuid_command(command: &mut UuidCommand) {
    command.cmd.set(LE, LC_UUID);
    command.cmdsize.set(LE, size_of::<UuidCommand>() as u32);
    command.uuid.zero();
}

fn write_dylinker_command(command: &mut DylinkerCommand, path_buffer: &mut [u8]) {
    command.cmd.set(LE, LC_LOAD_DYLINKER);
    command.cmdsize.set(
        LE,
        ((size_of::<DylinkerCommand>() + DYLINKER_PATH.len())
            .next_multiple_of(MACHO_COMMAND_ALIGNMENT)) as u32,
    );
    command
        .name
        .offset
        .set(LE, size_of::<DylinkerCommand>() as u32);

    path_buffer[0..DYLINKER_PATH.len()].copy_from_slice(DYLINKER_PATH);
    path_buffer[DYLINKER_PATH.len()..].zero();
}

/// Writes `LC_RPATH`: one directory dyld should try when resolving an `@rpath`-relative dependency.
fn write_rpath_command(command: &mut RpathCommand, path_buffer: &mut [u8], path: &str) {
    command.cmd.set(LE, LC_RPATH);
    command.cmdsize.set(LE, rpath_command_size(path) as u32);
    command
        .path
        .offset
        .set(LE, size_of::<RpathCommand>() as u32);

    path_buffer[0..path.len()].copy_from_slice(path.as_bytes());
    path_buffer[path.len()..].zero();
}

fn write_dylib_command(
    command: &mut DylibCommand,
    path_buffer: &mut [u8],
    path: &[u8],
    versions: crate::macho::DylibVersions,
    is_weak: bool,
) {
    // Same command either way, differing only in whether dyld insists on finding the library.
    command.cmd.set(
        LE,
        if is_weak {
            object::macho::LC_LOAD_WEAK_DYLIB
        } else {
            LC_LOAD_DYLIB
        },
    );
    command
        .cmdsize
        .set(LE, load_dylib_command_size(path) as u32);
    command
        .dylib
        .name
        .offset
        .set(LE, size_of::<DylibCommand>() as u32);
    // TODO
    command.dylib.timestamp.set(LE, 2);

    // Taken from the library rather than invented: dyld refuses to load one older than the image
    // was built against, so a made-up compatibility version either waves through a library that
    // should have been rejected or rejects one that was fine.
    command.dylib.current_version.set(LE, versions.current);
    command
        .dylib
        .compatibility_version
        .set(LE, versions.compatibility);

    path_buffer[0..path.len()].copy_from_slice(path);
    path_buffer[path.len()..].zero();
}

fn write_dyld_chained_fixups_command(layout: &MachOLayout, command: &mut DyldChainedFixupsCommand) {
    let chained_fixup_table = layout
        .section_layouts
        .get(output_section_id::CHAINED_FIXUP_TABLE);

    command.cmd.set(LE, LC_DYLD_CHAINED_FIXUPS);
    command
        .cmdsize
        .set(LE, size_of::<DyldChainedFixupsCommand>() as u32);
    command
        .dataoff
        .set(LE, chained_fixup_table.file_offset as u32);
    command
        .datasize
        .set(LE, chained_fixup_table.file_size as u32);
}

fn write_symtab_command(layout: &MachOLayout, command: &mut SymtabCommand) {
    // The table is one run made of two adjacent output sections - locals then externals - so it
    // starts where the locals do and covers both.
    let locals = layout.section_layouts.get(output_section_id::SYMTAB_LOCAL);
    let globals = layout.section_layouts.get(output_section_id::SYMTAB_GLOBAL);
    let strtab = layout.section_layouts.get(output_section_id::STRTAB);

    command.cmd.set(LE, LC_SYMTAB);
    command.cmdsize.set(LE, size_of::<SymtabCommand>() as u32);
    command.symoff.set(LE, locals.file_offset as u32);

    let mut nsyms = ((locals.file_size + globals.file_size) / size_of::<SymtabEntry>()) as u32;

    // Malfunction: under-report the symbol count so that the last symbol in the table becomes
    // invisible to anything reading LC_SYMTAB. The symbol bytes are still present in __LINKEDIT,
    // so this is not detectable by hashing the file's contents - only by comparing symbol tables.
    if malfunction::malfunction_point("macho-truncate-symtab") {
        nsyms = nsyms.saturating_sub(1);
    }

    command.nsyms.set(LE, nsyms);
    command.stroff.set(LE, strtab.file_offset as u32);
    command.strsize.set(LE, strtab.file_size as u32);
}

/// Returns how many slots `__stubs` holds, which is also where `__got`'s run starts in the
/// indirect symbol table, since the stubs are emitted first.
fn num_stub_slots(layout: &MachOLayout) -> u32 {
    (layout
        .section_layouts
        .get(output_section_id::PLT_GOT)
        .file_size as u64
        / PLT_ENTRY_SIZE) as u32
}

/// Returns the symbol table index of the undefined symbol for the import at `import_index`.
///
/// The undefined symbols are the last run of the table, written by the epilogue in import order,
/// so an import's position in the list is its position in that run.
fn undefined_symbol_index(layout: &MachOLayout, import_index: usize) -> u32 {
    let entry_size = size_of::<SymtabEntry>();
    let num_symbols = (layout
        .section_layouts
        .get(output_section_id::SYMTAB_LOCAL)
        .file_size
        + layout
            .section_layouts
            .get(output_section_id::SYMTAB_GLOBAL)
            .file_size)
        / entry_size;

    (num_symbols - layout.format_specific.imported_symbols.len() + import_index) as u32
}

/// Writes the indirect symbol table: one symbol index per slot of `__stubs` and then of `__got`,
/// naming the symbol whose address that slot holds.
///
/// A slot's position within its section is derived from its address rather than from the order of
/// the import list, so this can't silently disagree with what `write_got_entries` and
/// `write_plt_entries` actually put there.
fn write_indirect_symtab(layout: &MachOLayout, out: &mut [u8]) -> Result {
    let num_stubs = num_stub_slots(layout) as usize;
    let stubs_base = layout
        .section_layouts
        .get(output_section_id::PLT_GOT)
        .mem_offset;
    let got_base = layout
        .section_layouts
        .get(output_section_id::GOT)
        .mem_offset;

    let entries: &mut [U32<Endianness>] = slice_from_all_bytes_mut(out);

    // Not every slot names a symbol another image has to supply: one holding the address of a
    // symbol defined here is marked as such, so nothing tries to read a symbol index out of it.
    // Zero would otherwise be read as "the symbol at index 0", which is a real entry.
    for entry in entries.iter_mut() {
        entry.set(LE, macho::INDIRECT_SYMBOL_LOCAL.0);
    }

    for (import_index, imported_symbol) in
        layout.format_specific.imported_symbols.iter().enumerate()
    {
        let symbol_index = undefined_symbol_index(layout, import_index);

        let got_slot = imported_symbol
            .got_address
            .get()
            .checked_sub(got_base)
            .ok_or_else(|| error!("GOT entry address is before __got"))?
            / GOT_ENTRY_SIZE;

        let got_entry = entries
            .get_mut(num_stubs + got_slot as usize)
            .ok_or_else(|| error!("__got slot is outside the indirect symbol table"))?;
        got_entry.set(LE, symbol_index);

        if let Some(plt_address) = imported_symbol.plt_address {
            let stub_slot = plt_address
                .get()
                .checked_sub(stubs_base)
                .ok_or_else(|| error!("Stub address is before __stubs"))?
                / PLT_ENTRY_SIZE;

            let stub_entry = entries
                .get_mut(stub_slot as usize)
                .ok_or_else(|| error!("__stubs slot is outside the indirect symbol table"))?;
            stub_entry.set(LE, symbol_index);
        }
    }

    Ok(())
}

/// Describes how the symbol table is partitioned, and locates the indirect symbol table.
///
/// The three runs are contiguous by construction: locals and externals are separate output
/// sections laid out in that order, and the undefined ones are written by the epilogue, which comes
/// last. See `allocate_symtab`.
fn write_dysymtab_command(layout: &MachOLayout, command: &mut DysymtabCommand) {
    let entry_size = size_of::<SymtabEntry>();
    let num_locals = layout
        .section_layouts
        .get(output_section_id::SYMTAB_LOCAL)
        .file_size
        / entry_size;
    let num_globals = layout
        .section_layouts
        .get(output_section_id::SYMTAB_GLOBAL)
        .file_size
        / entry_size;

    // The epilogue writes exactly one undefined symbol per import, at the end of the global part.
    let num_undefined = layout.format_specific.imported_symbols.len();
    let num_defined_globals = num_globals - num_undefined;

    let indirect = layout
        .section_layouts
        .get(output_section_id::INDIRECT_SYMTAB);

    command.cmd.set(LE, LC_DYSYMTAB);
    command.cmdsize.set(LE, size_of::<DysymtabCommand>() as u32);

    command.ilocalsym.set(LE, 0);
    command.nlocalsym.set(LE, num_locals as u32);
    command.iextdefsym.set(LE, num_locals as u32);
    command.nextdefsym.set(LE, num_defined_globals as u32);
    command
        .iundefsym
        .set(LE, (num_locals + num_defined_globals) as u32);
    command.nundefsym.set(LE, num_undefined as u32);

    command.indirectsymoff.set(LE, indirect.file_offset as u32);
    command.nindirectsyms.set(
        LE,
        (indirect.file_size as u64 / INDIRECT_SYMTAB_ENTRY_SIZE) as u32,
    );

    // We emit no table of contents, module table, reference table or relocations - a linked image
    // needs none of them, and ld64 leaves them empty here too.
    command.tocoff.set(LE, 0);
    command.ntoc.set(LE, 0);
    command.modtaboff.set(LE, 0);
    command.nmodtab.set(LE, 0);
    command.extrefsymoff.set(LE, 0);
    command.nextrefsyms.set(LE, 0);
    command.extreloff.set(LE, 0);
    command.nextrel.set(LE, 0);
    command.locreloff.set(LE, 0);
    command.nlocrel.set(LE, 0);
}

fn write_code_signature_command(layout: &MachOLayout, command: &mut CodeSignatureCommand) {
    let code_signature = layout
        .section_layouts
        .get(output_section_id::CODE_SIGNATURE);

    command.cmd.set(LE, LC_CODE_SIGNATURE);
    command
        .cmdsize
        .set(LE, size_of::<CodeSignatureCommand>() as u32);
    command.dataoff.set(LE, code_signature.file_offset as u32);
    command.datasize.set(LE, code_signature.file_size as u32);
}

/// The `page_start` value that says a page holds no fixups at all.
const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;

/// Position of the `next` field shared by every 64-bit chained-pointer format. It counts
/// `CHAINED_PTR_NEXT_STRIDE` sized units from one link of a chain to the following one; zero ends
/// the chain.
const CHAINED_PTR_NEXT_SHIFT: u32 = 51;
const CHAINED_PTR_NEXT_MASK: u64 = 0xfff << CHAINED_PTR_NEXT_SHIFT;
const CHAINED_PTR_NEXT_STRIDE: u64 = 4;

/// Width of the `target` field of a `DYLD_CHAINED_PTR_64_OFFSET` rebase.
const CHAINED_PTR_64_TARGET_BITS: u32 = 36;

/// Position of the top byte of a pointer, which a rebase stores in its own `high8` field directly
/// above `target` rather than folding into the offset. That's what lets a tagged pointer
/// round-trip.
const CHAINED_PTR_64_HIGH8_SHIFT: u32 = 56;

/// Width of the `name_offset` field of a `dyld_chained_import`.
const CHAINED_IMPORT_NAME_OFFSET_BITS: u32 = 23;
/// Where the "this need not be there" bit sits in a `dyld_chained_import`, between the library
/// ordinal below it and the name offset above.
const CHAINED_IMPORT_WEAK_BIT: u32 = 8;

/// Set in a `DYLD_CHAINED_PTR_64` slot to say that dyld should bind it to an imported symbol
/// rather than slide it as a rebase.
const CHAINED_PTR_BIND: u64 = 1 << 63;

/// The `addend` field of a `dyld_chained_ptr_64_bind`, which sits directly above the 24-bit import
/// ordinal. It's how a reference to an imported symbol carries a displacement, since the address
/// being displaced isn't known until dyld resolves the symbol.
const CHAINED_PTR_BIND_ADDEND_SHIFT: u32 = 24;
const CHAINED_PTR_BIND_ADDEND_BITS: u32 = 8;
const CHAINED_PTR_BIND_MAX_ADDEND: u64 = (1 << CHAINED_PTR_BIND_ADDEND_BITS) - 1;

/// Returns the address the thread-local template starts at, which is what offsets stored in a
/// `tlv_descriptor` are measured from. `__thread_data` comes first and `__thread_bss` follows it,
/// so the start of `__thread_data` is the base of the whole block.
fn thread_local_block_address(layout: &MachOLayout<'_>) -> u64 {
    layout
        .section_layouts
        .get(output_section_id::TDATA)
        .mem_offset
}

/// Returns the position of a symbol in the import list, which is what a bind slot stores to say
/// which symbol dyld should resolve it to.
fn import_ordinal(layout: &MachOLayout<'_>, symbol_id: SymbolId) -> Result<u64> {
    // The import list is keyed by the symbol's definition, which is the one in the dylib, whereas
    // a relocation names the undefined symbol in the referencing object.
    let definition = layout.symbol_db.definition(symbol_id);

    layout
        .format_specific
        .imported_symbols
        .iter()
        .position(|imported| imported.symbol_id == definition)
        .map(|ordinal| ordinal as u64)
        .ok_or_else(|| {
            // Only symbols that get a `__got` or `__stubs` entry are currently recorded as
            // imports, so a symbol reached solely through a pointer in initialised data - a global
            // initialised to the address of a libc function, say - never makes it into the list
            // and has no ordinal to bind to. Erroring beats the alternative: before binds were
            // emitted at all, such a slot got a rebase of a nonsense address and the binary took
            // SIGBUS the first time it was used.
            error!(
                "{} is only referenced by a pointer in data, which wild cannot import yet",
                layout.symbol_debug(symbol_id)
            )
        })
}

/// A slot in the output image that dyld has to write to at load time.
#[derive(Clone, Copy)]
struct FixupSite {
    /// Memory address of the slot in the output image.
    address: u64,

    /// Whether the slot is bound to an imported symbol. Bind slots have already had their ordinal
    /// encoded by `write_got_entries` and only need their `next` field filling in. The rest hold
    /// an address within this image and need re-encoding as a rebase.
    is_bind: bool,
}

/// A segment that can hold chained fixups, together with the fixups that landed in it.
struct SegmentFixups {
    /// Index of the segment among the output's `LC_SEGMENT_64` commands, which is what
    /// `dyld_chained_starts_in_image::seg_info_offset` is indexed by. Segments without fixups
    /// still take up an index, so this cannot be a position within `SegmentFixups` values.
    segment_index: usize,

    segment_type: SegmentType,
    sizes: OutputRecordLayout,
    sites: Vec<FixupSite>,

    /// Offset within each page of the first link of that page's chain, or
    /// `DYLD_CHAINED_PTR_START_NONE`.
    page_starts: Vec<u16>,
}

/// Writes the pointer chains that dyld walks at load time, and the `LC_DYLD_CHAINED_FIXUPS`
/// payload that describes where those chains start.
///
/// Both kinds of fixup - a bind against an imported symbol and a rebase of an address within this
/// image - are links of the same singly linked list, so they have to be emitted together. There is
/// one chain per page of each segment: `page_starts[p]` locates the first link in page `p` and each
/// link's `next` field gives the distance to the following one. A chain never crosses a page
/// boundary, which is what lets the kernel apply fixups a page at a time.
fn write_chained_fixups(
    layout: &MachOLayout,
    sized_output: &mut SizedOutput,
    fixup_sites: Vec<FixupSite>,
) -> Result {
    verbose_timing_phase!("Write chained fixups");

    let page_size = MACHO_PAGE_ALIGNMENT.value();

    // dyld applies a rebase as `mach_header_address + target`, so targets are relative to the
    // start of `SegmentType::Text`, which is the segment that contains the mach header.
    let image_base = get_segment_sections(layout, SegmentType::Text)
        .ok_or_else(|| error!("Text segment is mandatory"))?
        .segment_size
        .mem_offset;

    // `write_segment_commands` emits `__PAGEZERO` before everything in `PROGRAM_SEGMENT_DEFS`, so
    // it takes segment index 0 and the definitions that count as segments follow in order.
    let mut segment_count = 1;
    let mut segments = Vec::new();

    for def in PROGRAM_SEGMENT_DEFS
        .iter()
        .filter(|def| def.count_as_segment)
    {
        let Some(info) = get_segment_sections(layout, def.segment_type) else {
            continue;
        };

        let segment_index = segment_count;
        segment_count += 1;

        // Only the writable data segments can hold fixups: applying one is a store into the
        // segment, and everything else is mapped read-only.
        if matches!(
            def.segment_type,
            SegmentType::DataSections | SegmentType::DataConstSections
        ) {
            segments.push(SegmentFixups {
                segment_index,
                segment_type: def.segment_type,
                sizes: info.segment_size,
                sites: Vec::new(),
                page_starts: Vec::new(),
            });
        }
    }

    ensure!(
        segment_count <= MAX_SEGMENT_COUNT,
        "unexpected number of active segments"
    );

    let mut sites = layout
        .format_specific
        .imported_symbols
        .iter()
        .map(|imported_symbol| FixupSite {
            address: imported_symbol.got_address.get(),
            is_bind: true,
        })
        .chain(fixup_sites)
        .collect_vec();

    // dyld walks each chain from low to high address, so that's the order the links go in.
    sites.sort_unstable_by_key(|site| site.address);

    for site in sites {
        let segment = segments
            .iter_mut()
            .find(|segment| {
                site.address >= segment.sizes.mem_offset
                    && site.address - segment.sizes.mem_offset < segment.sizes.mem_size
            })
            .with_context(|| {
                format!(
                    "Fixup at address 0x{:x} is outside __DATA and __DATA_CONST, so dyld has \
                     nowhere to apply it. A pointer in initialised data has ended up in a \
                     read-only segment - note that `__DATA,__const` is currently mapped into \
                     __TEXT rather than __DATA_CONST",
                    site.address
                )
            })?;

        segment.sites.push(site);
    }

    write_fixup_chains(sized_output, &mut segments, image_base, page_size)?;

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;

    write_chained_fixup_table(
        layout,
        section_buffers.get_mut(output_section_id::CHAINED_FIXUP_TABLE),
        &segments,
        segment_count,
        image_base,
        page_size,
    )
}

/// Encodes each page's chain in place in the output buffer and records where it starts.
fn write_fixup_chains(
    sized_output: &mut SizedOutput,
    segments: &mut [SegmentFixups],
    image_base: u64,
    page_size: u64,
) -> Result {
    let out = &mut *sized_output.out;
    let mut fixup_dropped = false;

    for segment in segments {
        if segment.sites.is_empty() {
            continue;
        }

        let last_offset =
            segment.sites.last().expect("checked above").address - segment.sizes.mem_offset;

        // `page_count` is just the length of the `page_start` array, so it has to reach the last
        // page that has a fixup on it. Covering the whole segment as well matches what ld64 does.
        let page_count =
            (last_offset / page_size + 1).max(segment.sizes.mem_size.div_ceil(page_size));
        segment.page_starts = vec![DYLD_CHAINED_PTR_START_NONE; usize::try_from(page_count)?];

        for (i, site) in segment.sites.iter().enumerate() {
            let offset_in_segment = site.address - segment.sizes.mem_offset;
            let page = offset_in_segment / page_size;
            let offset_in_page = offset_in_segment % page_size;

            ensure!(
                offset_in_page.is_multiple_of(CHAINED_PTR_NEXT_STRIDE),
                "Chained fixup at address 0x{:x} (segment at 0x{:x}) isn't aligned to the chain stride",
                site.address,
                segment.sizes.mem_offset
            );

            let page_start = &mut segment.page_starts[usize::try_from(page)?];
            if *page_start == DYLD_CHAINED_PTR_START_NONE {
                *page_start = offset_in_page as u16;
            }

            // The chain stops at the end of the page. Whatever comes next starts a new chain that
            // is reached through `page_starts` instead.
            let mut next = match segment.sites.get(i + 1) {
                Some(following)
                    if (following.address - segment.sizes.mem_offset) / page_size == page =>
                {
                    (following.address - site.address) / CHAINED_PTR_NEXT_STRIDE
                }
                _ => 0,
            };

            ensure!(
                next <= CHAINED_PTR_NEXT_MASK >> CHAINED_PTR_NEXT_SHIFT,
                "Chained fixup at address 0x{:x} is too far from the following fixup",
                site.address
            );

            // Malfunction: cut the first chain that has more than one link short after its first
            // entry. The `dyld_chained_import` table and the `page_starts` array are left intact,
            // so a checker that only reads those sees nothing wrong; only a checker that actually
            // *walks* the page chain notices that every fixup after the first has become
            // unreachable and will never be applied by dyld. Skipping over chains that are
            // already a single link is what makes this bite regardless of which segment happens
            // to come first.
            if next != 0 && !fixup_dropped && malfunction::malfunction_point("macho-drop-fixup") {
                next = 0;
                fixup_dropped = true;
            }

            let file_offset =
                usize::try_from(segment.sizes.file_offset as u64 + offset_in_segment)?;
            let slot = out
                .get_mut(file_offset..file_offset + size_of::<u64>())
                .with_context(|| {
                    format!(
                        "Chained fixup at address 0x{:x} is outside of the output file",
                        site.address
                    )
                })?;
            let existing = u64::from_le_bytes(slot.try_into().expect("slot is 8 bytes"));

            let value = if site.is_bind {
                (existing & !CHAINED_PTR_NEXT_MASK) | (next << CHAINED_PTR_NEXT_SHIFT)
            } else {
                /* DYLD_CHAINED_PTR_64_OFFSET rebase format:
                uint64_t dyld_chained_ptr_64_rebase:
                  target: 36 // offset from the address the mach header is loaded at
                  high8: 8
                  reserved: 7 // all zeros
                  next: 12 // 4-byte stride
                  bind: 1 // == 0
                */
                // The top byte is carried separately rather than as part of the offset, so that a
                // pointer with tag bits in it survives. libc++ relies on this: `type_info::__name`
                // has its top bit set to say the name isn't unique across images, so every C++
                // program with RTTI has pointers here that aren't just addresses.
                let high8 = existing >> CHAINED_PTR_64_HIGH8_SHIFT;
                let address = existing & ((1 << CHAINED_PTR_64_HIGH8_SHIFT) - 1);

                let target = address.checked_sub(image_base).with_context(|| {
                    format!(
                        "Rebase at address 0x{site_address:x} points at 0x{existing:x}, \
                         which is before the image base 0x{image_base:x}",
                        site_address = site.address
                    )
                })?;

                ensure!(
                    target < (1 << CHAINED_PTR_64_TARGET_BITS),
                    "Rebase at address 0x{:x} points at 0x{existing:x}, which is too far from \
                     the image base to encode",
                    site.address
                );

                target | (high8 << CHAINED_PTR_64_TARGET_BITS) | (next << CHAINED_PTR_NEXT_SHIFT)
            };

            slot.copy_from_slice(&value.to_le_bytes());
        }
    }

    Ok(())
}

fn write_chained_fixup_table(
    layout: &MachOLayout,
    chained_fixup_table: &mut [u8],
    segments: &[SegmentFixups],
    segment_count: usize,
    image_base: u64,
    page_size: u64,
) -> Result {
    let symbols = &layout.format_specific.imported_symbols;

    // 1) work out the offsets of everything. `dyld_chained_starts_in_image` is `seg_count` (u32)
    //    followed by `seg_info_offset` ([u32; seg_count]), where a zero offset means the segment
    //    has no fixups. The `dyld_chained_starts_in_segment` records for the segments that do
    //    follow it, and the offsets that point at them are relative to `seg_count`.
    let starts_offset = size_of::<ChainedFixupsHeader>();
    let starts_in_image_len = size_of::<u32>() * (segment_count + 1);
    let mut seg_info_offsets = vec![0u32; segment_count];
    let mut starts_in_segment_len = 0;

    for segment in segments {
        if segment.sites.is_empty() {
            continue;
        }

        // Malfunction: leave the `seg_info_offset` for this segment at zero. A zero offset means
        // "this segment has no fixups", so dyld skips the segment entirely and none of its binds
        // or rebases are ever applied - while the `dyld_chained_starts_in_segment` record we go
        // on to write below is still physically present in the blob, just orphaned. This is the
        // shape of the real bug that motivated this work (wild used to emit a starts record for
        // only one segment), so any checker that claims to detect that bug must detect this.
        if segment.segment_type != SegmentType::DataConstSections
            || !malfunction::malfunction_point("macho-drop-segment-starts")
        {
            seg_info_offsets[segment.segment_index] =
                u32::try_from(starts_in_image_len + starts_in_segment_len)?;
        }

        starts_in_segment_len += size_of::<DyldChainedStartsInSegment>()
            + CHAINED_FIXUP_PAGE_START_SIZE as usize * segment.page_starts.len();
    }

    let imports_offset = (starts_offset + starts_in_image_len + starts_in_segment_len)
        .next_multiple_of(size_of::<u32>());

    // 2) fill up the header
    let mut header = ChainedFixupsHeader::new_zeroed();
    header.fixups_version.set(0);
    header.starts_offset.set(u32::try_from(starts_offset)?);
    header.imports_offset.set(u32::try_from(imports_offset)?);
    header.symbols_offset.set(u32::try_from(
        imports_offset + size_of::<u32>() * symbols.len(),
    )?);
    header.imports_count.set(u32::try_from(symbols.len())?);
    header.imports_format.set(DYLD_CHAINED_IMPORT);
    header.symbols_format.set(0);

    let mut blob = Vec::with_capacity(imports_offset);
    blob.extend_from_slice(header.as_bytes());

    // 3) fill up dyld_chained_starts_in_image
    blob.extend_from_slice(&u32::try_from(segment_count)?.to_le_bytes());
    for seg_info_offset in &seg_info_offsets {
        blob.extend_from_slice(&seg_info_offset.to_le_bytes());
    }

    // 4) fill up one dyld_chained_starts_in_segment per segment that has fixups
    for segment in segments {
        if segment.sites.is_empty() {
            continue;
        }

        let mut starts_in_segment = DyldChainedStartsInSegment::new_zeroed();
        starts_in_segment.size.set(u32::try_from(
            size_of::<DyldChainedStartsInSegment>()
                + CHAINED_FIXUP_PAGE_START_SIZE as usize * segment.page_starts.len(),
        )?);
        starts_in_segment.page_size.set(u16::try_from(page_size)?);
        starts_in_segment
            .pointer_format
            .set(DYLD_CHAINED_PTR_64_OFFSET);

        // `segment_offset` is where the segment is relative to the mach header, which is how dyld
        // finds the page that a `page_start` belongs to.
        let mut segment_offset = segment
            .sizes
            .mem_offset
            .checked_sub(image_base)
            .context("Segment with fixups is before the image base")?;

        // Malfunction: point the starts record at the wrong segment offset (one page too high).
        // Every fixup slot in the chain is then computed relative to the wrong base, so dyld
        // writes pointers into the wrong memory.
        // `integration_tests::verify_chained_fixups_segment_offsets` already checks this field,
        // so this injection also proves that check still bites.
        if segment.segment_type == SegmentType::DataConstSections
            && malfunction::malfunction_point("macho-wrong-segment-offset")
        {
            segment_offset = segment_offset.wrapping_add(page_size);
        }

        starts_in_segment.segment_offset.set(segment_offset);
        starts_in_segment.max_valid_pointer.set(0);
        starts_in_segment
            .page_count
            .set(u16::try_from(segment.page_starts.len())?);

        blob.extend_from_slice(starts_in_segment.as_bytes());
        for page_start in &segment.page_starts {
            blob.extend_from_slice(&page_start.to_le_bytes());
        }
    }

    // Pad out to the (aligned) start of the imports table.
    blob.resize(imports_offset, 0);

    // 5) build the symbol string pool, which the imports below refer to by offset
    let mut string_pool = Vec::new();
    let mut symbol_offsets = Vec::with_capacity(symbols.len());

    for imported_symbol in symbols {
        let symbol_name = layout
            .symbol_db
            .symbol_name(imported_symbol.symbol_id)?
            .bytes();
        symbol_offsets.push(u32::try_from(string_pool.len())?);
        string_pool.extend_from_slice(symbol_name);
        string_pool.push(b'\0');
    }

    // 6) emit `dyld_chained_import`, which is built from 3 pieces:
    // lib_ordinal: 8
    // weak_import: 1
    // name_offset: 23
    for (imported_symbol, symbol_offset) in symbols.iter().zip(&symbol_offsets) {
        let file_id = layout
            .symbol_db
            .file_id_for_symbol(imported_symbol.symbol_id);

        let dynamic = match layout.file_layout(file_id) {
            FileLayout::StubLibrary(file) => &file.format_specific,
            FileLayout::Dynamic(file) => &file.format_specific,
            _ => {
                bail!("Internal error: Internal symbol refers to non-stub library");
            }
        };

        let mut lib_ordinal = dynamic.ordinal.get();

        // Malfunction: bind against the wrong library. The name offset is untouched, so the
        // import still resolves to a plausible-looking symbol name; only the ordinal that says
        // *which dylib to look in* is wrong. A checker that compares symbol names but not
        // ordinals will not notice.
        if malfunction::malfunction_point("macho-bad-import-ordinal") {
            lib_ordinal = lib_ordinal.wrapping_add(1);
        }

        ensure!(
            *symbol_offset < (1 << CHAINED_IMPORT_NAME_OFFSET_BITS),
            "Chained fixup symbol string pool is too large"
        );

        // The bit between the ordinal and the name says the symbol need not be there: dyld
        // resolves a missing weak import to zero instead of failing to load the image.
        let weak_import = u32::from(crate::macho::is_weak_library(file_id, &layout.symbol_db))
            << CHAINED_IMPORT_WEAK_BIT;

        blob.extend_from_slice(
            &(u32::from(lib_ordinal) | weak_import | (symbol_offset << 9)).to_le_bytes(),
        );
    }

    blob.extend_from_slice(&string_pool);

    ensure!(
        blob.len() <= chained_fixup_table.len(),
        "Insufficient allocation for the chained fixup table: needed {} bytes but have {}",
        blob.len(),
        chained_fixup_table.len()
    );

    chained_fixup_table[..blob.len()].copy_from_slice(&blob);
    // Anything left over is the padding that keeps `__LINKEDIT` aligned.
    chained_fixup_table[blob.len()..].fill(0);

    Ok(())
}
fn write_uuid(layout: &MachOLayout, sized_output: &mut SizedOutput) -> Result {
    verbose_timing_phase!("Write UUID");

    let hash = blake3::Hasher::new()
        .update_rayon(&sized_output.out)
        .finalize();

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    let load_commands = section_buffers.get_mut(output_section_id::LOAD_COMMANDS);

    while !load_commands.is_empty() {
        let header = object::from_bytes::<LoadCommand<Endianness>>(load_commands)
            .map_err(|_| error!("Invalid load command header"))?
            .0;
        let cmd_type = header.cmd.get(LE);
        let cmd_size = header.cmdsize.get(LE) as usize;
        let mut cmd = load_commands
            .split_off_mut(..cmd_size)
            .context("Invalid load command allocation")?;

        if cmd_type == LC_UUID {
            let uuid_cmd = take_mut::<UuidCommand>(&mut cmd)?;
            let uuid_size = uuid_cmd.uuid.len();

            uuid_cmd.uuid.copy_from_slice(&hash.as_bytes()[..uuid_size]);
            // Match lld's UUID Version 3 from RFC 9562.
            uuid_cmd.uuid[6] = (uuid_cmd.uuid[6] & 0x0f) | 0x30;
            uuid_cmd.uuid[8] = (uuid_cmd.uuid[8] & 0x3f) | 0x80;
            return Ok(());
        }
    }

    bail!("Missing LC_UUID");
}

fn write_code_signature_metadata(layout: &MachOLayout, sized_output: &mut SizedOutput) -> Result {
    verbose_timing_phase!("Write code signature metadata");

    let code_signature_section = layout
        .section_layouts
        .get(output_section_id::CODE_SIGNATURE);
    let code_signature_identifier = code_signature_identifier(layout.args());
    let padded_identifier_size = code_signature_padded_identifier_size(layout.args()) as usize;

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    let code_signature = section_buffers.get_mut(output_section_id::CODE_SIGNATURE);

    let (super_blob, rest): (&mut CodeSignatureSuperBlob, &mut [u8]) =
        CodeSignatureSuperBlob::mut_from_prefix(code_signature)
            .map_err(|_| error!("Invalid CODE_SIGNATURE allocation"))?;
    let (blob_indices, rest) = <[CodeSignatureBlobIndex]>::mut_from_prefix_with_elems(rest, 1)
        .map_err(|_| error!("Invalid CODE_SIGNATURE allocation"))?;
    let blob_index = &mut blob_indices[0];
    let (code_directories, rest) =
        <[CodeSignatureCodeDirectory]>::mut_from_prefix_with_elems(rest, 1)
            .map_err(|_| error!("Invalid CODE_SIGNATURE allocation"))?;
    let code_dir = &mut code_directories[0];
    let (identifier, hashes) = rest.split_at_mut(padded_identifier_size);

    super_blob.magic.set(CSMAGIC_EMBEDDED_SIGNATURE);
    super_blob
        .length
        .set(code_signature_section.file_size as u32);
    super_blob.count.set(1);

    blob_index.type_.set(CSSLOT_CODEDIRECTORY);
    blob_index.offset.set(CS_BLOB_HEADERS_SIZE as u32);
    blob_index.padding.set(0);

    code_dir.magic.set(CSMAGIC_CODEDIRECTORY);
    code_dir
        .length
        .set((code_signature_section.file_size as u64 - CS_BLOB_HEADERS_SIZE) as u32);
    code_dir.version.set(CS_SUPPORTSEXECSEG);
    code_dir.flags.set(CS_ADHOC | CS_LINKER_SIGNED);
    code_dir
        .hash_offset
        .set(size_of::<CodeSignatureCodeDirectory>() as u32 + padded_identifier_size as u32);
    code_dir
        .ident_offset
        .set(size_of::<CodeSignatureCodeDirectory>() as u32);
    code_dir.n_special_slots.set(0);
    code_dir
        .n_code_slots
        .set(code_signature_section.file_offset.div_ceil(CS_BLOCK_SIZE) as u32);
    code_dir
        .code_limit
        .set(code_signature_section.file_offset as u32);
    code_dir.hash_size = CS_HASH_SIZE;
    code_dir.hash_type = CS_HASHTYPE_SHA256;
    code_dir.platform = 0;
    code_dir.page_size = CS_BLOCK_SIZE_EXP;
    code_dir.spare2.set(0);
    code_dir.scatter_offset.set(0);
    code_dir.team_offset.set(0);
    code_dir.spare3.set(0);
    code_dir.code_limit64.set(0);

    let text_segment_size = get_segment_sections(layout, SegmentType::Text)
        .ok_or_else(|| error!("Text segment is mandatory"))?
        .segment_size;
    code_dir
        .exec_seg_base
        .set(text_segment_size.file_offset as u64);
    code_dir
        .exec_seg_limit
        .set(text_segment_size.file_size as u64);
    // TODO: change once shared libraries are supported
    code_dir.exec_seg_flags.set(CS_EXECSEG_MAIN_BINARY);

    identifier[..code_signature_identifier.len()].copy_from_slice(code_signature_identifier);
    identifier[code_signature_identifier.len()..].fill(0);
    hashes.fill(0);

    Ok(())
}

fn write_code_signature_hashes(layout: &MachOLayout, sized_output: &mut SizedOutput) -> Result {
    verbose_timing_phase!("Write code signature hashes");

    let code_signature_section = layout
        .section_layouts
        .get(output_section_id::CODE_SIGNATURE);
    let calculated_hashes: Vec<_> = sized_output.out[..code_signature_section.file_offset]
        .par_chunks(CS_BLOCK_SIZE)
        .map(Sha256::digest)
        .collect();
    let calculated_hashes = calculated_hashes.into_iter().flatten().collect_vec();

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    let code_signature = section_buffers.get_mut(output_section_id::CODE_SIGNATURE);
    let hashes_offset =
        (CS_HEADERS_SIZE + code_signature_padded_identifier_size(layout.args())) as usize;
    let hashes = code_signature
        .get_mut(hashes_offset..)
        .ok_or_else(|| error!("Invalid CODE_SIGNATURE allocation"))?;

    hashes.copy_from_slice(&calculated_hashes);

    #[cfg(target_os = "macos")]
    if let crate::file_writer::OutputBuffer::Mmap(output) = &mut sized_output.out {
        // Match lld's workaround for the macOS kernel caching signature-verification
        // data before the final code signature has been written:
        //
        // https://openradar.appspot.com/FB8914231
        unsafe {
            libc::msync(
                output.as_mut_ptr().cast(),
                code_signature_section.file_offset + code_signature_section.file_size,
                libc::MS_INVALIDATE,
            );
        }
    }

    Ok(())
}

struct MachOSymbolTableWriter<'layout> {
    next_strtab_offset: u32,
    /// Which Mach-O section index each output section got. Computed once, because every symbol
    /// needs it and working it out from the output order is a walk of the whole order.
    section_indices: &'layout OutputSectionMap<u8>,
}

impl MachOSymbolTableWriter<'_> {
    fn write_str(&mut self, name: &[u8], buffers: &mut OutputSectionPartMap<&mut [u8]>) -> u32 {
        let len_with_terminator = name.len() + 1;
        let offset = self.next_strtab_offset;
        let out = buffers
            .get_mut(part_id::STRTAB)
            .split_off_mut(..len_with_terminator)
            .unwrap();
        out[..name.len()].copy_from_slice(name);
        out[name.len()] = 0;
        self.next_strtab_offset += len_with_terminator as u32;
        offset
    }

    #[inline(always)]
    fn define_symbol(
        &mut self,
        buffers: &mut OutputSectionPartMap<&mut [u8]>,
        name: &[u8],
        section: u8,
        symbol_type: object::macho::SymbolFlags,
        desc: object::macho::SymbolDesc,
        value: u64,
    ) -> Result {
        let entry = self.write_entry(name, symbol_type, buffers)?;
        entry.n_sect = section;
        entry.n_type = symbol_type;
        entry.n_value.set(LE, value);
        entry.n_desc.set(LE, desc);

        Ok(())
    }

    fn write_entry<'out>(
        &mut self,
        name: &[u8],
        symbol_type: object::macho::SymbolFlags,
        buffers: &'out mut OutputSectionPartMap<&mut [u8]>,
    ) -> Result<&'out mut SymtabEntry> {
        // Local and external symbols go to separate parts so that each ends up as one contiguous
        // run in the output even though objects are written independently. `LC_DYSYMTAB` can then
        // name each run by index. See `allocate_symtab`, which counts them the same way.
        let part = if symbol_type.contains(macho::N_EXT) {
            part_id::SYMTAB_GLOBAL
        } else {
            part_id::SYMTAB_LOCAL
        };

        let string_offset = self.write_str(name, buffers);
        let entry_bytes = buffers
            .get_mut(part)
            .split_off_mut(..size_of::<SymtabEntry>())
            .unwrap();
        let entry: &mut SymtabEntry = from_bytes_mut(entry_bytes)
            .map_err(|_| error!("Invalid symtab entry allocation"))?
            .0;
        entry.n_strx.set(LE, string_offset);
        Ok(entry)
    }
}

fn write_symbols<'data>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    symbol_writer: &mut MachOSymbolTableWriter<'_>,
) -> Result {
    for ((sym_index, sym), flags) in object
        .object
        .enumerate_symbols()
        .zip(layout.per_symbol_flags.raw_range(object.symbol_id_range))
    {
        let symbol_id = object.symbol_id_range.input_to_id(sym_index);
        let Some(info) = SymbolCopyInfo::new(
            object.object,
            sym_index,
            sym,
            symbol_id,
            &layout.symbol_db,
            flags.get(),
            &object.sections,
        ) else {
            continue;
        };

        let mut value = 0;
        let (section, symbol_type, desc) =
            if let Some(section_index) = object.object.symbol_section(sym, sym_index)? {
                let section_id = match &object.sections[section_index.0] {
                    // A symbol in a merged section still belongs to the section it came from; only
                    // its offset within the output moved, and the resolution already accounts for
                    // that.
                    SectionSlot::Loaded(_) | SectionSlot::MergeStrings(_) => object
                        .section_part_id(section_index, &layout.symbol_db.section_part_ids)
                        .output_section_id(),
                    _ => bail!(
                        "Tried to copy a symbol in a section we didn't load. {}",
                        layout.symbol_debug(symbol_id)
                    ),
                };
                let primary_id = layout.output_sections.primary_output_section(section_id);
                let n_type = sym.n_type.with_type(N_SECT);
                let n_sect = *symbol_writer.section_indices.get(primary_id);
                ensure!(
                    n_sect != 0,
                    "No Mach-O section index for {} while writing {}",
                    primary_id,
                    layout.symbol_debug(symbol_id)
                );
                let n_desc = sym.n_desc.get(LE);
                (n_sect, n_type, n_desc)
            } else if sym.is_absolute() {
                let n_desc = sym.n_desc.get(LE);
                (0, sym.n_type.with_type(N_ABS), n_desc)
            } else {
                bail!("Attempted to output a Mach-O symtab entry with an unexpected section type")
            };

        if let Some(res) = layout.local_symbol_resolution(symbol_id) {
            value = res.value_for_symbol_table();
        }

        symbol_writer.define_symbol(buffers, info.name, section, symbol_type, desc, value)?;
    }

    write_debug_map(object, buffers, layout, symbol_writer)?;

    Ok(())
}

/// Writes the stabs that say where this object's debug info lives.
///
/// They go after the object's own symbols, which is where ld64 puts them and what keeps each
/// object's map in one run. Everything here is a local symbol, so `LC_DYSYMTAB` counts them along
/// with the rest without being told separately.
fn write_debug_map<'data>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    symbol_writer: &mut MachOSymbolTableWriter<'_>,
) -> Result {
    let Some(debug_info) = crate::macho::debug_map_info(object.object, layout.args())? else {
        return Ok(());
    };

    let text_section = *symbol_writer.section_indices.get(output_section_id::TEXT);

    let stab = |writer: &mut MachOSymbolTableWriter<'_>,
                buffers: &mut OutputSectionPartMap<&mut [u8]>,
                kind: u8,
                name: &[u8],
                section: u8,
                descriptor: u16,
                value: u64|
     -> Result {
        writer.define_symbol(
            buffers,
            name,
            section,
            object::macho::SymbolFlags(kind),
            object::macho::SymbolDesc(descriptor),
            value,
        )
    };

    // Where the compiler was run, and what it was compiling. `dsymutil` joins the two by
    // concatenation, which is why the directory carries its own trailing separator.
    stab(symbol_writer, buffers, N_SO, b"", text_section, 0, 0)?;
    stab(symbol_writer, buffers, N_SO, &debug_info.directory, 0, 0, 0)?;
    stab(symbol_writer, buffers, N_SO, &debug_info.file_name, 0, 0, 0)?;

    // The object itself, and when it was written. `dsymutil` opens this path to read the DWARF, and
    // compares the timestamp against the file it finds to know whether it is still the right one.
    let object_path = object.input.debug_map_path();
    stab(
        symbol_writer,
        buffers,
        N_OSO,
        object_path.as_os_str().as_encoded_bytes(),
        0,
        1,
        object.input.modification_time_seconds(),
    )?;

    for ((sym_index, sym), flags) in object
        .object
        .enumerate_symbols()
        .zip(layout.per_symbol_flags.raw_range(object.symbol_id_range))
    {
        let symbol_id = object.symbol_id_range.input_to_id(sym_index);
        let Some(info) = SymbolCopyInfo::new(
            object.object,
            sym_index,
            sym,
            symbol_id,
            &layout.symbol_db,
            flags.get(),
            &object.sections,
        ) else {
            continue;
        };

        let Some(kind) = crate::macho::debug_map_stab_kind(object.object, sym, sym_index)? else {
            continue;
        };

        let address = layout
            .local_symbol_resolution(symbol_id)
            .map_or(0, |resolution| resolution.value_for_symbol_table());

        match kind {
            crate::macho::DebugMapEntry::Function => {
                let length =
                    object
                        .object
                        .symbol_section(sym, sym_index)?
                        .map_or(0, |section_index| {
                            object
                                .object
                                .section(section_index)
                                .map_or(0, |section| section.size.get(LE))
                        });

                stab(
                    symbol_writer,
                    buffers,
                    N_BNSYM,
                    b"",
                    text_section,
                    0,
                    address,
                )?;
                stab(
                    symbol_writer,
                    buffers,
                    N_FUN,
                    info.name,
                    text_section,
                    0,
                    address,
                )?;
                // The function's length, in an entry with no name and no section - the pair is read
                // together, and the second half says how far the first one extends.
                stab(symbol_writer, buffers, N_FUN, b"", 0, 0, length)?;
                stab(
                    symbol_writer,
                    buffers,
                    N_ENSYM,
                    b"",
                    text_section,
                    0,
                    address,
                )?;
            }

            crate::macho::DebugMapEntry::Variable => {
                // A variable with external linkage is found by name from the ordinary symbol table,
                // so its address is left at zero. One with internal linkage has no such symbol and
                // carries its address here.
                if sym.n_type.contains(macho::N_EXT) {
                    stab(symbol_writer, buffers, N_GSYM, info.name, 0, 0, 0)?;
                } else {
                    let section = section_index_of(
                        object,
                        sym,
                        sym_index,
                        symbol_writer,
                        &layout.symbol_db.section_part_ids,
                    )?;

                    stab(
                        symbol_writer,
                        buffers,
                        N_STSYM,
                        info.name,
                        section,
                        0,
                        address,
                    )?;
                }
            }
        }
    }

    stab(symbol_writer, buffers, N_SO, b"", text_section, 0, 0)?;

    Ok(())
}

/// The Mach-O section number a symbol's definition lands in.
fn section_index_of(
    object: &ObjectLayout<'_, MachO>,
    symbol: &SymtabEntry,
    symbol_index: SymbolIndex,
    symbol_writer: &MachOSymbolTableWriter<'_>,
    section_part_ids: &[crate::part_id::PartId],
) -> Result<u8> {
    let Some(section_index) = object.object.symbol_section(symbol, symbol_index)? else {
        return Ok(0);
    };

    let section_id = object
        .section_part_id(section_index, section_part_ids)
        .output_section_id();

    Ok(*symbol_writer.section_indices.get(section_id))
}

/// Returns the address of the branch island to use for a branch that can't reach its target, or
/// `None` if it can reach it directly.
///
/// A `BRANCH26` carries a 26-bit signed word displacement, so it reaches +-128 MiB. Past that the
/// branch physically cannot encode the target, and the only way to keep it is to send it somewhere
/// nearer that does the long jump - so layout reserves an island per out-of-range target and this
/// redirects the branch to it.
fn thunk_address_for_relocation<A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'_, MachO>,
    part_id: crate::part_id::PartId,
    layout: &MachOLayout<'_>,
    rel_info: RelocationKindInfo,
    local_symbol_id: SymbolId,
    value: u64,
) -> Result<Option<u64>> {
    let Some(config) = A::thunk_config() else {
        return Ok(None);
    };

    if !rel_info.thunkable || rel_info.range.contains(value as i64) {
        return Ok(None);
    }

    let canonical_id = layout.symbol_db.definition(local_symbol_id);

    // Code in the main alignment bucket gets its object's own block of islands, which keeps each
    // island near the branches that use it. Anything else falls back to the first block.
    let thunk_id = if part_id == config.primary_function_part_id {
        object_layout.thunk_block_id
    } else {
        crate::thunks::ThunkBlockId::FIRST
    };

    let thunk_address = layout
        .thunk_block_addresses
        .get(thunk_id.as_usize())
        .and_then(|addresses| addresses.get(&canonical_id))
        .copied();

    let Some(thunk_address) = thunk_address else {
        bail!(
            "Branch to {} is out of range and no thunk was reserved for it",
            layout.symbol_db.symbol_name_for_display(local_symbol_id)
        );
    };

    ensure!(
        thunk_address != 0,
        "Thunk address not yet allocated for {}",
        layout.symbol_db.symbol_name_for_display(local_symbol_id)
    );

    Ok(Some(thunk_address))
}

/// Writes the branch islands this object is responsible for.
fn write_thunks<A: Arch<Platform = MachO>>(
    object: &ObjectLayout<'_, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'_>,
) -> Result {
    if !object.owns_thunk_block {
        return Ok(());
    }

    let Some(addresses) = layout
        .thunk_block_addresses
        .get(object.thunk_block_id.as_usize())
    else {
        return Ok(());
    };

    if addresses.is_empty() {
        return Ok(());
    }

    let config = A::thunk_config().context("Thunks were reserved without a thunk config")?;
    let thunk_size = config.thunk_size as usize;
    let buffer = buffers.get_mut(config.primary_function_part_id);

    for (&symbol_id, &thunk_address) in addresses {
        let resolution = layout
            .merged_symbol_resolution(symbol_id)
            .with_context(|| {
                format!(
                    "Thunk target {} has no resolution",
                    layout.symbol_db.symbol_name_for_display(symbol_id)
                )
            })?;

        let thunk = buffer
            .split_off_mut(..thunk_size)
            .ok_or_else(|| error!("Insufficient space reserved for branch islands"))?;

        A::write_thunk(thunk_address, resolution.raw_value, thunk);
    }

    Ok(())
}

/// Numbers the output sections the way a symbol table entry has to refer to them: by position among
/// the sections actually emitted, counting from one.
///
/// This can't be worked out by walking the output order and counting, because the order contains
/// sections that don't reach the output - a segment with nothing in it is dropped entirely, and its
/// sections go with it, but they still sit in the order. Counting them shifted every later
/// section's number past the end of the section list, and a symbol naming a section that doesn't
/// exist is malformed: tools stop reading the symbol table at that point, which loses every symbol
/// after it.
///
/// Taking the sections from `get_segment_sections`, in the order `write_segment_commands` emits the
/// segments, is what makes this agree with the section list by construction.
fn build_section_index_map(layout: &MachOLayout<'_>) -> Result<OutputSectionMap<u8>> {
    let mut map = layout.output_sections.new_section_map::<u8>();
    let mut index: u8 = 1;

    for segment_type in [
        SegmentType::TextSections,
        SegmentType::DataSections,
        SegmentType::DataConstSections,
    ] {
        let Some(info) = get_segment_sections(layout, segment_type) else {
            continue;
        };

        for section_id in info.section_ids {
            *map.get_mut(section_id) = index;
            index = index
                .checked_add(1)
                .ok_or_else(|| error!("More than 255 output sections"))?;
        }
    }

    Ok(map)
}
