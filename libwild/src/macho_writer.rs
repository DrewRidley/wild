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
use crate::macho::EntryPointCommand;
use crate::macho::FileHeader;
use crate::macho::GOT_ENTRY_SIZE;
use crate::macho::MACHO_COMMAND_ALIGNMENT;
use crate::macho::MACHO_START_MEM_ADDRESS;
use crate::macho::MAX_SEGMENT_COUNT;
use crate::macho::MachO;
use crate::macho::PLT_ENTRY_SIZE;
use crate::macho::PROGRAM_SEGMENT_DEFS;
use crate::macho::SEG_DATA_CONST;
use crate::macho::SectionEntry;
use crate::macho::SegmentCommand;
use crate::macho::SegmentSectionsInfo;
use crate::macho::SegmentType;
use crate::macho::SymtabCommand;
use crate::macho::UuidCommand;
use crate::macho::code_signature_identifier;
use crate::macho::code_signature_padded_identifier_size;
use crate::macho::get_segment_sections;
use crate::macho::load_dylib_command_size;
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
use itertools::Itertools;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationSize;
use linker_utils::utils::slice_from_all_bytes_mut;
use object::BigEndian;
use object::Endianness;
use object::SymbolIndex;
use object::from_bytes_mut;
use object::macho;
use object::macho::CPU_SUBTYPE_ARM64_ALL;
use object::macho::CPU_TYPE_ARM64;
use object::macho::LC_BUILD_VERSION;
use object::macho::LC_CODE_SIGNATURE;
use object::macho::LC_DYLD_CHAINED_FIXUPS;
use object::macho::LC_LOAD_DYLIB;
use object::macho::LC_LOAD_DYLINKER;
use object::macho::LC_MAIN;
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
    warn_if_unwind_info_needed(layout);
    reject_incomplete_thread_locals(layout)?;

    let (mut section_buffers, mut padding) =
        split_output_into_sections(layout, &mut sized_output.out);
    padding.fill_zero();

    // Addresses of pointer-sized slots that hold an address within this image. Each one needs a
    // rebase entry in the chained-fixup table, otherwise dyld leaves the link-time address in
    // place and the program dereferences an address that hasn't been slid by the load bias.
    // They're discovered while relocations are applied, which happens in parallel, so each group
    // accumulates its own list and merges it in once.
    let rebase_addresses = Mutex::new(Vec::new());

    let mut writable_buckets = split_buffers_by_alignment(&mut section_buffers, layout);
    let groups_and_buffers = split_output_by_group(layout, &mut writable_buckets);
    groups_and_buffers
        .into_par_iter()
        .try_for_each(|(group, mut buffers)| -> Result {
            verbose_timing_phase!("Write group");

            let mut symbol_writer = MachOSymbolTableWriter {
                next_strtab_offset: group.strtab_start_offset,
            };
            let mut group_rebases = Vec::new();
            for file in &group.files {
                write_file::<A>(
                    file,
                    &mut buffers,
                    layout,
                    &sized_output.trace,
                    &mut symbol_writer,
                    &mut group_rebases,
                )
                .with_context(|| format!("Failed copying from {file} to output file"))?;
            }
            if !group_rebases.is_empty() {
                rebase_addresses
                    .lock()
                    .expect("Rebase list mutex was poisoned")
                    .append(&mut group_rebases);
            }
            Ok(())
        })?;

    let mut section_buffers = split_output_into_sections(layout, &mut sized_output.out).0;
    write_got_entries(layout, section_buffers.get_mut(output_section_id::GOT))?;
    write_plt_entries::<A>(layout, section_buffers.get_mut(output_section_id::PLT_GOT))?;
    drop(section_buffers);

    let rebase_addresses = rebase_addresses
        .into_inner()
        .expect("Rebase list mutex was poisoned");
    write_chained_fixups(layout, sized_output, rebase_addresses)?;

    write_code_signature_metadata(layout, sized_output)?;
    write_uuid(layout, sized_output)?;
    write_code_signature_hashes(layout, sized_output)?;

    Ok(())
}

/// Warns when the output contains exception-handling tables but no `__TEXT,__unwind_info`.
///
/// We don't synthesise `__unwind_info` from the `__LD,__compact_unwind` sections in the input yet.
/// For most code that only costs you backtraces, but as soon as something throws, libunwind has no
/// way to find the personality routine or the landing pads and the process calls `terminate`. The
/// presence of `__gcc_except_tab` is what distinguishes "unwinding would be nice" from "this binary
/// is going to abort", so only warn for the latter - otherwise every single link would warn, since
/// clang emits `__compact_unwind` even for trivial C.
fn warn_if_unwind_info_needed(layout: &MachOLayout<'_>) {
    let except_tab = layout
        .section_layouts
        .get(output_section_id::GCC_EXCEPT_TABLE);

    if except_tab.mem_size > 0 {
        layout.args().warning(
            "emitting a binary with exception-handling tables but no __unwind_info: \
             wild cannot build __unwind_info from __compact_unwind yet, so throwing an \
             exception will call terminate",
        );
    }
}

/// Fails the link when the output contains thread-local variables.
///
/// The addressing side of thread-local storage works: `__thread_vars`, `__thread_data` and
/// `__thread_bss` are laid out into `__DATA`, and the TLVP relocation pair relaxes to a direct
/// reference to the descriptor exactly as ld64 does. What is missing is the descriptor contents.
/// Each `tlv_descriptor` needs its first word bound to `__tlv_bootstrap` in libSystem, and its
/// third word holding the variable's offset within the thread-local block rather than an address -
/// we currently emit a rebase for both, so the binary builds and then takes SIGBUS on first use.
///
/// Refusing to write the file keeps that from looking like a working link. Remove this once the
/// descriptors are filled in properly.
fn reject_incomplete_thread_locals(layout: &MachOLayout<'_>) -> Result {
    let thread_vars = layout.section_layouts.get(output_section_id::THREAD_VARS);

    ensure!(
        thread_vars.mem_size == 0,
        "thread-local variables are not supported yet: the __thread_vars descriptors would need \
         binding to __tlv_bootstrap and a thread-block offset, and wild does not emit either yet"
    );

    Ok(())
}

fn write_file<'data, A: Arch<Platform = MachO>>(
    file: &FileLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    _trace: &TraceOutput,
    symbol_writer: &mut MachOSymbolTableWriter,
    rebase_addresses: &mut Vec<u64>,
) -> Result {
    match file {
        FileLayout::Object(s) => {
            write_object::<A>(s, buffers, layout, symbol_writer, rebase_addresses)?;
        }
        FileLayout::Prelude(s) => write_prelude(s, buffers, layout)?,
        _ => {
            // TODO
        }
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
    debug_assert_eq!(
        prelude.format_specific.imported_library_file_ids.len(),
        prelude.format_specific.load_dylib_command_sizes.len()
    );

    let header_buffer = buffers.get_mut(part_id::FILE_HEADER);
    populate_file_header(layout, prelude, take_mut(header_buffer)?)?;
    ensure!(header_buffer.is_empty(), "Excess FILE_HEADER allocation");

    let mut load_command_buffer = slice_from_all_bytes_mut(buffers.get_mut(part_id::LOAD_COMMANDS));
    write_segment_commands(layout, &mut load_command_buffer)?;

    write_entry_point_command(layout, take_mut(&mut load_command_buffer)?)?;

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

        write_dylib_command(dylib_command, command_buffer, path);
    }

    write_dyld_chained_fixups_command(layout, take_mut(&mut load_command_buffer)?);

    write_symtab_command(layout, take_mut(&mut load_command_buffer)?);

    write_code_signature_command(layout, take_mut(&mut load_command_buffer)?);

    ensure!(
        load_command_buffer.is_empty(),
        "Excess LOAD_COMMANDS allocation"
    );

    // Fill up one extra character as n_strx == 0 is treated as unnamed.
    buffers.get_mut(part_id::STRTAB).fill(0);

    Ok(())
}

fn write_got_entries(layout: &MachOLayout<'_>, got: &mut [u8]) -> Result {
    let got_layout = layout.section_layouts.get(output_section_id::GOT);

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
    header.filetype.set(LE, MH_EXECUTE);
    header
        .ncmds
        .set(LE, prelude.format_specific.load_command_count as u32);
    header
        .sizeofcmds
        .set(LE, load_commands_info.segment_size.file_size as u32);
    let mut flags = macho::MH_PIE | macho::MH_DYLDLINK | macho::MH_NOUNDEFS | macho::MH_TWOLEVEL;

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

fn write_segment_commands(layout: &MachOLayout, load_commands: &mut &mut [u8]) -> Result {
    let load_cmd_err = |()| error!("Invalid LOAD_COMMANDS allocation");
    let pagezero_segment = take_mut(load_commands)?;
    write_segment(
        SEG_PAGEZERO,
        macho::VmProt(0),
        pagezero_segment,
        0,
        0,
        0,
        MACHO_START_MEM_ADDRESS,
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
    write_sections(SEG_TEXT, text_sections, &text_segment_sections)?;

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
        write_sections(SEG_DATA, data_sections, &data_segment_sections)?;
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
        section.offset.set(LE, size.file_offset as u32);
        section.align.set(LE, u32::from(size.alignment.exponent));
        section.reloff.set(LE, 0);
        section.nreloc.set(LE, 0);
        section.flags.set(LE, *section_flags);
        section.reserved1.set(LE, 0);
        // TODO: find a better place
        let reserved2 =
            if section_flags.0 & macho::SECTION_TYPE == u32::from(macho::S_SYMBOL_STUBS.0) {
                PLT_ENTRY_SIZE as u32
            } else {
                0
            };
        section.reserved2.set(LE, reserved2);
        section.reserved3.set(LE, 0);
    }

    Ok(())
}

fn write_object<'data, A: Arch<Platform = MachO>>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    symbol_writer: &mut MachOSymbolTableWriter,
    rebase_addresses: &mut Vec<u64>,
) -> Result {
    verbose_timing_phase!("Write object", file_id = object.file_id.as_u32());

    let _span = debug_span!("write_file", filename = %object.input).entered();
    let _file_span = layout.args().common().trace_span_for_file(object.file_id);
    for (i, sec) in object.sections.iter().enumerate() {
        match sec {
            SectionSlot::Loaded(sec) => {
                write_object_section::<A>(
                    object,
                    layout,
                    *sec,
                    object::SectionIndex(i),
                    buffers,
                    rebase_addresses,
                )?;
            }
            _ => (),
        }
    }

    write_symbols(object, buffers, layout, symbol_writer)?;

    Ok(())
}

fn write_object_section<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout<'data>,
    section: Section,
    section_index: object::SectionIndex,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    rebase_addresses: &mut Vec<u64>,
) -> Result {
    let out = write_section_raw(object_layout, layout, section, section_index, buffers)?;

    let section_address = object_layout.section_resolutions[section_index.0]
        .address()
        .context("Attempted to apply relocations to a section that we didn't load")?;

    for rel in object_layout.relocations(section_index)?.relocations {
        apply_relocation::<A>(
            object_layout,
            section_address,
            rel.info(LE),
            layout,
            out,
            rebase_addresses,
        )?;
    }

    Ok(())
}

#[inline(always)]
fn apply_relocation<'data, A: Arch<Platform = MachO>>(
    object_layout: &ObjectLayout<'data, MachO>,
    section_address: u64,
    rel: RelocationInfo,
    layout: &MachOLayout<'data>,
    out: &mut [u8],
    rebase_addresses: &mut Vec<u64>,
) -> Result {
    let offset_in_section = u64::from(rel.r_address);
    let place = section_address + offset_in_section;

    let _span = tracing::trace_span!(
        "relocation",
        address = place,
        address_hex = %HexU64::new(place)
    )
    .entered();

    let rel_info = A::relocation_from_raw(rel)?;
    let (resolution, _symbol_index, local_symbol_id) = get_resolution(rel, object_layout, layout)?;
    let flags = layout.flags_for_symbol(local_symbol_id);

    // Layout only gives a `__got` slot to symbols whose address isn't known until dyld binds them.
    // A GOT-style relocation against anything else has to be turned into a direct reference, which
    // means rewriting the instruction as well as computing a different value for it. Keying this
    // off the resolution rather than off the flags means the writer can't disagree with whatever
    // layout decided (see `macho::Indirection`).
    if matches!(
        rel_info.kind,
        RelocationKind::Got | RelocationKind::GotRelative
    ) && resolution.format_specific.got_address.is_none()
    {
        A::relax_got_load(rel, &mut out[offset_in_section as usize..]).with_context(|| {
            format!(
                "Failed to relax {} against {}",
                A::rel_type_to_string(rel),
                layout.symbol_debug(local_symbol_id)
            )
        })?;
    }

    let mask = get_page_mask(rel_info.mask);
    let value = match rel_info.kind {
        RelocationKind::Absolute => resolution.raw_value.bitand(mask.symbol_plus_addend),
        RelocationKind::AbsoluteLowPart => resolution.raw_value.bitand(mask.symbol_plus_addend),
        RelocationKind::Relative => resolution
            .raw_value
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::GotRelative => resolution
            .raw_value
            .bitand(mask.symbol_plus_addend)
            .wrapping_sub(place.bitand(mask.place)),
        RelocationKind::Got => resolution.raw_value.bitand(mask.symbol_plus_addend),
        _ => todo!(),
    };

    tracing::trace!(
            %flags,
            ?rel_info.kind,
            %rel_info.size,
            value,
            value_hex = %HexU64::new(value),
            symbol_name = %layout.symbol_db.symbol_name_for_display(local_symbol_id),
            "relocation applied");

    // A pointer-sized absolute reference to an address inside this image is written as the
    // link-time address, which is only correct if dyld happens to load us at our preferred
    // address. Record the slot so that a rebase fixup gets emitted for it; dyld then adds the
    // load bias when it walks the chain. Absolute symbols (`N_ABS`) name a fixed value rather
    // than a place in the image, so they must not be slid, and a resolution of zero is an
    // undefined weak reference, which stays null.
    if rel_info.kind == RelocationKind::Absolute
        && rel_info.size == RelocationSize::ByteSize(size_of::<u64>())
        && !flags.is_absolute()
        && value != 0
    {
        rebase_addresses.push(place);
    }

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

fn write_section_raw<'out, 'data>(
    object: &ObjectLayout<'data, MachO>,
    layout: &MachOLayout,
    sec: Section,
    section_index: object::SectionIndex,
    buffers: &'out mut OutputSectionPartMap<&mut [u8]>,
) -> Result<&'out mut [u8]> {
    let part_id = object.section_part_id(section_index, &layout.symbol_db.section_part_ids);
    if layout
        .output_sections
        .has_data_in_file(part_id.output_section_id())
    {
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
        let out = section_buffer.split_off_mut(..allocation_size).unwrap();
        let object_section = object.object.section(section_index)?;

        let section_size = object.object.section_size(object_section)?;
        let (out, padding) = out.split_at_mut(section_size as usize);
        object.object.copy_section_data(object_section, out)?;
        padding.fill(0);
        Ok(out)
    } else {
        Ok(&mut [])
    }
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
    command.stacksize.set(LE, 0);

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

fn write_dylib_command(command: &mut DylibCommand, path_buffer: &mut [u8], path: &[u8]) {
    command.cmd.set(LE, LC_LOAD_DYLIB);
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
    // TODO
    command
        .dylib
        .current_version
        .set(LE, macho::Version(1356 << 16));
    command
        .dylib
        .compatibility_version
        .set(LE, macho::Version(1 << 16));

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
    let symtab = layout.section_layouts.get(output_section_id::SYMTAB_GLOBAL);
    let strtab = layout.section_layouts.get(output_section_id::STRTAB);

    command.cmd.set(LE, LC_SYMTAB);
    command.cmdsize.set(LE, size_of::<SymtabCommand>() as u32);
    command.symoff.set(LE, symtab.file_offset as u32);

    let mut nsyms = (symtab.file_size / size_of::<SymtabEntry>()) as u32;

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

/// Width of the `name_offset` field of a `dyld_chained_import`.
const CHAINED_IMPORT_NAME_OFFSET_BITS: u32 = 23;

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
    rebase_addresses: Vec<u64>,
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
        .chain(rebase_addresses.into_iter().map(|address| FixupSite {
            address,
            is_bind: false,
        }))
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
                "Chained fixup at address 0x{:x} isn't aligned to the chain stride",
                site.address
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
                let target = existing.checked_sub(image_base).with_context(|| {
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

                target | (next << CHAINED_PTR_NEXT_SHIFT)
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

        blob.extend_from_slice(&(u32::from(lib_ordinal) | (symbol_offset << 9)).to_le_bytes());
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

struct MachOSymbolTableWriter {
    next_strtab_offset: u32,
}

impl MachOSymbolTableWriter {
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
        let entry = self.write_entry(name, buffers)?;
        entry.n_sect = section;
        entry.n_type = symbol_type;
        entry.n_value.set(LE, value);
        entry.n_desc.set(LE, desc);

        Ok(())
    }

    fn write_entry<'out>(
        &mut self,
        name: &[u8],
        buffers: &'out mut OutputSectionPartMap<&mut [u8]>,
    ) -> Result<&'out mut SymtabEntry> {
        let string_offset = self.write_str(name, buffers);
        let entry_bytes = buffers
            .get_mut(part_id::SYMTAB_GLOBAL)
            .split_off_mut(..size_of::<SymtabEntry>())
            .unwrap();
        let entry: &mut SymtabEntry = from_bytes_mut(entry_bytes)
            .map_err(|_| error!("Invalid SYMTAB_GLOBAL entry allocation"))?
            .0;
        entry.n_strx.set(LE, string_offset);
        Ok(entry)
    }
}

fn write_symbols<'data>(
    object: &ObjectLayout<'data, MachO>,
    buffers: &mut OutputSectionPartMap<&mut [u8]>,
    layout: &MachOLayout<'data>,
    symbol_writer: &mut MachOSymbolTableWriter,
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
                    SectionSlot::Loaded(_) => object
                        .section_part_id(section_index, &layout.symbol_db.section_part_ids)
                        .output_section_id(),
                    _ => bail!(
                        "Tried to copy a symbol in a section we didn't load. {}",
                        layout.symbol_debug(symbol_id)
                    ),
                };
                let primary_id = layout.output_sections.primary_output_section(section_id);
                let n_type = sym.n_type.with_type(N_SECT);
                let n_sect = macho_section_index(layout, primary_id).with_context(|| {
                    format!(
                        "No Mach-O section index for {} while writing {}",
                        primary_id,
                        layout.symbol_debug(symbol_id)
                    )
                })?;
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

    Ok(())
}

// TODO: This is inefficient; simplify it once load commands use a table allocator instead of
// being modeled as a section.
fn macho_section_index(
    layout: &MachOLayout<'_>,
    section_id: output_section_id::OutputSectionId,
) -> Result<u8> {
    // The section index is one-based.
    let mut section_idx = 1u8;
    let mut in_section_segment = false;
    for event in &layout.output_order {
        match event {
            output_section_id::OrderEvent::SegmentStart(segment_id) => {
                let segment_type = layout.program_segments.segment_def(segment_id).segment_type;
                // TODO: Right now, the various load commands are mapped as "sections", so we can't
                // just take the mapped index of the output "section".
                in_section_segment = matches!(
                    segment_type,
                    SegmentType::TextSections
                        | SegmentType::DataSections
                        | SegmentType::DataConstSections
                );
            }
            output_section_id::OrderEvent::SegmentEnd(_) => {
                in_section_segment = false;
            }
            output_section_id::OrderEvent::Section(current) if in_section_segment => {
                if current == section_id {
                    return Ok(section_idx);
                }
                section_idx = section_idx
                    .checked_add(1)
                    .ok_or(error!("Section index out of range (u8)"))?;
            }
            _ => {}
        }
    }

    bail!("cannot find the output section")
}
