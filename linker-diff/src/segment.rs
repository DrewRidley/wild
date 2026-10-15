use crate::header_diff::Converter;
use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use anyhow::Ok;
use anyhow::Result;
use anyhow::bail;
use linker_utils::elf::pt;
use object::Object;
use object::elf::PT_LOAD;
use object::read::elf::ProgramHeader as _;
use object::read::macho::LoadCommandVariant;

pub(crate) fn report_diffs(report: &mut crate::Report, objects: &[crate::Binary]) {
    if !report.require_format("segment", objects, &["elf", "macho"]) {
        return;
    }
    report.add_diffs(crate::header_diff::diff_fields(
        objects,
        read_program_segment_fields,
        "segment",
        DiffMode::Normal,
    ));
}

fn read_program_segment_fields(object: &crate::Binary) -> Result<FieldValues> {
    let e = object.file.endianness();
    let mut values = FieldValues::default();

    match object.file {
        object::File::Elf64(elf_file) => {
            for segment in elf_file.elf_program_headers() {
                let p_type = segment.p_type(e);
                let p_flags = segment.p_flags(e);
                let p_align = segment.p_align(e);

                if p_type == PT_LOAD {
                    let mut flag_str = String::new();
                    if p_flags.contains(object::elf::PF_R) {
                        flag_str.push('R');
                    }
                    if p_flags.contains(object::elf::PF_W) {
                        flag_str.push('W');
                    }
                    if p_flags.contains(object::elf::PF_X) {
                        flag_str.push('X');
                    }

                    values.insert(
                        format!("LOAD.{flag_str}.alignment"),
                        p_align,
                        Converter::None,
                        object,
                    );
                } else {
                    let segment_type = pt::Display(p_type);

                    values.insert(
                        format!("{segment_type}.alignment"),
                        p_align,
                        Converter::None,
                        object,
                    );
                    values.insert(
                        format!("{segment_type}.flags"),
                        p_flags.0,
                        Converter::None,
                        object,
                    );
                }
            }
        }
        object::File::MachO64(macho_file) => {
            read_macho_segment_fields(macho_file, e, &mut values)?;
        }
        other => bail!(
            "read_program_segment_fields has no implementation for `{}`",
            crate::file_format_name(other)
        ),
    }

    Ok(values)
}

/// Reads `LC_SEGMENT_64` load commands. Written from the `segment_command_64` layout in
/// `<mach-o/loader.h>`, via the `object` crate's read side.
///
/// Everything here is keyed by **segment name**, never by segment index. Wild and ld64 legitimately
/// emit `__DATA` and `__DATA_CONST` in opposite orders, so an index-keyed comparison would report a
/// difference on every single binary and would have to be ignored, which would take the real
/// content of this pass down with it.
///
/// Likewise, no absolute address appears in any value: `__DATA` lives at a different vmaddr in each
/// linker's output and both are correct. What is compared is what a *loader* cares about:
/// protections, the file-backed vs zero-filled split, and page alignment.
fn read_macho_segment_fields(
    macho_file: &object::read::macho::MachOFile64<'_, object::Endianness>,
    endian: object::Endianness,
    values: &mut FieldValues,
) -> Result<()> {
    let mut load_commands = macho_file.macho_load_commands()?;

    while let Some(load_command) = load_commands.next()? {
        let LoadCommandVariant::Segment64(segment, _sections) = load_command.variant()? else {
            continue;
        };

        let name = String::from_utf8_lossy(
            segment
                .segname
                .split(|b| *b == 0)
                .next()
                .unwrap_or(&segment.segname),
        )
        .into_owned();

        let vmaddr = segment.vmaddr.get(endian);
        let vmsize = segment.vmsize.get(endian);
        let filesize = segment.filesize.get(endian);

        values.insert_string_owned(
            format!("{name}.initprot"),
            format_vm_prot(segment.initprot.get(endian).0),
        );
        values.insert_string_owned(
            format!("{name}.maxprot"),
            format_vm_prot(segment.maxprot.get(endian).0),
        );
        values.insert_string_owned(
            format!("{name}.nsects"),
            segment.nsects.get(endian).to_string(),
        );
        values.insert_string_owned(
            format!("{name}.flags"),
            format!("0x{:x}", segment.flags.get(endian).0),
        );

        // How many bytes a segment is padded out to is a layout choice (ld64 rounds __LINKEDIT's
        // vmsize up to a page, Wild doesn't), so the byte count itself isn't comparable. What is
        // comparable is whether the segment is well-formed at all: a vmsize below filesize means
        // dyld would map less than the file contains.
        values.insert_string_owned(
            format!("{name}.vmsize-vs-filesize"),
            if vmsize < filesize {
                format!("INVALID: vmsize 0x{vmsize:x} < filesize 0x{filesize:x}")
            } else {
                "OK".to_owned()
            },
        );

        // Segments must start on a page boundary or dyld can't map them. 16KiB is the arm64 page
        // size; x86_64 macOS uses 4KiB, so accept either rather than hard-coding the host's.
        values.insert_string_owned(
            format!("{name}.vmaddr-page-aligned"),
            if vmaddr.is_multiple_of(0x4000) {
                "16k".to_owned()
            } else if vmaddr.is_multiple_of(0x1000) {
                "4k".to_owned()
            } else {
                format!("MISALIGNED (0x{vmaddr:x})")
            },
        );
    }

    Ok(())
}

/// Renders a `vm_prot_t` the way `otool -l` does.
fn format_vm_prot(prot: u32) -> String {
    let mut out = String::new();
    out.push(if prot & 0x1 != 0 { 'r' } else { '-' });
    out.push(if prot & 0x2 != 0 { 'w' } else { '-' });
    out.push(if prot & 0x4 != 0 { 'x' } else { '-' });
    out
}
