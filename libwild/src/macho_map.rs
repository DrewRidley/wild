//! The link map: a plain-text account of what ended up where.
//!
//! `-map` asks for a file listing the inputs, the sections and every symbol with its address and
//! size. Nothing reads it at run time - it exists so that a person, or a size-analysis tool, can
//! answer "what is taking up the space" and "which object did this come from" without picking the
//! binary apart. Build systems ask for it routinely, and until it was accepted the link failed.

use crate::error::Result;
use crate::input_data::FileId;
use crate::layout::FileLayout;
use crate::macho::MachO;
use crate::macho::SegmentType;
use crate::macho::get_segment_sections;
use crate::platform::ObjectFile as _;
use hashbrown::HashMap;
use std::fmt::Write as _;
use std::path::Path;

/// The segments whose sections are worth listing, and the names they carry in the output.
const MAPPED_SEGMENTS: &[(SegmentType, &str)] = &[
    (SegmentType::TextSections, "__TEXT"),
    (SegmentType::DataConstSections, "__DATA_CONST"),
    (SegmentType::DataSections, "__DATA"),
];

/// The byte order everything Mach-O we produce is in.
const E: object::Endianness = object::Endianness::Little;

/// Writes the link map for a finished layout.
pub(crate) fn write_link_map(layout: &crate::layout::Layout<'_, MachO>, path: &Path) -> Result {
    let mut out = String::new();

    writeln!(out, "# Path: {}", layout.args().common.output.display())?;
    writeln!(out, "# Arch: arm64")?;

    // The inputs, numbered, because every symbol below names the one it came from by index. Index
    // zero is what the linker made up rather than read: the header, the stubs, the tables.
    //
    // Only the objects are listed. ld64 also numbers the libraries, so that it can attribute the
    // stubs and GOT slots it synthesises for them; we don't list those symbols, so naming their
    // libraries here would be an index nothing points at.
    writeln!(out, "# Object files:")?;
    writeln!(out, "[  0] linker synthesized")?;

    let mut file_indices: HashMap<FileId, usize> = HashMap::new();
    let mut next_index = 1;

    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(object) = file else {
                continue;
            };

            writeln!(out, "[{next_index:3}] {}", object.input)?;
            file_indices.insert(object.file_id, next_index);
            next_index += 1;
        }
    }

    writeln!(out, "# Sections:")?;
    writeln!(out, "# Address\tSize    \tSegment\tSection")?;

    for (segment_type, segment_name) in MAPPED_SEGMENTS {
        let Some(info) = get_segment_sections(layout, *segment_type) else {
            continue;
        };

        for (size, section_name, _) in &info.segment_sections {
            let Some(section_name) = section_name else {
                continue;
            };

            writeln!(
                out,
                "0x{:X}\t0x{:08X}\t{segment_name}\t{}",
                size.mem_offset,
                size.mem_size,
                String::from_utf8_lossy(section_name.0)
            )?;
        }
    }

    writeln!(out, "# Symbols:")?;
    writeln!(out, "# Address\tSize    \tFile  Name")?;

    let mut symbols = Vec::new();

    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(object) = file else {
                continue;
            };

            let index = file_indices.get(&object.file_id).copied().unwrap_or(0);

            for (symbol_index, symbol) in object.object.enumerate_symbols() {
                let symbol_id = object.symbol_id_range.input_to_id(symbol_index);

                let Some(resolution) = layout.local_symbol_resolution(symbol_id) else {
                    continue;
                };

                let address = resolution.value_for_symbol_table();

                if address == 0 {
                    continue;
                }

                // The size is the atom's, which with one function or datum per atom is that
                // function's. A symbol that isn't at the start of its atom is a label inside
                // something else and has no size of its own.
                let size = object
                    .object
                    .symbol_section(symbol, symbol_index)?
                    .filter(|section_index| {
                        object
                            .object
                            .section(*section_index)
                            .is_ok_and(|section| section.addr.get(E) == symbol.n_value.get(E))
                    })
                    .and_then(|section_index| {
                        object
                            .object
                            .section(section_index)
                            .ok()
                            .map(|section| section.size.get(E))
                    })
                    .unwrap_or(0);

                let name = object.object.symbol_name(symbol)?;

                symbols.push((address, size, index, name));
            }
        }
    }

    symbols.sort_unstable_by_key(|(address, ..)| *address);

    for (address, size, index, name) in symbols {
        writeln!(
            out,
            "0x{address:X}\t0x{size:08X}\t[{index:3}] {}",
            String::from_utf8_lossy(name)
        )?;
    }

    std::fs::write(path, out)
        .map_err(|error| crate::error!("Failed to write link map `{}`: {error}", path.display()))?;

    Ok(())
}
