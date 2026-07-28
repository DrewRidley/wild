//! The debug map: how a linked Mach-O image says where its debug info went.
//!
//! Mach-O doesn't gather DWARF into the linked image the way ELF does. The debug info stays in the
//! object files, and the image carries only a map back to them, written as stabs in the symbol
//! table: which object each function came from, and where that function ended up. `dsymutil` reads
//! the map, opens each object named by an `N_OSO` stab, and relocates its DWARF into a `.dSYM`
//! bundle; `lldb` does the same thing on the fly. Without the map there is no path from an address
//! back to the source, so a `-g` link produces something that can't be debugged - the DWARF is
//! sitting in the `.o` files with nothing to say so.
//!
//! The shape, per object, is:
//!
//! ```text
//! SO    ""                     the map for one object begins
//! SO    "/path/to/dir/"        where the compiler was run
//! SO    "source.c"             what it was compiling
//! OSO   "/path/to/object.o"    the object itself, its mtime in n_value
//!   BNSYM / FUN name / FUN size / ENSYM      once per function
//!   GSYM name                                once per global variable
//!   STSYM name                               once per file-scoped variable
//! SO    ""                     and ends
//! ```

use crate::error::Result;
use crate::platform::ObjectFile as _;
use object::macho;
use object::read::macho::Section as _;
use std::borrow::Cow;

/// `N_SO`: the source file a run of stabs came from, and with an empty name, the end of that run.
pub(crate) const N_SO: u8 = 0x64;
/// `N_OSO`: the object file to go and read the debug info from.
pub(crate) const N_OSO: u8 = 0x66;
/// `N_FUN`: a function, then its length in a second entry with no name.
pub(crate) const N_FUN: u8 = 0x24;
/// `N_BNSYM` and `N_ENSYM`: the bounds of the function between them.
pub(crate) const N_BNSYM: u8 = 0x2e;
pub(crate) const N_ENSYM: u8 = 0x4e;
/// `N_GSYM`: a variable with external linkage. Its address is left at zero - `dsymutil` finds it
/// from the ordinary symbol of the same name.
pub(crate) const N_GSYM: u8 = 0x20;
/// `N_STSYM`: a variable with internal linkage, which has no such symbol, so this carries the
/// address itself.
pub(crate) const N_STSYM: u8 = 0x26;

/// What one object contributes to the debug map, other than its functions and variables.
pub(crate) struct ObjectDebugInfo {
    /// The directory the compiler was invoked in, with the trailing separator ld64 writes.
    pub(crate) directory: Vec<u8>,

    /// The source file, as the compile unit names it.
    pub(crate) file_name: Vec<u8>,
}

/// Reads the source file a compile unit describes, or `None` if the object carries no DWARF.
///
/// Only the first compile unit is read. An object built from one translation unit has exactly one,
/// which is what a debug map entry describes; the rest of the DWARF is `dsymutil`'s to interpret,
/// and it goes back to the object file for it rather than trusting anything here.
pub(crate) fn read_object_debug_info<'data>(
    object: &crate::macho::File<'data>,
) -> Result<Option<ObjectDebugInfo>> {
    if object
        .section_by_name(debug_section_name(gimli::SectionId::DebugInfo))
        .is_none()
    {
        return Ok(None);
    }

    let sections = gimli::DwarfSections::load(|id| -> Result<Cow<'data, [u8]>> {
        let Some((_, section)) = object.section_by_name(debug_section_name(id)) else {
            return Ok(Cow::Borrowed(&[]));
        };

        Ok(Cow::Borrowed(object.raw_section_data(section)?))
    })?;

    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, gimli::LittleEndian));

    let Some(header) = dwarf.units().next()? else {
        return Ok(None);
    };

    let unit = dwarf.unit(header)?;

    let Some(file_name) = unit.name else {
        return Ok(None);
    };

    // ld64 writes the directory with a trailing separator, and `dsymutil` joins the two by
    // concatenation rather than as paths - so the separator has to be here rather than assumed.
    let directory = unit.comp_dir.map_or_else(Vec::new, |dir| {
        let mut dir = dir.slice().to_vec();
        if !dir.ends_with(b"/") {
            dir.push(b'/');
        }
        dir
    });

    Ok(Some(ObjectDebugInfo {
        directory,
        file_name: file_name.slice().to_vec(),
    }))
}

/// Translates a DWARF section name to the way Mach-O spells it: `.debug_info` is `__debug_info`,
/// and the segment it sits in isn't part of the name we match on.
fn debug_section_name(id: gimli::SectionId) -> &'static str {
    match id {
        gimli::SectionId::DebugAbbrev => "__debug_abbrev",
        gimli::SectionId::DebugAddr => "__debug_addr",
        gimli::SectionId::DebugInfo => "__debug_info",
        gimli::SectionId::DebugLine => "__debug_line",
        gimli::SectionId::DebugLineStr => "__debug_line_str",
        gimli::SectionId::DebugStr => "__debug_str",
        // Mach-O section names stop at sixteen bytes, so this one arrives truncated.
        gimli::SectionId::DebugStrOffsets => "__debug_str_offs",
        gimli::SectionId::DebugRngLists => "__debug_rnglists",
        gimli::SectionId::DebugLocLists => "__debug_loclists",
        // Anything else is either absent from Mach-O or not needed to name a compile unit. An
        // empty section is a valid answer to gimli, and reading a name we don't know would be a
        // guess.
        _ => "",
    }
}

/// Whether a symbol in this section describes code, which decides whether it becomes a function
/// stab or a variable one.
pub(crate) fn is_code_section(section: &crate::macho::SectionEntry) -> bool {
    let flags = section.flags(object::Endianness::Little);

    flags.contains(macho::S_ATTR_PURE_INSTRUCTIONS)
        || flags.contains(macho::S_ATTR_SOME_INSTRUCTIONS)
}

/// The stabs one function costs: its bounds, its name and its length.
pub(crate) const STABS_PER_FUNCTION: u64 = 4;

/// The stabs that bracket one object's contribution: three `SO` and one `OSO`, plus the `SO` that
/// closes it.
pub(crate) const STABS_PER_OBJECT: u64 = 5;
