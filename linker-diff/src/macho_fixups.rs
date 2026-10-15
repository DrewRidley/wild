//! Independent reader for `LC_DYLD_CHAINED_FIXUPS`, written from the Mach-O / dyld chained
//! fixups format description. This is an oracle for libwild's Mach-O writer, so it must not
//! import, call or copy anything from `libwild::macho*`.
//!
//! The on-disk layout implemented here is the one documented in dyld's `<mach-o/fixup-chains.h>`:
//!
//! ```text
//! struct dyld_chained_fixups_header {
//!     uint32_t fixups_version;  // 0
//!     uint32_t starts_offset;   // offset of dyld_chained_starts_in_image in chain_data
//!     uint32_t imports_offset;  // offset of imports table in chain_data
//!     uint32_t symbols_offset;  // offset of symbol strings in chain_data
//!     uint32_t imports_count;   // number of imported symbol names
//!     uint32_t imports_format;  // DYLD_CHAINED_IMPORT*
//!     uint32_t symbols_format;  // 0 => uncompressed, 1 => zlib compressed
//! };
//!
//! struct dyld_chained_starts_in_image {
//!     uint32_t seg_count;
//!     uint32_t seg_info_offset[seg_count]; // 0 => segment has no fixups
//! };
//!
//! struct dyld_chained_starts_in_segment {
//!     uint32_t size;
//!     uint16_t page_size;
//!     uint16_t pointer_format;
//!     uint64_t segment_offset;      // offset of segment from the image base
//!     uint32_t max_valid_pointer;
//!     uint16_t page_count;
//!     uint16_t page_start[page_count];
//! };
//! ```
//!
//! The 64-bit chain entries are:
//!
//! ```text
//! rebase: target:36, high8:8, reserved:7, next:12, bind:1(==0)
//! bind:   ordinal:24, addend:8, reserved:19, next:12, bind:1(==1)
//! ```
//!
//! `next` is a count of 4-byte strides; `next == 0` terminates the chain.

use crate::Binary;
use crate::Diff;
use crate::DiffValues;
use crate::Report;
use crate::Result;
use crate::header_diff::ResolvedValue;
use crate::header_diff::diff_array;
use anyhow::Context as _;
use anyhow::bail;
use itertools::Itertools as _;
use object::Object as _;
use object::ObjectSymbol as _;
use object::macho::LC_DYLD_CHAINED_FIXUPS;
use object::read::macho::LoadCommandVariant;
use object::read::macho::Section as _;
use object::read::macho::Segment as _;

// Pointer formats. Only the two used by 64-bit userland images are walked; anything else is
// reported as an error rather than silently ignored.
const DYLD_CHAINED_PTR_64: u16 = 2;
const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;

const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;
const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;

const DYLD_CHAINED_IMPORT: u32 = 1;
const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

/// Maximum number of fixups we will follow before deciding that the chain is malformed. Guards
/// against a corrupt `next` field producing an unbounded loop.
const MAX_FIXUPS: usize = 1_000_000;

/// One fixup that dyld will apply at load time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fixup {
    /// e.g. `__DATA`. Never an index - segment ORDER DIFFERS between wild and ld64.
    pub(crate) segment_name: String,

    /// e.g. `__data`, `__got`. `None` if the address falls in no section.
    pub(crate) section_name: Option<String>,

    /// Absolute VM address of the fixup slot. DISPLAY ONLY - never compared.
    pub(crate) vm_address: u64,

    pub(crate) kind: FixupKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FixupKind {
    /// A pointer that dyld slides by the load bias.
    Rebase {
        /// Absolute VM address of the target. DISPLAY ONLY.
        target_vm_address: u64,

        /// Symbolic description of the target. THIS is what gets compared.
        target_description: String,
    },
    Bind {
        symbol: String,
        lib_ordinal: i64,
        addend: i64,
        weak_import: bool,
    },
}

/// Full parse of the `LC_DYLD_CHAINED_FIXUPS` payload.
pub(crate) struct ChainedFixups {
    /// Sorted by `fixup_comparison_key`. An empty vec means "parsed fine, zero fixups", which is
    /// different from `read_chained_fixups` returning `None`.
    pub(crate) fixups: Vec<Fixup>,

    pub(crate) imports: Vec<String>,

    pub(crate) pointer_format: u16,

    pub(crate) page_size: u32,

    /// One entry per Mach-O segment, in load-command order: whether that segment has any chained
    /// fixups. This is the field that catches wild's missing `__DATA` rebase: wild produces
    /// `[F, F, F, T, F]` where ld64 produces `[F, F, T, T, F]`.
    pub(crate) segments_with_starts: Vec<(String, bool)>,
}

/// A Mach-O segment, as read from the load commands.
struct SegmentInfo {
    name: String,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    sections: Vec<SectionInfo>,
}

struct SectionInfo {
    segment_name: String,
    name: String,
    addr: u64,
    size: u64,
}

/// The bits of the Mach-O image that we need in order to interpret the fixups blob.
pub(crate) struct ImageInfo {
    /// The virtual address that the image is nominally loaded at, i.e. the address of the Mach-O
    /// header. All `segment_offset` and `runtimeOffset` values are relative to this.
    pub(crate) image_base: u64,
    segments: Vec<SegmentInfo>,
    /// Install names of `LC_LOAD_DYLIB` (and friends) commands, in load-command order. The
    /// chained-fixup `lib_ordinal` is a 1-based index into this.
    dylibs: Vec<String>,
    /// The `dataoff`/`datasize` of `LC_DYLD_CHAINED_FIXUPS`, if present.
    fixups_data: Option<(u64, u64)>,
}

pub(crate) fn read_image_info(bin: &Binary) -> Result<ImageInfo> {
    let object::File::MachO64(file) = bin.file else {
        bail!("Not a 64-bit Mach-O file");
    };

    let e = file.endianness();
    let mut load_commands = file.macho_load_commands()?;
    let mut segments = Vec::new();
    let mut dylibs = Vec::new();
    let mut fixups_data = None;

    while let Some(load_command) = load_commands.next()? {
        match load_command.variant()? {
            LoadCommandVariant::Segment64(segment, section_data) => {
                let segment_name = String::from_utf8_lossy(segment.name()).into_owned();

                let sections = segment
                    .sections(e, section_data)?
                    .iter()
                    .map(|section| SectionInfo {
                        segment_name: String::from_utf8_lossy(section.segment_name()).into_owned(),
                        name: String::from_utf8_lossy(section.name()).into_owned(),
                        addr: section.addr(e),
                        size: section.size(e),
                    })
                    .collect();

                segments.push(SegmentInfo {
                    name: segment_name,
                    vmaddr: segment.vmaddr(e),
                    vmsize: segment.vmsize(e),
                    fileoff: segment.fileoff(e),
                    filesize: segment.filesize(e),
                    sections,
                });
            }
            LoadCommandVariant::Dylib(dylib) => {
                let name = load_command.string(e, dylib.dylib.name)?;
                dylibs.push(String::from_utf8_lossy(name).into_owned());
            }
            LoadCommandVariant::LinkeditData(linkedit)
                if linkedit.cmd.get(e) == LC_DYLD_CHAINED_FIXUPS =>
            {
                fixups_data = Some((
                    u64::from(linkedit.dataoff.get(e)),
                    u64::from(linkedit.datasize.get(e)),
                ));
            }
            _ => {}
        }
    }

    // The image base is the address of the mach header. That is the start of the first segment
    // that actually maps file offset 0 - conventionally `__TEXT`. `__PAGEZERO` has filesize 0, so
    // skipping zero-filesize segments finds the right one for both wild and ld64 layouts.
    let image_base = segments
        .iter()
        .find(|segment| segment.filesize > 0 && segment.fileoff == 0)
        .map(|segment| segment.vmaddr)
        .context("Mach-O image has no segment mapping file offset 0")?;

    Ok(ImageInfo {
        image_base,
        segments,
        dylibs,
        fixups_data,
    })
}

impl ImageInfo {
    fn section_containing(&self, address: u64) -> Option<&SectionInfo> {
        self.segments.iter().find_map(|segment| {
            segment
                .sections
                .iter()
                .find(|section| (section.addr..section.addr + section.size).contains(&address))
        })
    }

    fn segment_containing(&self, address: u64) -> Option<&SegmentInfo> {
        self.segments
            .iter()
            .find(|segment| (segment.vmaddr..segment.vmaddr + segment.vmsize).contains(&address))
    }

    /// Converts an ordinal from a bind record into a human-readable library name. Special ordinals
    /// are rendered symbolically. Note that we deliberately render the *basename* of the install
    /// name, since linkers may legitimately record different paths for the same library.
    fn library_name(&self, ordinal: i64) -> String {
        match ordinal {
            0 => "self".to_owned(),
            -1 => "main-executable".to_owned(),
            -2 => "flat-lookup".to_owned(),
            -3 => "weak-lookup".to_owned(),
            n if n > 0 => match self.dylibs.get((n - 1) as usize) {
                Some(name) => install_name_stem(name),
                None => format!("<bad-ordinal-{n}>"),
            },
            n => format!("<bad-ordinal-{n}>"),
        }
    }
}

/// `/usr/lib/libSystem.B.dylib` -> `libSystem`.
fn install_name_stem(install_name: &str) -> String {
    let base = install_name.rsplit('/').next().unwrap_or(install_name);
    let base = base.strip_suffix(".dylib").unwrap_or(base);
    // Strip a compatibility-version suffix like `.B`.
    match base.rsplit_once('.') {
        Some((stem, suffix)) if suffix.len() == 1 && suffix.chars().all(char::is_alphanumeric) => {
            stem.to_owned()
        }
        _ => base.to_owned(),
    }
}

/// Describes `address` in a way that doesn't depend on where the linker chose to put things. If a
/// symbol covers the address then we use `symbol` or `symbol+0xN`. Otherwise we fall back to
/// `__SEG/__sect`. We deliberately do *not* include an offset in the fall-back: linkers may order
/// anonymous entries (e.g. GOT slots) differently and that isn't a bug.
pub(crate) fn describe_address(bin: &Binary, image: &ImageInfo, address: u64) -> String {
    let mut best: Option<(u64, &str)> = None;

    for symbol in bin.file.symbols() {
        if symbol.section_index().is_none() {
            continue;
        }
        let sym_address = symbol.address();
        if sym_address > address {
            continue;
        }
        let Ok(name) = symbol.name() else { continue };
        if name.is_empty() {
            continue;
        }
        // Only consider a symbol if it's in the same section as the address we're describing.
        // Without this, the last symbol of one section would "cover" the start of the next.
        if image.section_containing(sym_address).map(|s| s.addr)
            != image.section_containing(address).map(|s| s.addr)
        {
            continue;
        }
        if best.is_none_or(|(best_address, _)| sym_address > best_address) {
            best = Some((sym_address, name));
        }
    }

    if let Some((sym_address, name)) = best {
        let offset = address - sym_address;
        if offset == 0 {
            return name.to_owned();
        }
        return format!("{name}+{offset:#x}");
    }

    match image.section_containing(address) {
        Some(section) => format!("{}/{}", section.segment_name, section.name),
        None => match image.segment_containing(address) {
            Some(segment) => format!("{}/<no-section>", segment.name),
            None => "<unmapped>".to_owned(),
        },
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .context("Chained fixups: read past end of blob")?;
    Ok(u16::from_le_bytes(bytes.try_into()?))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .context("Chained fixups: read past end of blob")?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .context("Chained fixups: read past end of blob")?;
    Ok(u64::from_le_bytes(bytes.try_into()?))
}

struct Import {
    name: String,
    lib_ordinal: i64,
    addend: i64,
    weak_import: bool,
}

fn read_imports(blob: &[u8], header: &FixupsHeader) -> Result<Vec<Import>> {
    if header.symbols_format != 0 {
        bail!(
            "Chained fixups: unsupported symbols_format {}",
            header.symbols_format
        );
    }

    let symbols_base = usize::try_from(header.symbols_offset)?;
    let imports_base = usize::try_from(header.imports_offset)?;
    let count = usize::try_from(header.imports_count)?;

    let read_name = |name_offset: u64| -> Result<String> {
        let start = symbols_base
            .checked_add(usize::try_from(name_offset)?)
            .context("Chained fixups: symbol name offset overflow")?;
        let tail = blob
            .get(start..)
            .context("Chained fixups: symbol name offset out of range")?;
        let end = tail
            .iter()
            .position(|b| *b == 0)
            .context("Chained fixups: unterminated symbol name")?;
        Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
    };

    let mut imports = Vec::with_capacity(count);

    match header.imports_format {
        DYLD_CHAINED_IMPORT => {
            for i in 0..count {
                let raw = read_u32(blob, imports_base + i * 4)?;
                imports.push(Import {
                    name: read_name(u64::from(raw >> 9))?,
                    lib_ordinal: sign_extend_ordinal(raw & 0xff, 8),
                    addend: 0,
                    weak_import: (raw >> 8) & 1 != 0,
                });
            }
        }
        DYLD_CHAINED_IMPORT_ADDEND => {
            for i in 0..count {
                let raw = read_u32(blob, imports_base + i * 8)?;
                let addend = read_u32(blob, imports_base + i * 8 + 4)? as i32;
                imports.push(Import {
                    name: read_name(u64::from(raw >> 9))?,
                    lib_ordinal: sign_extend_ordinal(raw & 0xff, 8),
                    addend: i64::from(addend),
                    weak_import: (raw >> 8) & 1 != 0,
                });
            }
        }
        DYLD_CHAINED_IMPORT_ADDEND64 => {
            for i in 0..count {
                let raw = read_u64(blob, imports_base + i * 16)?;
                let addend = read_u64(blob, imports_base + i * 16 + 8)? as i64;
                imports.push(Import {
                    name: read_name(raw >> 32)?,
                    lib_ordinal: sign_extend_ordinal(u32::try_from(raw & 0xffff)?, 16),
                    addend,
                    weak_import: (raw >> 16) & 1 != 0,
                });
            }
        }
        other => bail!("Chained fixups: unsupported imports_format {other}"),
    }

    Ok(imports)
}

/// Library ordinals are stored unsigned but the special values (`-1` = main executable, `-2` =
/// flat lookup, `-3` = weak lookup) are encoded as the top of the range.
fn sign_extend_ordinal(raw: u32, bits: u32) -> i64 {
    let raw = i64::from(raw);
    let top = 1i64 << bits;
    if raw >= top - 3 { raw - top } else { raw }
}

struct FixupsHeader {
    starts_offset: u32,
    imports_offset: u32,
    symbols_offset: u32,
    imports_count: u32,
    imports_format: u32,
    symbols_format: u32,
}

/// `Ok(None)` means the binary has no `LC_DYLD_CHAINED_FIXUPS` load command at all. `Err(_)` means
/// the command is present but the payload is malformed. We must never map `Err` to `None` - that
/// would turn a broken linker output into a silent pass.
///
/// Part of the interface other components code against, so it stays public even though
/// `report_diffs` goes via `read_chained_fixups_with_image`.
#[allow(dead_code)]
pub(crate) fn read_chained_fixups(bin: &Binary) -> Result<Option<ChainedFixups>> {
    if !matches!(bin.file, object::File::MachO64(_)) {
        return Ok(None);
    }

    let image = read_image_info(bin)?;
    read_chained_fixups_with_image(bin, &image)
}

#[allow(clippy::too_many_lines)]
fn read_chained_fixups_with_image(
    bin: &Binary,
    image: &ImageInfo,
) -> Result<Option<ChainedFixups>> {
    let Some((dataoff, datasize)) = image.fixups_data else {
        return Ok(None);
    };

    // We need the raw file bytes to read both the LINKEDIT payload and the pointer chains
    // themselves. `Binary` doesn't retain them, so re-read from disk.
    let file_bytes = std::fs::read(&bin.path)
        .with_context(|| format!("Failed to re-read `{}`", bin.path.display()))?;

    let start = usize::try_from(dataoff)?;
    let end = start
        .checked_add(usize::try_from(datasize)?)
        .context("Chained fixups: data range overflow")?;
    let blob = file_bytes
        .get(start..end)
        .context("Chained fixups: LC_DYLD_CHAINED_FIXUPS data range is outside the file")?;

    let fixups_version = read_u32(blob, 0)?;
    if fixups_version != 0 {
        bail!("Chained fixups: unsupported fixups_version {fixups_version}");
    }

    let header = FixupsHeader {
        starts_offset: read_u32(blob, 4)?,
        imports_offset: read_u32(blob, 8)?,
        symbols_offset: read_u32(blob, 12)?,
        imports_count: read_u32(blob, 16)?,
        imports_format: read_u32(blob, 20)?,
        symbols_format: read_u32(blob, 24)?,
    };

    let imports = read_imports(blob, &header)?;

    let starts_base = usize::try_from(header.starts_offset)?;
    let seg_count = usize::try_from(read_u32(blob, starts_base)?)?;

    if seg_count > image.segments.len() {
        bail!(
            "Chained fixups: starts_in_image has {seg_count} segments but the image has {}",
            image.segments.len()
        );
    }

    let mut fixups = Vec::new();
    let mut segments_with_starts = Vec::new();
    let mut pointer_format = 0;
    let mut page_size = 0;

    for seg_index in 0..image.segments.len() {
        let segment = &image.segments[seg_index];

        let seg_info_offset = if seg_index < seg_count {
            usize::try_from(read_u32(blob, starts_base + 4 + seg_index * 4)?)?
        } else {
            0
        };

        if seg_info_offset == 0 {
            segments_with_starts.push((segment.name.clone(), false));
            continue;
        }

        let starts = starts_base
            .checked_add(seg_info_offset)
            .context("Chained fixups: seg_info_offset overflow")?;

        let seg_page_size = u32::from(read_u16(blob, starts + 4)?);
        let seg_pointer_format = read_u16(blob, starts + 6)?;
        let segment_offset = read_u64(blob, starts + 8)?;
        // Layout of dyld_chained_starts_in_segment:
        //   0: size (u32), 4: page_size (u16), 6: pointer_format (u16),
        //   8: segment_offset (u64), 16: max_valid_pointer (u32), 20: page_count (u16),
        //   22: page_start[page_count] (u16)
        let page_count = usize::from(read_u16(blob, starts + 20)?);
        let page_starts = starts + 22;

        pointer_format = seg_pointer_format;
        page_size = seg_page_size;

        if seg_page_size == 0 {
            bail!("Chained fixups: segment `{}` has page_size 0", segment.name);
        }

        // `segment_offset` is relative to the image base. Cross-check it against the segment that
        // this starts record is supposed to describe - if it doesn't match, the seg_info_offsets
        // array is mis-indexed and every address we derive would be wrong.
        let expected_segment_offset = segment
            .vmaddr
            .checked_sub(image.image_base)
            .context("Chained fixups: segment address is below the image base")?;
        if segment_offset != expected_segment_offset {
            bail!(
                "Chained fixups: starts record {seg_index} has segment_offset {segment_offset:#x} \
                 but segment `{}` is at image offset {expected_segment_offset:#x}",
                segment.name
            );
        }

        let mut segment_has_fixups = false;

        for page_index in 0..page_count {
            let page_start = read_u16(blob, page_starts + page_index * 2)?;
            if page_start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }

            let chain_offsets = if page_start & DYLD_CHAINED_PTR_START_MULTI != 0 {
                // The value is an index into an overflow list of chain starts that follows the
                // page_start array. Only used by some 32-bit formats, but handle it anyway.
                let mut list = Vec::new();
                let list_base =
                    page_starts + usize::from(page_start & !DYLD_CHAINED_PTR_START_MULTI) * 2;
                let mut i = 0;
                loop {
                    let entry = read_u16(blob, list_base + i * 2)?;
                    list.push(u64::from(entry & !DYLD_CHAINED_PTR_START_LAST));
                    if entry & DYLD_CHAINED_PTR_START_LAST != 0 {
                        break;
                    }
                    i += 1;
                    if i > page_count {
                        bail!("Chained fixups: runaway multi-start list");
                    }
                }
                list
            } else {
                vec![u64::from(page_start)]
            };

            for chain_offset in chain_offsets {
                let offset_in_segment =
                    (page_index as u64) * u64::from(seg_page_size) + chain_offset;
                segment_has_fixups = true;
                walk_chain(
                    bin,
                    image,
                    &file_bytes,
                    segment,
                    offset_in_segment,
                    seg_pointer_format,
                    &imports,
                    &mut fixups,
                )?;
            }
        }

        segments_with_starts.push((segment.name.clone(), segment_has_fixups));
    }

    fixups.sort_by_cached_key(|fixup| fixup_comparison_key_with_image(fixup, bin, Some(image)));

    let mut import_names = imports
        .iter()
        .map(|import| {
            format!(
                "{}/{}{}",
                image.library_name(import.lib_ordinal),
                import.name,
                if import.weak_import { " (weak)" } else { "" }
            )
        })
        .collect_vec();
    import_names.sort();

    Ok(Some(ChainedFixups {
        fixups,
        imports: import_names,
        pointer_format,
        page_size,
        segments_with_starts,
    }))
}

#[allow(clippy::too_many_lines)]
fn walk_chain(
    bin: &Binary,
    image: &ImageInfo,
    file_bytes: &[u8],
    segment: &SegmentInfo,
    start_offset_in_segment: u64,
    pointer_format: u16,
    imports: &[Import],
    fixups: &mut Vec<Fixup>,
) -> Result {
    if !matches!(
        pointer_format,
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET
    ) {
        bail!("Chained fixups: unsupported pointer_format {pointer_format}");
    }

    let mut offset_in_segment = start_offset_in_segment;

    loop {
        if fixups.len() >= MAX_FIXUPS {
            bail!("Chained fixups: chain appears to be unterminated");
        }

        if offset_in_segment >= segment.filesize {
            bail!(
                "Chained fixups: chain in segment `{}` runs past the end of the segment",
                segment.name
            );
        }

        let file_offset = usize::try_from(segment.fileoff + offset_in_segment)?;
        let raw = read_u64(file_bytes, file_offset)?;
        let vm_address = segment.vmaddr + offset_in_segment;

        let section_name = image
            .section_containing(vm_address)
            .map(|section| section.name.clone());

        let is_bind = raw >> 63 != 0;

        let kind = if is_bind {
            let ordinal = (raw & 0xff_ffff) as u32;
            let inline_addend = ((raw >> 24) & 0xff) as i64;
            let import = imports
                .get(ordinal as usize)
                .with_context(|| format!("Chained fixups: bind ordinal {ordinal} out of range"))?;

            FixupKind::Bind {
                symbol: import.name.clone(),
                lib_ordinal: import.lib_ordinal,
                addend: import.addend + inline_addend,
                weak_import: import.weak_import,
            }
        } else {
            let target = raw & 0xf_ffff_ffff;
            let high8 = (raw >> 36) & 0xff;
            let target_vm_address = if pointer_format == DYLD_CHAINED_PTR_64_OFFSET {
                image.image_base + target + (high8 << 56)
            } else {
                target + (high8 << 56)
            };

            FixupKind::Rebase {
                target_vm_address,
                target_description: describe_address(bin, image, target_vm_address),
            }
        };

        fixups.push(Fixup {
            segment_name: segment.name.clone(),
            section_name,
            vm_address,
            kind,
        });

        let next = (raw >> 51) & 0xfff;
        if next == 0 {
            return Ok(());
        }
        offset_in_segment += next * 4;
    }
}

/// Stable, layout-independent comparison key. Must not contain any absolute address.
///
/// Part of the interface other components code against. `report_diffs` uses the
/// `_with_image` variant so that the load commands are only parsed once.
#[allow(dead_code)]
pub(crate) fn fixup_comparison_key(fixup: &Fixup, bin: &Binary) -> String {
    let image = read_image_info(bin).ok();
    fixup_comparison_key_with_image(fixup, bin, image.as_ref())
}

fn fixup_comparison_key_with_image(
    fixup: &Fixup,
    bin: &Binary,
    image: Option<&ImageInfo>,
) -> String {
    let location = format!(
        "{}/{}",
        fixup.segment_name,
        fixup.section_name.as_deref().unwrap_or("<no-section>")
    );

    let slot = match image {
        Some(image) => describe_address(bin, image, fixup.vm_address),
        None => "?".to_owned(),
    };
    // If no symbol covers the slot then `describe_address` returns the section name, which is
    // already in `location`, so collapse it to a placeholder rather than repeating it.
    let slot = if slot == location {
        ".".to_owned()
    } else {
        slot
    };

    match &fixup.kind {
        FixupKind::Rebase {
            target_description, ..
        } => format!("{location} {slot} rebase->{target_description}"),
        FixupKind::Bind {
            symbol,
            lib_ordinal,
            addend,
            weak_import,
        } => {
            // Compare against the library *name*, not the ordinal: the order in which linkers
            // emit LC_LOAD_DYLIB commands is a layout decision, not a semantic one.
            let library = match image {
                Some(image) => image.library_name(*lib_ordinal),
                None => format!("ordinal:{lib_ordinal}"),
            };
            let weak = if *weak_import { " weak" } else { "" };
            format!("{location} {slot} bind {library}/{symbol}+{addend}{weak}")
        }
    }
}

/// Renders a fixup for human consumption. Deliberately avoids hexadecimal addresses: the test
/// harness's `normalise_report` deletes any snapshot line containing `0x` followed by three or
/// more hex digits, which would silently empty out any `.exp` file covering this table. Offsets
/// are therefore decimal and relative to the image base.
fn format_fixup(fixup: &Fixup, key: &str, image_base: u64) -> String {
    let slot = fixup.vm_address.wrapping_sub(image_base);
    match &fixup.kind {
        FixupKind::Rebase {
            target_vm_address, ..
        } => {
            let target = target_vm_address.wrapping_sub(image_base);
            format!("{key} (slot img+{slot}, target img+{target})")
        }
        FixupKind::Bind { .. } => format!("{key} (slot img+{slot})"),
    }
}

/// Everything we extract from one binary. Computed once per binary so that we don't re-read the
/// file for each of the tables below.
struct Analysis {
    status: String,
    segments: Vec<String>,
    /// `(for_comparison, formatted)` for each fixup.
    fixups: Vec<(String, String)>,
    imports: Vec<String>,
}

fn analyse(bin: &Binary) -> Result<Analysis> {
    let image = read_image_info(bin)?;

    let Some(fixups) = read_chained_fixups_with_image(bin, &image)? else {
        return Ok(Analysis {
            status: "absent".to_owned(),
            segments: Vec::new(),
            fixups: Vec::new(),
            imports: Vec::new(),
        });
    };

    let mut segments = fixups
        .segments_with_starts
        .iter()
        .filter(|(_, has_fixups)| *has_fixups)
        .map(|(name, _)| {
            // `page_size` is deliberately decimal - see `format_fixup`.
            format!(
                "{name} has-fixups ptr_format={} page_size={}",
                fixups.pointer_format, fixups.page_size
            )
        })
        .collect_vec();
    segments.sort();

    let fixup_rows = fixups
        .fixups
        .iter()
        .map(|fixup| {
            let key = fixup_comparison_key_with_image(fixup, bin, Some(&image));
            let formatted = format_fixup(fixup, &key, image.image_base);
            (key, formatted)
        })
        .collect_vec();

    Ok(Analysis {
        status: "present".to_owned(),
        segments,
        fixups: fixup_rows,
        imports: fixups.imports,
    })
}

/// Registered pass. Emits diff keys under the `macho.fixups.*` namespace.
pub(crate) fn report_diffs(report: &mut Report, objects: &[Binary]) {
    // Only applicable to Mach-O. Do nothing at all for other formats so that this pass can't
    // affect the existing ELF test suite.
    if objects.is_empty()
        || !objects
            .iter()
            .all(|obj| matches!(obj.file, object::File::MachO64(_)))
    {
        return;
    }

    let analyses = objects.iter().map(analyse).collect_vec();

    if std::env::var_os("LINKER_DIFF_MACHO_FIXUPS_DEBUG").is_some() {
        for (obj, analysis) in objects.iter().zip(&analyses) {
            match analysis {
                Ok(analysis) => {
                    eprintln!("=== {} status={}", obj.name, analysis.status);
                    for segment in &analysis.segments {
                        eprintln!("  seg  {segment}");
                    }
                    for (key, formatted) in &analysis.fixups {
                        eprintln!("  fix  {key}   |   {formatted}");
                    }
                    for import in &analysis.imports {
                        eprintln!("  imp  {import}");
                    }
                }
                Err(error) => eprintln!("=== {} error: {error:?}", obj.name),
            }
        }
    }

    // Presence / parse status. A parse failure and a missing load command are distinct states and
    // both reach the report. This is deliberately a separate key from the contents so that a
    // half-working parse can't be mistaken for agreement.
    let statuses = analyses
        .iter()
        .map(|result| match result {
            Ok(analysis) => analysis.status.clone(),
            Err(error) => format!("error: {error}"),
        })
        .collect_vec();

    let any_error = analyses.iter().any(Result::is_err);

    if any_error || !report.config.match_multi(statuses.iter()) {
        report.add_diff(Diff {
            key: "macho.fixups.presence".to_owned(),
            values: DiffValues::PerObject(statuses),
        });
    }

    if any_error {
        // Addresses derived from a malformed blob are meaningless; don't compound the noise.
        return;
    }

    let analyses = analyses
        .into_iter()
        .map(|analysis| analysis.expect("checked above"))
        .collect_vec();

    // Which segments carry fixups. Compared by segment NAME, since wild and ld64 emit __DATA and
    // __DATA_CONST in different orders.
    let aligned = align_rows(
        &analyses
            .iter()
            .map(|analysis| {
                analysis
                    .segments
                    .iter()
                    .map(|segment| (segment.clone(), segment.clone()))
                    .collect_vec()
            })
            .collect_vec(),
    );
    let diffs = diff_array(
        objects,
        |bin| Ok(take_aligned(&aligned, objects, bin)),
        "macho.fixups.segments",
    );
    report.add_diffs(diffs);

    // The fixups themselves. This is the check that catches a missing rebase.
    let aligned = align_rows(
        &analyses
            .iter()
            .map(|analysis| analysis.fixups.clone())
            .collect_vec(),
    );
    let diffs = diff_array(
        objects,
        |bin| Ok(take_aligned(&aligned, objects, bin)),
        "macho.fixups",
    );
    report.add_diffs(diffs);

    // The import table.
    let aligned = align_rows(
        &analyses
            .iter()
            .map(|analysis| {
                analysis
                    .imports
                    .iter()
                    .map(|import| (import.clone(), import.clone()))
                    .collect_vec()
            })
            .collect_vec(),
    );
    let diffs = diff_array(
        objects,
        |bin| Ok(take_aligned(&aligned, objects, bin)),
        "macho.fixups.imports",
    );
    report.add_diffs(diffs);
}

/// `diff_array` renders row `i` of each binary side by side, so if one binary has fewer entries
/// than another, the resulting table silently mis-pairs rows. Pad every binary's list out to a
/// common shape, keyed on `for_comparison`, so that a missing fixup shows up as an explicit
/// `<missing>` cell opposite the fixup it is missing.
fn align_rows(per_binary: &[Vec<(String, String)>]) -> Vec<Vec<ResolvedValue>> {
    let mut all_keys: Vec<&str> = per_binary
        .iter()
        .flat_map(|rows| rows.iter().map(|(key, _)| key.as_str()))
        .unique()
        .collect_vec();
    all_keys.sort_unstable();

    let mut out: Vec<Vec<ResolvedValue>> = (0..per_binary.len()).map(|_| Vec::new()).collect_vec();

    for key in all_keys {
        let occurrences = per_binary
            .iter()
            .map(|rows| {
                rows.iter()
                    .filter(|(row_key, _)| row_key == key)
                    .map(|(_, formatted)| formatted.as_str())
                    .collect_vec()
            })
            .collect_vec();

        let max = occurrences.iter().map(Vec::len).max().unwrap_or(0);

        for slot in 0..max {
            for (binary_index, formatted) in occurrences.iter().enumerate() {
                let value = match formatted.get(slot) {
                    Some(formatted) => ResolvedValue {
                        for_comparison: key.to_owned(),
                        formatted: (*formatted).to_owned(),
                    },
                    None => ResolvedValue {
                        for_comparison: format!("<missing> {key}"),
                        formatted: format!("<missing> {key}"),
                    },
                };
                out[binary_index].push(value);
            }
        }
    }

    out
}

fn take_aligned(
    aligned: &[Vec<ResolvedValue>],
    objects: &[Binary],
    bin: &Binary,
) -> Vec<ResolvedValue> {
    let index = objects
        .iter()
        .position(|obj| obj.path == bin.path)
        .unwrap_or(0);
    aligned[index]
        .iter()
        .map(|value| ResolvedValue {
            for_comparison: value.for_comparison.clone(),
            formatted: value.formatted.clone(),
        })
        .collect_vec()
}
