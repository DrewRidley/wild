//! This crate finds differences between two ELF files. It's intended use is where the files were
//! produced by different linkers, or different versions of the same linker. So the input files
//! should be the same except for where the linkers make different decisions such as layout.
//!
//! Because the intended use is verifying the correct functioning of linkers, the focus is on
//! avoiding false positives rather than avoiding false negatives. i.e. we'd much rather fail to
//! report a difference than report a difference that doesn't matter. Ideally a reported difference
//! should indicate a bug or missing feature of the linker.
//!
//! Right now, performance of this library is not a priority, so there's quite a bit of heap
//! allocation going on that with a little work could be avoided. If we end up using this library as
//! part of a fuzzer this may need to be optimised.

#![allow(clippy::too_many_arguments)]

use anyhow::Context as _;
use anyhow::bail;
use asm_diff::AddressIndex;
use clap::Parser;
use hashbrown::HashMap;
use itertools::Itertools as _;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use linker_utils::utils::slice_from_all_bytes;
use object::Endianness;
use object::File;
use object::Object as _;
use object::ObjectSection;
use object::ObjectSymbol as _;
use section_map::IndexedLayout;
use section_map::LayoutAndFiles;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;

mod aarch64;
mod arch;
mod asm_diff;
mod colour;
mod debug_info_diff;
mod diagnostics;
mod eh_frame_diff;
mod gnu_hash;
mod header_diff;
mod init_order;
mod loongarch64;
mod macho_dyld_info;
mod macho_fixups;
mod ppc64;
mod riscv64;
mod riscv_attributes;
pub(crate) mod section_map;
mod segment;
mod symbol_diff;
mod symtab;
mod sysv_hash;
mod trace;
mod utils;
mod version_diff;
mod x86_64;

type Result<T = (), E = anyhow::Error> = core::result::Result<T, E>;
type ElfFile64<'data> = object::read::elf::ElfFile64<'data, Endianness>;

pub use crate::colour::ColourMode;
use arch::Arch;
use arch::ArchKind;
pub use diagnostics::enable_diagnostics;
use object::Section;
use object::Symbol;
use section_map::InputSectionId;
use section_map::OwnedFileIdentifier;

#[non_exhaustive]
#[derive(Parser, Default, Clone)]
pub struct Config {
    /// Keys to ignore.
    #[arg(long, value_delimiter = ',')]
    pub ignore: Vec<String>,

    /// Show only the specified keys.
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,

    /// Treat the sections with the specified names as equivalent. e.g. ".got.plt=.got"
    #[arg(long, value_delimiter = ',', value_parser = parse_string_equality)]
    pub equiv: Vec<(String, String)>,

    /// Apply defaults for things that should be ignored currently for Wild. These defaults are
    /// subject to change as Wild changes.
    #[arg(long)]
    pub wild_defaults: bool,

    /// Print information about what sections did and didn't get diffed.
    #[arg(long)]
    pub coverage: bool,

    /// Display names for input files.
    #[arg(long, value_delimiter = ',', value_name = "NAME,NAME...")]
    pub display_names: Vec<String>,

    /// Files to compare against
    #[arg(long = "ref", value_name = "FILE")]
    pub references: Vec<PathBuf>,

    /// Match any reference instead of requiring all references to match
    #[arg(long)]
    pub match_any: bool,

    #[arg(long, alias = "color", default_value = "auto")]
    pub colour: ColourMode,

    /// Treat validation passes that have no implementation for the file format under test as
    /// failures, even when they're acknowledged by the ignore list. Use this to see the true
    /// verification coverage rather than the acknowledged-gap-adjusted coverage.
    #[arg(long)]
    pub fail_on_unimplemented: bool,

    /// Primary file that we're validating against the reference file(s)
    pub file: PathBuf,
}

/// An output binary such as an executable or shared object.
pub struct Binary<'data> {
    name: String,
    path: PathBuf,
    file: &'data File<'data>,
    address_index: AddressIndex<'data>,
    name_index: NameIndex<'data>,
    indexed_layout: Option<IndexedLayout<'data>>,
    trace: trace::Trace,
    sections_by_name: HashMap<&'data [u8], SectionInfo>,
}

#[derive(Clone, Copy)]
struct SectionInfo {
    index: object::SectionIndex,
    size: u64,
}

struct NameIndex<'data> {
    globals_by_name: HashMap<&'data [u8], Vec<object::SymbolIndex>>,
    locals_by_name: HashMap<&'data [u8], Vec<object::SymbolIndex>>,
    dynamic_by_name: HashMap<&'data [u8], Vec<object::SymbolIndex>>,
}

/// Why a validation pass doesn't cover a particular file format.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum GapCategory {
    /// The thing the pass validates doesn't exist in this file format, so there's nothing to
    /// implement. Closing one of these means deleting the row, not writing code.
    NotApplicable,

    /// The pass *should* cover this format, but doesn't. **This number should only ever go down.**
    NotImplemented,
}

/// A validation pass that is known not to cover a particular file format.
pub(crate) struct CoverageGap {
    /// Always `unimplemented.<pass>.<format>`. This is also the ignore key.
    pub(crate) key: &'static str,
    pub(crate) category: GapCategory,
    /// Why the gap exists and, for `NotImplemented`, what would close it.
    pub(crate) note: &'static str,
}

/// THE INVENTORY OF THINGS LINKER-DIFF DOESN'T CHECK.
///
/// Every entry here is a validation pass that runs for ELF but does nothing for Mach-O. Before
/// this table existed those passes were *silent*: they returned an empty set of fields,
/// `diff_fields` found nothing to compare, and a half-finished module was indistinguishable from a
/// passing one.
///
/// The rules:
///  * A pass that can't handle a binary's file format MUST call `Report::report_unimplemented`.
///  * If the resulting key isn't in this table, it is a hard failure. You cannot add a blind pass
///    without also adding a row here, and the row demands a justification.
///  * `--wild-defaults` adds every key here to the ignore list, so the existing tests stay green,
///    but `linker-diff` prints the whole inventory on every run and `--fail-on-unimplemented` turns
///    them all back into failures.
///
/// `grep -c NotImplemented linker-diff/src/lib.rs` is the number that has to shrink.
pub(crate) const MACHO_ACKNOWLEDGED_GAPS: &[CoverageGap] = &[
    CoverageGap {
        key: "unimplemented.asm-diff.macho",
        category: GapCategory::NotImplemented,
        note: "Relocations inside function bodies are NOT compared for Mach-O. asm_diff is built \
               on ELF dynamic tables, .rela sections and GOT/PLT indexing; making it Mach-O \
               capable is a rewrite, not a patch. This is the single largest verification hole.",
    },
    CoverageGap {
        key: "unimplemented.asm-index.macho",
        category: GapCategory::NotImplemented,
        note: "AddressIndex::build_indexes only indexes ELF, so there is no relocation/GOT/PLT \
               index to validate. Blocks asm-diff.",
    },
    CoverageGap {
        key: "unimplemented.dynamic.macho",
        category: GapCategory::NotImplemented,
        note: "Dylib dependencies are not diffed. The Mach-O equivalents of .dynamic are \
               LC_LOAD_DYLIB / LC_ID_DYLIB / LC_RPATH / LC_LOAD_WEAK_DYLIB.",
    },
    CoverageGap {
        key: "unimplemented.dynsym.macho",
        category: GapCategory::NotImplemented,
        note: "Exported symbols are not diffed. Mach-O exports live in the LC_DYLD_EXPORTS_TRIE \
               export trie, not in a .dynsym section.",
    },
    CoverageGap {
        key: "unimplemented.eh-frame.macho",
        category: GapCategory::NotImplemented,
        note: "Unwind info is not diffed. Mach-O uses __TEXT,__unwind_info (plus __eh_frame), \
               not .eh_frame_hdr. Note the Mach-O tests all pass `--ignore section.__unwind_info`, \
               so __unwind_info is currently unchecked in every dimension.",
    },
    CoverageGap {
        key: "unimplemented.debug-info.macho",
        category: GapCategory::NotImplemented,
        note: "DWARF compilation units are not diffed. gimli is asked for `.debug_info`, which \
               never matches Mach-O's `__debug_info`, so zero units are found and zero are \
               compared.",
    },
    CoverageGap {
        key: "unimplemented.init-order.macho",
        category: GapCategory::NotImplemented,
        note: "Initialiser order is not diffed. The pass looks for .init_array/.fini_array; \
               Mach-O uses __DATA,__mod_init_func and __DATA,__mod_term_func.",
    },
    CoverageGap {
        key: "unimplemented.got-plt.macho",
        category: GapCategory::NotImplemented,
        note: "Mach-O has no .got.plt, but it does have __DATA_CONST,__got and __TEXT,__stubs, \
               whose contents are equally unchecked.",
    },
    CoverageGap {
        key: "unimplemented.gnu-hash.macho",
        category: GapCategory::NotApplicable,
        note: "Mach-O has no .gnu.hash section. dyld resolves symbols through the export trie.",
    },
    CoverageGap {
        key: "unimplemented.sysv-hash.macho",
        category: GapCategory::NotApplicable,
        note: "Mach-O has no SysV .hash section.",
    },
    CoverageGap {
        key: "unimplemented.dynsym-partition.macho",
        category: GapCategory::NotApplicable,
        note: "Mach-O has a single LC_SYMTAB rather than a separate .dynsym. Its \
               local/extdef/undef partition is validated by the `macho.dysymtab` pass.",
    },
    CoverageGap {
        key: "unimplemented.version.macho",
        category: GapCategory::NotApplicable,
        note: "Mach-O has no symbol versioning (no .gnu.version / .gnu.version_d).",
    },
];

/// Greedy word wrap. Only used for rendering coverage-gap notes.
fn wrap_note(note: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in note.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn find_acknowledged_gap(key: &str) -> Option<&'static CoverageGap> {
    MACHO_ACKNOWLEDGED_GAPS.iter().find(|g| g.key == key)
}

/// A difference that `--wild-defaults` suppresses even though it is believed to be a genuine defect
/// in Wild's output, as opposed to a legitimate linker-to-linker difference.
///
/// The two are kept apart on purpose. The ignore list above is a list of things that don't matter;
/// putting a real bug in it makes the bug indistinguishable from noise, which is how a
/// verification tool rots. Everything here is still *reported* - see
/// [`Report::coverage_gap_report`] - it just doesn't fail the build.
pub(crate) struct KnownDefect {
    pub(crate) key: &'static str,
    pub(crate) note: &'static str,
}

/// Suppressed-but-real differences in Wild's Mach-O output. **Delete rows from here as they are
/// fixed.** Adding a row requires a description of the defect.
pub(crate) const WILD_MACHO_KNOWN_DEFECTS: &[KnownDefect] = &[
    KnownDefect {
        key: "section.__got.type",
        note: "Wild marks __DATA_CONST,__got as S_REGULAR. ld64 marks it \
               S_NON_LAZY_SYMBOL_POINTERS. Tools that enumerate indirect symbols (otool -I, \
               dyld_info) can't describe Wild's __got as a result.",
    },
    KnownDefect {
        key: "section.__got.reserved1",
        note: "Follows from the above: reserved1 is the index of the section's first entry in the \
               indirect symbol table, and Wild leaves it 0 while ld64 sets a real index.",
    },
    KnownDefect {
        key: "section.__got.alignment",
        note: "Wild gives __got align=2^0. It is an array of 8-byte pointers and ld64 gives it \
               align=2^3.",
    },
    KnownDefect {
        key: "macho.dysymtab",
        note: "Wild emits no LC_DYSYMTAB load command at all; ld64 emits one for every image it \
               links. Without it nothing can tell which run of LC_SYMTAB entries is local, which \
               is externally defined and which is undefined (`nm`, `otool -I`, dyld). Wild also \
               omits LC_DYLD_EXPORTS_TRIE, so the image advertises no exports either.",
    },
    KnownDefect {
        key: "file-header.flags.MH_WEAK_DEFINES",
        note: "Linking C++ (weak/coalesced definitions from inline functions and templates), ld64 \
               sets MH_WEAK_DEFINES in the Mach header and Wild does not. dyld uses this flag to \
               decide whether the image needs weak-symbol coalescing at load time.",
    },
    KnownDefect {
        key: "file-header.flags.MH_BINDS_TO_WEAK",
        note: "As above, for the importing side: ld64 sets MH_BINDS_TO_WEAK when the image binds \
               to a weak definition, Wild does not.",
    },
];

fn find_known_defect(key: &str) -> Option<&'static KnownDefect> {
    WILD_MACHO_KNOWN_DEFECTS.iter().find(|d| d.key == key)
}

/// Short name for a binary's file format. Used to key coverage gaps, so that
/// `unimplemented.asm-diff.macho` can be acknowledged without also blinding ELF.
pub(crate) fn file_format_name(file: &File) -> &'static str {
    match file {
        // "elf" and "macho" mean 64-bit. Every reader in this crate matches on `Elf64` / `MachO64`
        // specifically, so a 32-bit input gets its own name and therefore an *unacknowledged*
        // coverage gap - a loud failure - rather than quietly falling through the 64-bit readers.
        File::Elf64(_) => "elf",
        File::MachO64(_) => "macho",
        File::Elf32(_) => "elf32",
        File::MachO32(_) => "macho32",
        // `object::File` is `#[non_exhaustive]` and most other variants are feature-gated out of
        // this build. Anything that reaches here still gets a distinct, greppable format name so
        // that a gap is recorded rather than swallowed.
        _ => "other-format",
    }
}

impl Config {
    #[must_use]
    pub fn from_env() -> Self {
        Self::parse()
    }

    fn apply_wild_defaults(&mut self, arch: ArchKind) {
        self.ignore.extend(
            [
                // We don't currently support allocating space except in sections, so we have
                // sections to hold the section and program headers. We then need
                // to ignore them because GNU ld doesn't define such sections.
                "section.shdr",
                "section.phdr",
                // We don't yet support these sections.
                "section.data.rel.ro",
                // We set this to 8. GNU ld sometimes does too, but sometimes to 0.
                "section.got.entsize",
                "section.plt.got.entsize",
                "section.plt.entsize",
                // GNU ld sometimes sets this differently that we do.
                "section.plt",
                "section.plt.alignment",
                "section.bss.alignment",
                "section.gnu.build.attributes",
                "section.annobin.notes.entsize",
                // We don't yet group .lrodata sections separately.
                "section.lrodata",
                // We sometimes eliminate __tls_get_addr where GNU ld doesn't. This can mean that
                // we have no versioned symbols for ld-linux-x86-64.so.2 or
                // equivalent, which means we end up with one less version record.
                ".dynamic.DT_VERNEEDNUM",
                // We currently handle these dynamic tags differently
                ".dynamic.DT_JMPREL",
                ".dynamic.DT_PLTGOT",
                ".dynamic.DT_PLTREL",
                // We currently produce a .got.plt whenever we produce .plt, but GNU ld doesn't
                "section.got.plt",
                GOT_PLT_SECTION_NAME_STR,
                // We don't currently produce a separate .plt.sec section.
                "section.plt.sec",
                // Different hash values due to different implementations.
                ".dynamic.DT_HASH",
                // Different hash values due to different implementations.
                ".hash",
                "section.hash.alignment",
                "section.hash.entsize",
                // Some other linkers seem to generate a `.hash` section even when there are no
                // dynamic symbols.
                "section.hash",
                // aarch64-linux-gnu-ld on arch linux emits DT_BIND_NOW instead of
                // DT_FLAGS.BIND_NOW
                ".dynamic.DT_BIND_NOW",
                ".dynamic.DT_FLAGS.BIND_NOW",
                // When GNU ld encounters a GOT-forming reference to an ifunc, it generates a
                // canonical PLT entry and points the GOT at that. This means that it ends up with
                // GOT->PLT->GOT. We don't as yet support doing this.
                "rel.missing-got-plt-got",
                // We do support this. TODO: Should definitely look into why we're seeing this
                // missing in our output.
                "section.rela.plt",
                // We currently write 10 byte PLT entries in some cases where GNU ld writes 8 byte
                // ones.
                "section.plt.got.alignment",
                // GNU ld sometimes makes this writable sometimes not. Presumably this depends on
                // whether there are relocations or some flags.
                "section.eh_frame.flags",
                // TLSDESC relaxations aren't yet implemented.
                "rel.match_failed.R_X86_64_GOTPC32_TLSDESC",
                "rel.match_failed.R_X86_64_CODE_4_GOTPC32_TLSDESC",
                "rel.missing-opt.R_X86_64_TLSDESC_CALL.SkipTlsDescCall.*",
                // Wild eliminates GOTPCRELX in statically linked executables even for undefined
                // symbols, whereas other linkers don't. This is a valid optimisation that other
                // linkers don't currently do.
                "rel.extra-opt.R_X86_64_GOTPCRELX.CallIndirectToRelative.static-*",
                // Wild applies MovIndirectToLea relaxation to _DYNAMIC symbol in static builds
                // because it's marked as NON_INTERPOSABLE. GNU ld keeps the GOT-relative access.
                // Both are correct, but Wild's approach is more optimized.
                "rel.extra-opt.R_X86_64_REX_GOTPCRELX.MovIndirectToLea.static-*",
                // We don't yet support emitting warnings.
                "section.gnu.warning",
                // GNU ld sometimes applies relaxations that we don't yet.
                "rel.match_failed.R_AARCH64_TLSDESC_LD64_LO12",
                "rel.match_failed.R_AARCH64_TLSGD_ADD_LO12_NC",
                "rel.missing-opt.R_X86_64_TLSGD.TlsGdToInitialExec.shared-object",
                // GNU ld sometimes relaxes an adrp instruction to an adr instruction when the
                // address is known and within +/-1MB. We don't as yet.
                "rel.missing-opt.R_AARCH64_ADR_GOT_PAGE.AdrpToAdr.*",
                "rel.missing-opt.R_AARCH64_ADR_PREL_PG_HI21.AdrpToAdr.*",
                "rel.extra-opt.R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21.MovzXnLsl16.*",
                // LLD does some different relaxations to us
                "rel.missing-opt.R_AARCH64_ADR_GOT_PAGE.ReplaceWithNop.*",
                "rel.missing-opt.R_AARCH64_ADR_PREL_PG_HI21.ReplaceWithNop.*",
                // The other linkers set properties on sections if all input sections have that
                // property. For sections like .rodata, this seems like an unimportant behaviour to
                // replicate.
                "section.rodata.entsize",
                "section.rodata.flags",
                // We emit dynamic relocations for direct references to undefined weak symbols that
                // might be provided at runtime as well as GOT entries for indirect references. GNU
                // ld and lld only emit the GOT entries and leave direct references as null. Our
                // behaviour seems more consistent with the description of
                // `-zdynamic-undefined-weak`.
                "rel.undefined-weak.dynamic.R_X86_64_64",
                "rel.undefined-weak.dynamic.R_AARCH64_ABS64",
                // On aarch64, GNU ld, at least sometimes, converts R_AARCH64_ABS64 to a
                // PLT-forming relocation. We at present, don't.
                "rel.dynamic-plt-bypass",
                // If we don't optimise a TLS access, then we'll have references to __tls_get_addr,
                // when GNU ld doesn't.
                "dynsym.__tls_get_addr.*",
                // GNU ld emits two segments, whereas wild emits only a single segment.
                "segment.LOAD.R.*",
                // We haven't provided an implementation that is compatible with existing linkers.
                "segment.PHDR.*",
                "segment.GNU_RELRO.*",
                "segment.GNU_STACK.*",
                // Wild currently generates PT_NOTE even for non-alloc note sections, while the
                // other linkers don't.
                "segment.NOTE.*",
                // TODO: RISC-V
                "segment.LOAD.RW.alignment",
                // TODO: Latest lld sometimes doesn’t create a .note.gnu.property section even when
                // Wild does.
                "segment.GNU_PROPERTY.alignment",
                "segment.GNU_PROPERTY.flags",
                // TODO: We consider SFrame sections experimental and disabled by default.
                "segment.GNU_SFRAME.alignment",
                "segment.GNU_SFRAME.flags",
                "section.sframe",
                // Different linkers put the PLT in different locations relative to .text, so
                // whether range-extension thunks are needed varies.
                "rel.plt.extra-thunk",
                "rel.plt.absent-thunk",
                // On some systems Wild outputs these symbols while GNU ld does not.
            ]
            .into_iter()
            .map(ToOwned::to_owned),
        );

        self.ignore.extend(
            [
                // --- Mach-O: legitimate linker-to-linker differences. ---
                //
                // ld64 emits load commands Wild doesn't (LC_UUID, LC_SOURCE_VERSION,
                // LC_FUNCTION_STARTS, LC_DATA_IN_CODE, ...), so the command count and total size
                // can't match. Note this means a *missing* load command is not caught here; the
                // individual load commands that matter are diffed by their own passes.
                "file-header.ncmds",
                "file-header.sizeofcmds",
                // Wild and ld64 legitimately group input sections differently. e.g. for a
                // freestanding binary Wild emits __TEXT,{__text,__cstring,__const,__stubs} where
                // ld64 emits __TEXT,{__text,__const,__unwind_info}. Since every Mach-O test also
                // passes `--ignore section.__unwind_info`, this can never match.
                "segment.__TEXT.nsects",
                "segment.__DATA.nsects",
                "segment.__DATA_CONST.nsects",
            ]
            .into_iter()
            .map(ToOwned::to_owned),
        );

        // Mach-O validation passes that don't exist yet. Suppressed so the existing tests stay
        // runnable; still printed on every run by `Report::coverage_gap_report`.
        self.ignore
            .extend(MACHO_ACKNOWLEDGED_GAPS.iter().map(|g| g.key.to_owned()));

        // Real bugs in Wild's Mach-O output, suppressed so they don't mask unrelated regressions.
        // Also still printed on every run.
        self.ignore
            .extend(WILD_MACHO_KNOWN_DEFECTS.iter().map(|d| d.key.to_owned()));

        match arch {
            ArchKind::Aarch64 => self.ignore.extend(
                [
                    "section.ARM.attributes",
                    // Other linkers have a bigger initial PLT entry, thus the entsize is set to
                    // zero: https://sourceware.org/bugzilla/show_bug.cgi?id=26312
                    "section.plt.entsize",
                    // On Alpine Linux, aarch64, GNU ld seems to emit the _DYNAMIC symbol without a
                    // section index instead of pointing it at the .dynamic section.
                    "rel.extra-symbol._DYNAMIC",
                    // Also on Alpine Linux, aarch64, it seems that GNU ld is emitting an
                    // unnecessary GLOB_DAT relocation in a GOT entry.
                    "rel.missing-got-dynamic.executable",
                    // GNU ld replaces calls to undefined symbols with nop. Wild instead encodes
                    // bl 0x0 so that if the call site is reached, it will crash rather than
                    // silently continuing execution.
                    "rel.missing-opt.R_AARCH64_CALL26.ReplaceWithNop.*",
                    "rel.missing-opt.R_AARCH64_JUMP26.ReplaceWithNop.*",
                ]
                .into_iter()
                .map(ToOwned::to_owned),
            ),
            ArchKind::RiscV64 => self.ignore.extend(
                [
                    // TODO: for some reason, main is put into .dynsym by GNU ld.
                    "dynsym.main.section",
                    // GOT entries may differ due to unimplemented relaxations
                    "section.got.*",
                    // Dynamic relocations may differ
                    "rel.dynamic.*",
                    "rel.undefined-weak.*",
                    // Symbol address inconsistencies due to different optimizations
                    "error.*",
                    "section-diff-failed*",
                    // .relro_padding is showing up on risc-v.
                    "section.relro_padding",
                ]
                .into_iter()
                .map(ToOwned::to_owned),
            ),
            ArchKind::X86_64 => {}
            ArchKind::Ppc64 => {}
            ArchKind::LoongArch64 => self.ignore.extend(
                [
                    "section.sdata",
                    "section.iplt",
                    "rel.unknown_failure*",
                    "literal-byte-mismatch*",
                    "error.*",
                    "section-diff-failed*",
                    // GNU ld replaces calls to undefined symbols with nop. Wild instead encodes
                    // bl 0x0 so that if the call site is reached, it will crash rather than
                    // silently continuing execution.
                    "rel.missing-opt.R_LARCH_B26.ReplaceWithNop.*",
                ]
                .into_iter()
                .map(ToOwned::to_owned),
            ),
        }

        self.equiv.push((
            GOT_SECTION_NAME_STR.to_owned(),
            GOT_PLT_SECTION_NAME_STR.to_owned(),
        ));
        // We don't currently define .plt.got and .plt.sec, we just put everything into .plt.
        self.equiv.push((
            PLT_SECTION_NAME_STR.to_owned(),
            PLT_GOT_SECTION_NAME_STR.to_owned(),
        ));
        self.equiv.push((
            PLT_SECTION_NAME_STR.to_owned(),
            PLT_SEC_SECTION_NAME_STR.to_owned(),
        ));
    }

    #[must_use]
    pub fn to_arg_string(&self) -> String {
        let mut out = String::new();
        if self.wild_defaults {
            out.push_str("--wild-defaults ");
        }
        if !self.ignore.is_empty() {
            out.push_str("--ignore '");
            out.push_str(&self.ignore.join(","));
            out.push_str("' ");
        }
        if !self.equiv.is_empty() {
            out.push_str("--equiv '");
            let parts = self
                .equiv
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect_vec();
            out.push_str(&parts.join(","));
            out.push_str("' ");
        }
        if !self.display_names.is_empty() {
            out.push_str("--display-names ");
            out.push_str(&self.display_names.join(","));
            out.push(' ');
        }
        for file in &self.references {
            out.push_str("--ref ");
            out.push_str(&file.to_string_lossy());
            out.push(' ');
        }
        out.push_str(&self.file.to_string_lossy());
        out
    }

    fn filenames(&self) -> impl Iterator<Item = &PathBuf> {
        // We always put our file first, since it makes it easier to treat it differently. e.g. when
        // we compare a value from our file against each of the values from the other files.
        std::iter::once(&self.file).chain(&self.references)
    }

    /// Returns whether the first item equals all or any of the others, depending on the --match-any
    /// flag.
    fn match_multi<T: PartialEq>(&self, values: impl Iterator<Item = T>) -> bool {
        if self.match_any {
            first_equals_any(values)
        } else {
            first_equals_all(values)
        }
    }
}

impl<'data> Binary<'data> {
    pub(crate) fn new(
        file: &'data File<'data>,
        name: String,
        path: PathBuf,
        layout_and_files: Option<&'data LayoutAndFiles>,
    ) -> Result<Self> {
        let address_index = AddressIndex::new(file);
        let indexed_layout = layout_and_files.map(IndexedLayout::new).transpose()?;
        let trace = trace::Trace::for_path(&path)?;

        let sections_by_name = file
            .sections()
            .map(|section| {
                Ok((
                    section.name_bytes()?,
                    SectionInfo {
                        index: section.index(),
                        size: section.size(),
                    },
                ))
            })
            .collect::<Result<HashMap<&[u8], SectionInfo>>>()?;

        Ok(Self {
            name,
            file,
            path,
            address_index,
            name_index: NameIndex::new(file),
            indexed_layout,
            trace,
            sections_by_name,
        })
    }

    /// Looks up a symbol, first trying to get a global, or failing that a local. If multiple
    /// symbols have the same name, then `hint_address` is used to select which one to return.
    pub(crate) fn symbol_by_name<'file: 'data>(
        &'file self,
        name: &[u8],
        hint_address: u64,
    ) -> NameLookupResult<'data, 'file> {
        match self.lookup_symbol(&self.name_index.globals_by_name, name, hint_address) {
            NameLookupResult::Undefined => {
                self.lookup_symbol(&self.name_index.locals_by_name, name, hint_address)
            }
            other => other,
        }
    }

    fn lookup_symbol<'file: 'data>(
        &'file self,
        symbol_map: &HashMap<&[u8], Vec<object::SymbolIndex>>,
        name: &[u8],
        hint_address: u64,
    ) -> NameLookupResult<'data, 'file> {
        let indexes = symbol_map.get(name).map(Vec::as_slice).unwrap_or_default();

        if indexes.len() >= 2 {
            for sym_index in indexes {
                if let Ok(sym) = self.file.symbol_by_index(*sym_index)
                    && sym.address() == hint_address
                {
                    return NameLookupResult::Defined(sym);
                }
            }

            // We didn't find a symbol with exactly the address hinted at.
            return NameLookupResult::Duplicate;
        }

        if let Some(symbol_index) = indexes.first() {
            if let Ok(sym) = self.file.symbol_by_index(*symbol_index) {
                NameLookupResult::Defined(sym)
            } else {
                NameLookupResult::Undefined
            }
        } else {
            NameLookupResult::Undefined
        }
    }

    fn section_by_name<'file: 'data>(&'file self, name: &str) -> Option<Section<'data, 'file>> {
        self.section_by_name_bytes(name.as_bytes())
    }

    fn section_by_name_bytes<'file: 'data>(
        &'file self,
        name: &[u8],
    ) -> Option<Section<'data, 'file>> {
        let index = self.sections_by_name.get(name)?.index;
        self.file.section_by_index(index).ok()
    }

    fn section_containing_address<'file: 'data>(
        &'file self,
        address: u64,
    ) -> Option<Section<'file, 'data>> {
        self.file
            .sections()
            .find(|sec| (sec.address()..sec.address() + sec.size()).contains(&address))
    }

    /// Returns the name of the section that contains the supplied address. Does a linear scan, so
    /// should only be used for error reporting.
    fn section_name_containing_address(&self, address: u64) -> Option<&str> {
        self.section_containing_address(address)
            .and_then(|sec| sec.name().ok())
    }
}

#[derive(Debug)]
enum NameLookupResult<'data, 'file> {
    Undefined,
    Duplicate,
    Defined(Symbol<'data, 'file>),
}

fn validate_objects(
    report: &mut Report,
    objects: &[Binary],
    validation_name: &str,
    validation_fn: impl Fn(&Binary) -> Result,
) {
    let values = objects
        .iter()
        .map(|obj| match validation_fn(obj) {
            Ok(_) => "OK".to_owned(),
            Err(e) => e.to_string(),
        })
        .collect_vec();
    if report.config.match_multi(values.iter()) {
        return;
    }
    report.add_diff(Diff {
        key: validation_name.to_owned(),
        values: DiffValues::PerObject(values),
    });
}

/// Like [`validate_objects`], but for validations that only understand some file formats.
///
/// This exists because `validate_objects` collapses each binary to "OK" or an error string and
/// then compares those strings. A validation that doesn't understand the format therefore produces
/// the *same* result for every binary, which compares equal, which reports nothing. Instead of
/// letting the pass run and silently agree with itself, we record the gap.
fn validate_objects_for_formats(
    report: &mut Report,
    objects: &[Binary],
    validation_name: &str,
    pass_name: &str,
    supported_formats: &[&str],
    validation_fn: impl Fn(&Binary) -> Result,
) {
    if !report.require_format(pass_name, objects, supported_formats) {
        return;
    }
    validate_objects(report, objects, validation_name, validation_fn);
}

/// For a validation that is *by design* specific to one file format and has a sibling pass
/// covering the others. No coverage gap is recorded, because there is no gap - use
/// [`validate_objects_for_formats`] instead if there is.
fn validate_objects_format_specific(
    report: &mut Report,
    objects: &[Binary],
    validation_name: &str,
    formats: &[&str],
    validation_fn: impl Fn(&Binary) -> Result,
) {
    let Some(first) = objects.first() else {
        return;
    };
    if !formats.contains(&file_format_name(first.file)) {
        return;
    }
    validate_objects(report, objects, validation_name, validation_fn);
}

pub struct Report {
    /// The names of each of our binaries. These should be short, not a full path, since we often
    /// prefix lines with these names.
    names: Vec<String>,

    /// The full path of each of our binaries.
    paths: Vec<PathBuf>,

    /// The differences that were detected.
    diffs: Vec<Diff>,

    /// Validation passes that had no implementation for the file format of the binaries being
    /// compared. See [`MACHO_ACKNOWLEDGED_GAPS`]. A pass recorded here checked NOTHING; it is not
    /// evidence of correctness.
    unimplemented: Vec<UnimplementedPass>,

    /// Diff keys that were suppressed but are listed in [`WILD_MACHO_KNOWN_DEFECTS`], i.e. known
    /// bugs that were actually hit on this run.
    suppressed_defects: Vec<String>,

    /// The configuration that was used.
    config: Config,

    pub coverage: Option<Coverage>,
}

struct UnimplementedPass {
    /// `unimplemented.<pass>.<format>`
    key: String,
    format: String,
    /// Why the pass doesn't cover this format. Comes from [`MACHO_ACKNOWLEDGED_GAPS`] when the gap
    /// is acknowledged, otherwise from the call site.
    note: String,
    category: Option<GapCategory>,
    /// Whether the gap is acknowledged by the ignore list (which `--wild-defaults` populates from
    /// [`MACHO_ACKNOWLEDGED_GAPS`]). Unacknowledged gaps are failures.
    acknowledged: bool,
}

#[derive(Default)]
pub struct Coverage {
    sections: HashMap<InputSectionId, SectionCoverage>,
    colour: ColourMode,
}

struct SectionCoverage {
    /// The original input file from which the section came.
    original_file: OwnedFileIdentifier,

    /// The name of the section.
    name: String,

    /// Whether we diffed this section at all.
    diffed: bool,

    /// The size of the section in bytes.
    num_bytes: u64,
}

impl Report {
    pub fn from_config(mut config: Config) -> Result<Report> {
        let display_names = short_file_display_names(&config)?;

        let file_bytes = config
            .filenames()
            .map(|filename| -> Result<Vec<u8>> {
                let bytes = std::fs::read(filename)
                    .with_context(|| format!("Failed to read `{}`", filename.display()))?;
                Ok(bytes)
            })
            .collect::<Result<Vec<Vec<u8>>>>()?;

        let files = file_bytes
            .iter()
            .map(|bytes| -> Result<object::File> { Ok(object::File::parse(bytes.as_slice())?) })
            .collect::<Result<Vec<_>>>()?;

        let layouts = config
            .filenames()
            .map(|p| LayoutAndFiles::from_base_path(p))
            .collect::<Result<Vec<_>>>()?;

        let objects = files
            .iter()
            .zip(display_names)
            .zip(config.filenames())
            .zip(&layouts)
            .map(|(((file, name), path), layout)| -> Result<Binary> {
                Binary::new(file, name, path.clone(), layout.as_ref())
            })
            .collect::<Result<Vec<_>>>()?;

        if objects.len() < 2 {
            bail!("At least two files must be provided for comparison");
        }

        let arch = ArchKind::from_objects(&objects)?;

        if config.wild_defaults {
            config.apply_wild_defaults(arch);
        }

        let mut report = Report {
            names: objects.iter().map(|o| o.name.clone()).collect(),
            paths: objects.iter().map(|o| o.path.clone()).collect(),
            diffs: Default::default(),
            unimplemented: Default::default(),
            suppressed_defects: Default::default(),
            coverage: config.coverage.then(|| Coverage {
                colour: config.colour,
                ..Coverage::default()
            }),
            config,
        };

        report.run_on_objects(&objects, arch);

        Ok(report)
    }

    fn run_on_objects(&mut self, objects: &[Binary], arch: ArchKind) {
        // Comparing binaries in different file formats isn't meaningful and would make every
        // "unimplemented for this format" record ambiguous, so refuse rather than guess.
        let formats = objects
            .iter()
            .map(|o| file_format_name(o.file))
            .collect_vec();
        if !first_equals_all(formats.iter()) {
            self.add_error(format!(
                "Binaries have different file formats: {}",
                self.names
                    .iter()
                    .zip(&formats)
                    .map(|(name, format)| format!("{name}={format}"))
                    .join(", ")
            ));
            return;
        }

        validate_objects_for_formats(
            self,
            objects,
            GNU_HASH_SECTION_NAME_STR,
            "gnu-hash",
            &["elf"],
            gnu_hash::check_object,
        );
        validate_objects_for_formats(
            self,
            objects,
            HASH_SECTION_NAME_STR,
            "sysv-hash",
            &["elf"],
            sysv_hash::check_object,
        );
        validate_objects_for_formats(
            self,
            objects,
            "index",
            "asm-index",
            &["elf"],
            asm_diff::validate_indexes,
        );
        validate_objects_for_formats(
            self,
            objects,
            GOT_PLT_SECTION_NAME_STR,
            "got-plt",
            &["elf"],
            asm_diff::validate_got_plt,
        );
        // `.symtab` and `macho.dysymtab` are a matched pair: each is specific to one format and
        // together they cover both, so neither records a coverage gap for the other's format. They
        // are kept as separate keys so that suppressing a Mach-O finding can never blind ELF.
        validate_objects_format_specific(
            self,
            objects,
            SYMTAB_SECTION_NAME_STR,
            &["elf"],
            symtab::validate_debug,
        );
        validate_objects_format_specific(
            self,
            objects,
            "macho.dysymtab",
            &["macho"],
            symtab::validate_macho_dysymtab_present,
        );
        validate_objects_format_specific(
            self,
            objects,
            "macho.dysymtab.partition",
            &["macho"],
            symtab::validate_macho_dysymtab_partition,
        );
        validate_objects_for_formats(
            self,
            objects,
            DYNSYM_SECTION_NAME_STR,
            "dynsym-partition",
            &["elf"],
            symtab::validate_dynamic,
        );
        header_diff::check_dynamic_headers(self, objects);
        header_diff::check_file_headers(self, objects);
        header_diff::check_macho_linkedit_alignment(self, objects);
        header_diff::report_section_diffs(self, objects);
        eh_frame_diff::report_diffs(self, objects);
        version_diff::report_diffs(self, objects);
        debug_info_diff::check_debug_info(self, objects);
        symbol_diff::report_diffs(self, objects);
        segment::report_diffs(self, objects);
        macho_fixups::report_diffs(self, objects);
        macho_dyld_info::report_diffs(self, objects);

        match arch {
            ArchKind::X86_64 => {
                self.report_arch_specific_diffs::<crate::x86_64::X86_64>(objects);
            }
            ArchKind::Aarch64 => {
                self.report_arch_specific_diffs::<crate::aarch64::AArch64>(objects);
            }

            ArchKind::RiscV64 => {
                self.report_arch_specific_diffs::<crate::riscv64::RiscV64>(objects);
                riscv_attributes::report_diffs(self, objects);
            }
            ArchKind::LoongArch64 => {
                self.report_arch_specific_diffs::<crate::loongarch64::LoongArch64>(objects);
            }
            ArchKind::Ppc64 => {
                self.report_arch_specific_diffs::<crate::ppc64::Ppc64>(objects);
            }
        }
    }

    fn report_arch_specific_diffs<A: Arch>(&mut self, binaries: &[Binary]) {
        asm_diff::report_section_diffs::<A>(self, binaries);
        init_order::report_diffs::<A>(self, binaries);
    }

    fn add_diff(&mut self, diff: Diff) {
        if self.should_ignore(&diff.key) {
            // A suppressed difference that we've written down as a real bug still gets reported,
            // it just doesn't fail. Otherwise the ignore list would be a place bugs go to die.
            if find_known_defect(&diff.key).is_some()
                && !self.suppressed_defects.contains(&diff.key)
            {
                self.suppressed_defects.push(diff.key);
            }
            return;
        }
        self.diffs.push(diff);
    }

    fn add_diffs(&mut self, new_diffs: Vec<Diff>) {
        for diff in new_diffs {
            self.add_diff(diff);
        }
    }

    /// Records that the validation pass `pass` has no implementation for `format`, so it checked
    /// nothing. Exists so that a half-finished module is distinguishable from a passing one.
    ///
    /// Key namespace: `unimplemented.<pass>.<format>`. If the key isn't listed in
    /// [`MACHO_ACKNOWLEDGED_GAPS`] (which is what `--wild-defaults` feeds into the ignore list),
    /// this is a hard failure — you can't add a blind pass without writing down why.
    pub(crate) fn report_unimplemented(&mut self, pass: &str, format: &str) {
        self.report_unimplemented_with_reason(
            pass,
            format,
            "This pass has no implementation for this file format and checked nothing.",
        );
    }

    /// As [`Report::report_unimplemented`], but with a call-site explanation used when the gap
    /// isn't listed in [`MACHO_ACKNOWLEDGED_GAPS`].
    pub(crate) fn report_unimplemented_with_reason(
        &mut self,
        pass: &str,
        format: &str,
        reason: &str,
    ) {
        let key = format!("unimplemented.{pass}.{format}");
        if self.unimplemented.iter().any(|u| u.key == key) {
            return;
        }

        let acknowledged_gap = find_acknowledged_gap(&key);
        let acknowledged = !self.config.fail_on_unimplemented && self.should_ignore(&key);

        self.unimplemented.push(UnimplementedPass {
            note: acknowledged_gap.map_or_else(|| reason.to_owned(), |g| g.note.to_owned()),
            category: acknowledged_gap.map(|g| g.category),
            key,
            format: format.to_owned(),
            acknowledged,
        });
    }

    /// Returns whether the binaries' file format is one this pass understands. If not, records the
    /// gap and returns false so the caller can bail out loudly rather than quietly.
    pub(crate) fn require_format(
        &mut self,
        pass: &str,
        objects: &[Binary],
        supported_formats: &[&str],
    ) -> bool {
        let Some(first) = objects.first() else {
            return false;
        };
        let format = file_format_name(first.file);
        if supported_formats.contains(&format) {
            return true;
        }
        self.report_unimplemented(pass, format);
        false
    }

    fn failing_gaps(&self) -> impl Iterator<Item = &UnimplementedPass> {
        self.unimplemented.iter().filter(|u| !u.acknowledged)
    }

    #[must_use]
    pub fn has_problems(&self) -> bool {
        !self.diffs.is_empty() || self.failing_gaps().next().is_some()
    }

    /// A human-readable inventory of the validation passes that checked nothing, for printing on
    /// *every* run — including successful ones. The whole point of this crate is to be an oracle,
    /// and an oracle that silently declines to look at half the binary needs to say so out loud.
    ///
    /// Returns `None` when every pass ran.
    #[must_use]
    pub fn coverage_gap_report(&self) -> Option<String> {
        use std::fmt::Write as _;

        if self.unimplemented.is_empty() && self.suppressed_defects.is_empty() {
            return None;
        }

        let format = self
            .unimplemented
            .first()
            .map_or("?", |u| u.format.as_str());

        let not_implemented = self
            .unimplemented
            .iter()
            .filter(|u| u.category != Some(GapCategory::NotApplicable))
            .count();

        let total = self.unimplemented.len();
        let mut out = String::new();

        if total > 0 {
            let _ = writeln!(
                out,
                "!! VERIFICATION COVERAGE GAP: {total} validation pass(es) did not run for \
                 `{format}`; {not_implemented} of them should have."
            );
            let _ = writeln!(
                out,
                "!! A pass listed below reported nothing because it LOOKED at nothing. That is not \
                 evidence that the output is correct."
            );

            for gap in &self.unimplemented {
                let status = match (gap.acknowledged, gap.category) {
                    (false, _) => "UNACKNOWLEDGED",
                    (true, Some(GapCategory::NotApplicable)) => "not-applicable",
                    (true, _) => "NOT-IMPLEMENTED",
                };
                let _ = writeln!(out, "   [{status:<14}] {}", gap.key);
                for line in wrap_note(&gap.note, 92) {
                    let _ = writeln!(out, "        {line}");
                }
            }
        }

        if !self.suppressed_defects.is_empty() {
            let _ = writeln!(
                out,
                "!! SUPPRESSED KNOWN DEFECTS: {} difference(s) were found and NOT failed, because \
                 they are",
                self.suppressed_defects.len()
            );
            let _ = writeln!(
                out,
                "!! already recorded as bugs in Wild's output rather than acceptable differences."
            );
            for key in &self.suppressed_defects {
                let _ = writeln!(out, "   [known-defect  ] {key}");
                if let Some(defect) = find_known_defect(key) {
                    for line in wrap_note(defect.note, 92) {
                        let _ = writeln!(out, "        {line}");
                    }
                }
            }
        }

        let _ = writeln!(
            out,
            "!! Inventories: `MACHO_ACKNOWLEDGED_GAPS` and `WILD_MACHO_KNOWN_DEFECTS` in \
             linker-diff/src/lib.rs."
        );
        let _ = writeln!(
            out,
            "!! Pass --fail-on-unimplemented to turn the coverage gaps into failures."
        );

        Some(out)
    }

    #[must_use]
    pub fn should_ignore(&self, key: &str) -> bool {
        if !self.config.only.is_empty() {
            return !self.config.only.iter().any(|i| {
                if let Some(prefix) = i.strip_suffix('*') {
                    key.starts_with(prefix)
                } else {
                    key == *i
                }
            });
        }
        self.config.ignore.iter().any(|i| {
            if let Some(prefix) = i.strip_suffix('*') {
                key.starts_with(prefix)
            } else {
                key == *i
            }
        })
    }

    fn add_error(&mut self, error: impl Into<String>) {
        self.diffs.push(Diff {
            key: "error".to_owned(),
            values: DiffValues::PreFormatted(error.into()),
        });
    }
}

struct Diff {
    key: String,
    values: DiffValues,
}

enum DiffValues {
    PerObject(Vec<String>),
    PreFormatted(String),
}

impl Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (name, path) in self.names.iter().zip(&self.paths) {
            writeln!(f, "{name}: {}", path.display())?;
        }

        for diff in &self.diffs {
            writeln!(f, "{}", diff.key)?;

            match &diff.values {
                DiffValues::PerObject(values) => {
                    for (filename, result) in self.names.iter().zip(values) {
                        writeln!(f, "  {filename} {result}")?;
                    }
                }
                DiffValues::PreFormatted(values) => {
                    for line in values.lines() {
                        writeln!(f, "  {line}")?;
                    }
                }
            }

            writeln!(f)?;
        }

        // Only unacknowledged gaps are rendered here. Acknowledged ones would otherwise churn every
        // malfunction `.exp` snapshot as gaps get closed; they're reported by
        // `coverage_gap_report`, which the CLI prints on every run.
        for gap in self.failing_gaps() {
            writeln!(f, "{}", gap.key)?;
            writeln!(
                f,
                "  This validation pass has no implementation for `{}`, so it checked NOTHING.",
                gap.format
            )?;
            for line in wrap_note(&gap.note, 92) {
                writeln!(f, "  {line}")?;
            }
            writeln!(
                f,
                "  Either implement it, or add `{}` to MACHO_ACKNOWLEDGED_GAPS in \
                 linker-diff/src/lib.rs with a justification.",
                gap.key
            )?;
            writeln!(f)?;
        }

        Ok(())
    }
}

impl Display for Binary<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name.fmt(f)
    }
}

impl Display for Coverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Diffed sections:")?;

        let mut total_bytes = 0;
        let mut total_diffed = 0;

        for sec in self.sections.values() {
            writeln!(
                f,
                "  {} {}: {}",
                sec.original_file,
                sec.name,
                if sec.diffed {
                    self.colour.green("true")
                } else {
                    self.colour.red("false")
                }
            )?;

            if sec.diffed {
                total_diffed += sec.num_bytes;
            }

            total_bytes += sec.num_bytes;
        }

        writeln!(
            f,
            "Diffed {total_diffed} of {total_bytes} section bytes ({}%)",
            total_diffed * 100 / total_bytes
        )?;

        Ok(())
    }
}

fn short_file_display_names(config: &Config) -> Result<Vec<String>> {
    let paths = config.filenames().collect_vec();
    if !config.display_names.is_empty() {
        if config.display_names.len() != paths.len() {
            bail!(
                "--display-names has {} names, but {} filenames were provided",
                config.display_names.len(),
                paths.len()
            );
        }
        return Ok(config.display_names.clone());
    }
    if paths.is_empty() {
        return Ok(vec![]);
    }
    let mut names = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect_vec();
    if names.iter().all(|name| {
        Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
    }) {
        names = names
            .into_iter()
            .map(|n| n.strip_suffix(".so").unwrap().to_owned())
            .collect();
    }

    if names.len() > 1 {
        // We'll stop when we get to the length of the first name. This check is here to avoid
        // infinitely looping if all the names are equal.
        let first_len = names.first().map_or(0, |n| n.len());

        // This is not quite right, since we might split in the middle of a multibyte character.
        // But this is a dev tool, so we'll punt on that for now.
        let mut iterators = names.iter().map(|n| n.bytes()).collect_vec();
        let mut n = 0;
        while first_equals_all(iterators.iter_mut().map(Iterator::next)) && n < first_len {
            n += 1;
        }
        names = names
            .iter()
            .map(|name| String::from_utf8_lossy(&name.bytes().skip(n).collect_vec()).into_owned())
            .collect_vec();
    }
    Ok(names)
}

fn first_equals_all<T: PartialEq>(mut inputs: impl Iterator<Item = T>) -> bool {
    let Some(first) = inputs.next() else {
        return true;
    };
    for next in inputs {
        if next != first {
            return false;
        }
    }
    true
}

/// Returns whether the first input is equal to at least one of the remaining values.
fn first_equals_any<T: PartialEq>(mut inputs: impl Iterator<Item = T>) -> bool {
    let Some(first) = inputs.next() else {
        return true;
    };
    for next in inputs {
        if next == first {
            return true;
        }
    }
    false
}

impl<'data> NameIndex<'data> {
    fn new(file: &File<'data>) -> NameIndex<'data> {
        let mut globals_by_name: HashMap<&[u8], Vec<object::SymbolIndex>> = HashMap::new();
        let mut locals_by_name: HashMap<&[u8], Vec<object::SymbolIndex>> = HashMap::new();
        let mut dynamic_by_name: HashMap<&[u8], Vec<object::SymbolIndex>> = HashMap::new();

        for sym in file.symbols() {
            // We only index symbols that have a section. Note this is different than the object
            // crate's `is_defined`, which imposes additional requirements that we don't want.
            if sym.section_index().is_none() {
                continue;
            }

            if let Ok(mut name) = sym.name_bytes() {
                // Wild doesn't emit local symbols that start with ".L". The other linkers mostly do
                // the same. However, GNU ld and lld, if they encounter a GOT-forming relocation to
                // such a symbol, even if they then optimise away the GOT-forming relocation, will
                // emit the symbol. This behaviour seems weird and not worth replicating, so we just
                // ignore all just symbols.
                if name.starts_with(b".L") {
                    continue;
                }

                // GNU ld sometimes emits symbols that contain the symbol version. This causes
                // problems when we go to look those symbols up, since they no longer match the name
                // of the symbol in the original input file. So for now at least, we get rid of the
                // version.
                if let Some(at_pos) = name.iter().position(|b| *b == b'@') {
                    name = &name[..at_pos];
                }

                if sym.is_global() {
                    globals_by_name.entry(name).or_default().push(sym.index());
                } else {
                    locals_by_name.entry(name).or_default().push(sym.index());
                }
            }
        }

        for sym in file.dynamic_symbols() {
            if let Ok(name) = sym.name_bytes() {
                dynamic_by_name.entry(name).or_default().push(sym.index());
            }
        }

        NameIndex {
            globals_by_name,
            locals_by_name,
            dynamic_by_name,
        }
    }
}

fn parse_string_equality(
    s: &str,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let (a, b) = s
        .split_once('=')
        .ok_or_else(|| format!("invalid key-value pair. No '=' found in `{s}`"))?;
    Ok((a.to_owned(), b.to_owned()))
}

/// # Panics
///
/// Panics on any non-ELF relocation. Every pass that reaches this must first gate on file format
/// via [`Report::require_format`], so that an unsupported format is reported as a coverage gap
/// rather than crashing the differ (or, worse, being quietly routed around).
fn get_r_type<R: arch::RType>(rel: &object::Relocation) -> R {
    let object::RelocationFlags::Elf { r_type } = rel.flags() else {
        panic!(
            "get_r_type called with non-ELF relocation flags ({:?}). The calling pass is missing a \
             `Report::require_format` gate.",
            rel.flags()
        );
    };
    R::from_raw(r_type)
}
