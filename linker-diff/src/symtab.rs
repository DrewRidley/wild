use crate::Binary;
use crate::Result;
use anyhow::bail;
use linker_utils::elf::sht;
use object::Object as _;
use object::ObjectSymbol;
use object::read::elf::SectionHeader as _;
use object::read::macho::LoadCommandVariant;
use object::read::macho::Nlist as _;
use std::ops::Not;

pub(crate) fn validate_debug(object: &Binary) -> Result {
    validate(object, false)
}

pub(crate) fn validate_dynamic(object: &Binary) -> Result {
    validate(object, true)
}

/// Mach-O counterpart of [`validate_debug`]. Registered under its own key rather than sharing
/// `.symtab`, because a Mach-O-only finding must not be suppressible by an ignore key that would
/// also blind the ELF check.
///
/// Presence and consistency are deliberately two separate passes. Wild currently emits no
/// LC_DYSYMTAB at all, so the presence key is suppressed as a known defect - and if consistency
/// shared that key, it would be suppressed along with it and would silently stop checking anything
/// the day Wild does start emitting one.
pub(crate) fn validate_macho_dysymtab_present(object: &Binary) -> Result {
    let object::File::MachO64(macho_file) = object.file else {
        return Ok(());
    };
    if read_macho_dysymtab(macho_file)?.is_none() {
        bail!("No LC_DYSYMTAB load command");
    }
    Ok(())
}

pub(crate) fn validate_macho_dysymtab_partition(object: &Binary) -> Result {
    let object::File::MachO64(macho_file) = object.file else {
        return Ok(());
    };
    validate_macho_dysymtab(macho_file, object.file.endianness())
}

fn validate(object: &Binary, dynamic: bool) -> Result {
    let e = object.file.endianness();

    match object.file {
        object::File::Elf64(elf_file) => {
            let mut symtab_info = 0;
            let (symtab_section_type, mut symbols) = if dynamic {
                (sht::DYNSYM, object.file.dynamic_symbols())
            } else {
                (sht::SYMTAB, object.file.symbols())
            };

            for section in elf_file.elf_section_table().iter() {
                if section.sh_type(e) == symtab_section_type {
                    symtab_info = section.sh_info(e);
                }
            }

            let first_non_local = symbols.find_map(|sym| sym.is_local().not().then(|| sym.index()));
            if let Some(first_non_local) = first_non_local
                && first_non_local.0 != symtab_info as usize
            {
                bail!("info={symtab_info}, but first non-local is {first_non_local}")
            }
        }
        other => bail!(
            "ELF symtab validation was called for `{}`",
            crate::file_format_name(other)
        ),
    }
    Ok(())
}

fn read_macho_dysymtab<'data>(
    macho_file: &object::read::macho::MachOFile64<'data, object::Endianness>,
) -> Result<Option<&'data object::macho::DysymtabCommand<object::Endianness>>> {
    let mut load_commands = macho_file.macho_load_commands()?;
    while let Some(load_command) = load_commands.next()? {
        if let LoadCommandVariant::Dysymtab(command) = load_command.variant()? {
            return Ok(Some(command));
        }
    }
    Ok(None)
}

/// Validates `LC_DYSYMTAB` against `LC_SYMTAB`.
///
/// This is the Mach-O analogue of the ELF `sh_info`-points-at-the-first-non-local check above.
/// `LC_DYSYMTAB` doesn't describe a separate symbol table; it declares that the single `LC_SYMTAB`
/// is partitioned into three contiguous runs - local, externally-defined, undefined - and gives
/// the index and count of each. `dyld` and every Mach-O consumer trust those indices without
/// re-deriving them, so if the declared partition doesn't match the actual ordering of the nlist
/// entries, tools silently read the wrong symbols.
///
/// Written from the `dysymtab_command` / `nlist_64` definitions in `<mach-o/loader.h>` and
/// `<mach-o/nlist.h>`.
fn validate_macho_dysymtab(
    macho_file: &object::read::macho::MachOFile64<'_, object::Endianness>,
    endian: object::Endianness,
) -> Result {
    /// `n_type` mask selecting the symbol's type field.
    const N_TYPE: u8 = 0x0e;
    /// `n_type` bit: the symbol is external.
    const N_EXT: u8 = 0x01;
    /// `N_TYPE` value: undefined.
    const N_UNDF: u8 = 0x0;
    /// `n_type` bit: the entry is a stab (debug) entry. Stabs live among the local symbols.
    const N_STAB: u8 = 0xe0;

    let mut symtab_count: Option<u32> = None;

    let mut load_commands = macho_file.macho_load_commands()?;
    while let Some(load_command) = load_commands.next()? {
        if let LoadCommandVariant::Symtab(symtab) = load_command.variant()? {
            symtab_count = Some(symtab.nsyms.get(endian));
        }
    }
    let dysymtab = read_macho_dysymtab(macho_file)?;

    let Some(dysymtab) = dysymtab else {
        // Absence is reported by `validate_macho_dysymtab_present` under its own key, so that
        // suppressing the (currently failing) presence check doesn't also suppress this one.
        return Ok(());
    };
    let Some(nsyms) = symtab_count else {
        bail!("LC_DYSYMTAB is present but LC_SYMTAB is not");
    };

    let ilocal = dysymtab.ilocalsym.get(endian);
    let nlocal = dysymtab.nlocalsym.get(endian);
    let iextdef = dysymtab.iextdefsym.get(endian);
    let nextdef = dysymtab.nextdefsym.get(endian);
    let iundef = dysymtab.iundefsym.get(endian);
    let nundef = dysymtab.nundefsym.get(endian);

    // The three runs must tile [0, nsyms) exactly, in order and without gaps.
    if ilocal != 0 {
        bail!("LC_DYSYMTAB ilocalsym={ilocal}, expected 0");
    }
    if iextdef != nlocal {
        bail!(
            "LC_DYSYMTAB iextdefsym={iextdef}, but ilocalsym+nlocalsym={}",
            ilocal + nlocal
        );
    }
    if iundef != iextdef + nextdef {
        bail!(
            "LC_DYSYMTAB iundefsym={iundef}, but iextdefsym+nextdefsym={}",
            iextdef + nextdef
        );
    }
    if iundef + nundef != nsyms {
        bail!(
            "LC_DYSYMTAB partition covers {} symbols, but LC_SYMTAB has {nsyms}",
            iundef + nundef
        );
    }

    // Now check that the nlist entries really are in that order, so that a consumer indexing
    // straight into the undefined run gets undefined symbols.
    let symbols = macho_file.macho_symbol_table();
    for index in 0..nsyms {
        let Ok(nlist) = symbols.symbol(object::SymbolIndex(index as usize)) else {
            bail!("LC_SYMTAB claims {nsyms} symbols, but symbol {index} could not be read");
        };
        let n_type = nlist.n_type().0;
        let is_stab = n_type & N_STAB != 0;
        let is_ext = !is_stab && n_type & N_EXT != 0;
        let is_undef = !is_stab && n_type & N_TYPE == N_UNDF;

        let expected = if index < nlocal {
            "local"
        } else if index < iundef {
            "external-defined"
        } else {
            "undefined"
        };

        let actual = if is_stab || !is_ext {
            "local"
        } else if is_undef {
            "undefined"
        } else {
            "external-defined"
        };

        if expected != actual {
            let name = nlist
                .name(endian, symbols.strings())
                .map_or(std::borrow::Cow::Borrowed("<unreadable>"), |n| {
                    String::from_utf8_lossy(n)
                });
            bail!(
                "LC_DYSYMTAB says symbol {index} (`{name}`) is {expected}, \
                 but its n_type=0x{n_type:x} makes it {actual}"
            );
        }
    }

    Ok(())
}
