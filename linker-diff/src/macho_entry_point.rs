//! Independent check of a Mach-O executable's entry point.
//!
//! Nothing else in this crate looks at `LC_MAIN` / `LC_UNIXTHREAD`, so before this module a linker
//! could point the entry point at the wrong instruction - or at the wrong function entirely - and
//! every pass would still agree. The `macho-wrong-entry-point` malfunction exercises exactly that.
//!
//! The comparison is **symbolic**. The raw `entryoff` legitimately differs between linkers because
//! they lay `__TEXT` out differently (on the Mach-O malfunction test program, Wild produces 1088
//! and ld-prime 1272, and both are correct). What must agree is the *symbol* the entry point lands
//! on, and the offset within that symbol. Comparing `_main` against `_main` passes; comparing
//! `_main` against `_main+0x4` fails, which is what catches an entry point that has been nudged by
//! one instruction.
//!
//! Layout, from `<mach-o/loader.h>`:
//!
//! ```text
//! struct entry_point_command {   // LC_MAIN, 0x80000028
//!     uint32_t cmd;
//!     uint32_t cmdsize;
//!     uint64_t entryoff;    // file (not VM) offset of main(), relative to the mach header
//!     uint64_t stacksize;
//! };
//!
//! struct thread_command {       // LC_UNIXTHREAD, 0x5
//!     uint32_t cmd;
//!     uint32_t cmdsize;
//!     uint32_t flavor;
//!     uint32_t count;
//!     uint32_t state[count];    // register state; the PC is at a flavour-specific index
//! };
//! ```
//!
//! `LC_MAIN`'s `entryoff` is a *file* offset from the start of the mach header, so the VM address
//! is `image_base + entryoff`. `LC_UNIXTHREAD`'s PC is already a VM address.

use crate::Binary;
use crate::Diff;
use crate::DiffValues;
use crate::Report;
use crate::Result;
use crate::macho_fixups::ImageInfo;
use crate::macho_fixups::describe_address;
use crate::macho_fixups::read_image_info;
use anyhow::bail;
use itertools::Itertools as _;
use object::Object as _;
use object::macho::LC_MAIN;
use object::macho::LC_UNIXTHREAD;
use object::read::macho::LoadCommandVariant;

/// `ARM_THREAD_STATE64`. `pc` follows `x[0..29]`, `fp`, `lr` and `sp`, so it is register 32.
const ARM_THREAD_STATE64: u32 = 6;
const ARM_THREAD_STATE64_PC_INDEX: usize = 32;

/// `x86_THREAD_STATE64`. `rip` follows the 16 general purpose registers.
const X86_THREAD_STATE64: u32 = 4;
const X86_THREAD_STATE64_RIP_INDEX: usize = 16;

/// What a binary says its entry point is, in a form that can be compared between linkers.
enum EntryPoint {
    /// `LC_MAIN`. `description` is symbolic - e.g. `_main` or `_main+0x4`.
    Main { description: String },

    /// `LC_UNIXTHREAD`, used by static executables and by some non-Apple producers.
    UnixThread { description: String },

    /// No entry point load command at all. Normal for a dylib or bundle, a bug for an executable.
    None,
}

impl std::fmt::Display for EntryPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntryPoint::Main { description } => write!(f, "LC_MAIN {description}"),
            EntryPoint::UnixThread { description } => write!(f, "LC_UNIXTHREAD {description}"),
            EntryPoint::None => write!(f, "<none>"),
        }
    }
}

/// The raw entry point address, before symbolisation. Split out from `analyse` so that the
/// address-to-symbol step can't accidentally swallow a parse failure.
fn read_entry_address(bin: &Binary, image: &ImageInfo) -> Result<Option<(bool, u64)>> {
    let object::File::MachO64(file) = bin.file else {
        bail!("Not a 64-bit Mach-O file");
    };

    let e = file.endianness();
    let mut load_commands = file.macho_load_commands()?;

    while let Some(load_command) = load_commands.next()? {
        match load_command.variant()? {
            LoadCommandVariant::EntryPoint(entry_point) => {
                // `entryoff` is a file offset relative to the mach header, which is at
                // `image_base`. `__TEXT` maps file offset 0, so this is a plain addition.
                let entryoff = entry_point.entryoff.get(e);
                return Ok(Some((true, image.image_base + entryoff)));
            }
            LoadCommandVariant::Thread(thread, state_data)
                if thread.cmd.get(e) == LC_UNIXTHREAD =>
            {
                let pc = read_thread_state_pc(e, state_data)?;
                return Ok(Some((false, pc)));
            }
            _ => {
                // `object` decodes `LC_MAIN` as `EntryPoint` regardless of the raw command number,
                // but be explicit that we've considered - and rejected - nothing else.
                debug_assert_ne!(load_command.cmd(), LC_MAIN);
            }
        }
    }

    Ok(None)
}

/// Pulls the program counter out of an `LC_UNIXTHREAD` payload.
///
/// Deliberately errors rather than returning a placeholder for flavours we don't know: an
/// undecoded entry point that compares equal on both sides would be a check that verifies nothing.
fn read_thread_state_pc(e: object::Endianness, state_data: &[u8]) -> Result<u64> {
    // flavor: u32, count: u32, then `count` 32-bit words of register state.
    if state_data.len() < 8 {
        bail!(
            "LC_UNIXTHREAD payload is truncated ({} bytes)",
            state_data.len()
        );
    }
    let flavor = u32::from_le_bytes(state_data[0..4].try_into().expect("4 bytes"));
    let flavor = match e {
        object::Endianness::Little => flavor,
        object::Endianness::Big => flavor.swap_bytes(),
    };

    let register_index = match flavor {
        ARM_THREAD_STATE64 => ARM_THREAD_STATE64_PC_INDEX,
        X86_THREAD_STATE64 => X86_THREAD_STATE64_RIP_INDEX,
        other => bail!("Unsupported LC_UNIXTHREAD flavor {other}"),
    };

    // Registers are 64-bit for both supported flavours, and start after flavor + count.
    let offset = 8 + register_index * 8;
    let Some(bytes) = state_data.get(offset..offset + 8) else {
        bail!("LC_UNIXTHREAD payload too short to hold register {register_index}");
    };
    let raw = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
    Ok(match e {
        object::Endianness::Little => raw,
        object::Endianness::Big => raw.swap_bytes(),
    })
}

fn analyse(bin: &Binary) -> Result<EntryPoint> {
    let image = read_image_info(bin)?;

    let Some((is_lc_main, address)) = read_entry_address(bin, &image)? else {
        return Ok(EntryPoint::None);
    };

    let description = describe_address(bin, &image, address);

    Ok(if is_lc_main {
        EntryPoint::Main { description }
    } else {
        EntryPoint::UnixThread { description }
    })
}

pub(crate) fn report_diffs(report: &mut Report, objects: &[Binary]) {
    // Mach-O only. ELF's entry point is covered by the `file-header` pass.
    if objects.is_empty()
        || !objects
            .iter()
            .all(|obj| matches!(obj.file, object::File::MachO64(_)))
    {
        return;
    }

    let values = objects
        .iter()
        .map(|obj| match analyse(obj) {
            Ok(entry_point) => entry_point.to_string(),
            Err(error) => format!("error: {error}"),
        })
        .collect_vec();

    let any_error = values.iter().any(|value| value.starts_with("error: "));

    if any_error || !report.config.match_multi(values.iter()) {
        report.add_diff(Diff {
            key: "macho.entry-point".to_owned(),
            values: DiffValues::PerObject(values),
        });
    }
}
