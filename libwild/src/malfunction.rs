//! Contains code that allows us to cause the linker to malfunction in certain ways. This is used to
//! test our tests and to test linker-diff.
//!
//! A malfunction is enabled by setting `WILD_MALFUNCTION=<name>` and only takes effect in builds
//! with debug assertions. Any name that doesn't match an injection point is a no-op, which the
//! test harness relies on to produce the "clean" half of a malfunction test.
//!
//! The integration test harness drives malfunctions via the `//#Malfunction:<name>` directive,
//! paired with a mandatory `//#MalfunctionExpectKey:<key>`. The harness links the program twice -
//! with and without the malfunction - and requires the named linker-diff key to be reported for
//! the malfunctioning link *and* to read differently there than in the clean one.
//!
//! "linker-diff reported something" is deliberately not enough. Where the test program already
//! trips an unrelated, unfixed bug - which `linker-diff-macho.c` does - that weaker rule is
//! satisfied before the malfunction is even injected, and every config passes regardless of
//! whether its corruption is detectable. Requiring a named key that *changes* is what makes each
//! malfunction a proof that some specific check really does detect something.
//!
//! ## Inventory
//!
//! ELF:
//! * `elf-incorrect-type` - writes `ET_CORE` into `e_type` (`elf_writer.rs`).
//! * `no-movzx0lsl16` - skips a relaxation (`elf_aarch64.rs`).
//! * `no-mov-indirect-to-absolute` - skips a relaxation (`elf_x86_64.rs`).
//!
//! Mach-O (all in `macho_writer.rs`), listed with the property each one breaks:
//! * `macho-drop-segment-starts` - the segment that owns fixups gets `seg_info_offset = 0`, so dyld
//!   skips it and applies none of its binds or rebases.
//! * `macho-drop-fixup` - the page's fixup chain is terminated after its first entry, so every
//!   later fixup becomes unreachable. The import table is left correct, so only a checker that
//!   walks the chain can see it. Needs a program with at least two imports.
//! * `macho-wrong-segment-offset` - `dyld_chained_starts_in_segment::segment_offset` is one page
//!   too high, so the chain is walked over the wrong bytes.
//! * `macho-bad-import-ordinal` - each `dyld_chained_import` names the right symbol but the wrong
//!   library ordinal.
//! * `macho-no-pie` - clears `MH_PIE` in the Mach-O header, silently disabling ASLR.
//! * `macho-truncate-symtab` - `LC_SYMTAB::nsyms` is one too low, hiding the last symbol.
//! * `macho-wrong-entry-point` - `LC_MAIN::entryoff` is shifted by one instruction.
//!
//! Every Mach-O malfunction above still produces a binary that links successfully; the harness
//! sets `should_run = false` for malfunction configs, so the corrupted binary is never executed.

use crate::env;

pub const ENV_NAME: &str = "WILD_MALFUNCTION";

#[inline(always)]
pub(crate) fn malfunction_point(name: &str) -> bool {
    cfg!(debug_assertions) && env::var(ENV_NAME).is_ok_and(|v| v == name)
}

#[macro_export]
macro_rules! malfunction_point_ret {
    ($name:expr, $val:expr) => {
        if $crate::malfunction::malfunction_point($name) {
            return $val;
        }
    };
}
