// Malfunction tests for Mach-O. Each config below links this program with one deliberate
// corruption enabled in Wild's Mach-O writer, then requires linker-diff to notice. If a check
// stops working - or was never really implemented - the corresponding config fails with
// "No diff reported when running with malfunction ...". That is the point: it makes an
// unimplemented check indistinguishable from a broken one, instead of from a passing one.
//
// The program deliberately:
//   * imports several symbols from libSystem, so the __got chained-fixup chain has more than one
//     link and truncating it is observable, and
//   * puts a pointer to a global in initialised data, so a rebase is required in __DATA.
//
// It uses the libc/clang flavour rather than the freestanding runtime.c flavour, because the
// freestanding flavour has no dylib imports at all and therefore no fixups to corrupt.

//#AbstractConfig:default
//#LinkerDriver:clang
//#DiffIgnore:section.__unwind_info

// Drops the `seg_info_offset` for the segment that owns the fixups, so dyld skips the whole
// segment. This is the shape of the real bug that motivated Mach-O verification work, so any
// checker claiming to detect that bug must fail this config.
//#Config:malfunction-macho-drop-segment-starts:default
//#Malfunction:macho-drop-segment-starts

// Truncates the page's fixup chain after its first entry. The import table is untouched, so only
// a checker that walks the chain notices.
//#Config:malfunction-macho-drop-fixup:default
//#Malfunction:macho-drop-fixup

// NOT ENABLED: the `macho-wrong-segment-offset` malfunction (starts record points one page too
// high). The injection point exists in macho_writer.rs and works, but this corruption is already
// caught by `verify_chained_fixups_segment_offsets` in integration_tests.rs, which runs as an
// output-binary assertion *before* any diffing. The harness has no notion of "this malfunction is
// expected to trip a binary assertion", so enabling a config for it produces a hard test failure
// ("Chained fixups segment 3 has segment_offset 0xc000, expected offset 0x8000") rather than a
// diff snapshot. To enable it, the harness must first skip output-binary assertions - or treat a
// failing one as a successful detection - when a malfunction is active. Until then, verify it by
// hand: link with WILD_MALFUNCTION=macho-wrong-segment-offset and observe that assertion fire.

// Binds every import against the wrong library ordinal while keeping the symbol names correct.
//#Config:malfunction-macho-bad-import-ordinal:default
//#Malfunction:macho-bad-import-ordinal

// Clears MH_PIE, silently disabling ASLR for the output binary.
//#Config:malfunction-macho-no-pie:default
//#Malfunction:macho-no-pie

// Under-reports LC_SYMTAB's nsyms, hiding the last symbol.
//#Config:malfunction-macho-truncate-symtab:default
//#Malfunction:macho-truncate-symtab

// Shifts LC_MAIN's entryoff by one instruction.
//#Config:malfunction-macho-wrong-entry-point:default
//#Malfunction:macho-wrong-entry-point

#include <stdio.h>
#include <string.h>

int g = 7;
int* pg = &g;

int main(void) {
  char buf[16];
  memset(buf, 0, sizeof(buf));
  printf("%d %zu\n", *pg, strlen(buf));
  return *pg == 7 ? 42 : 1;
}
