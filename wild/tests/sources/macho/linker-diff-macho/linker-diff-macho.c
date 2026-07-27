// Malfunction tests for Mach-O. Each config below links this program with one deliberate
// corruption enabled in Wild's Mach-O writer, then requires linker-diff to notice.
//
// "Notice" is defined by the `//#MalfunctionExpectKey:` directive on each config: the named
// linker-diff key must be reported for the corrupted link AND must read differently there than it
// does for the same program linked clean. The harness produces that clean link itself.
//
// Requiring a *named, changed* key rather than merely a non-empty report matters here, because
// this program's report is not empty to begin with: `int *pg = &g;` below trips a real, unfixed
// rebase bug, so `macho.fixups`, `macho.fixups.segments` and `macho.dyld-info.chain-starts` are
// already reported before any malfunction is injected. Under the old "did linker-diff say
// anything?" rule every config below passed on the strength of that pre-existing diff - including
// `macho-wrong-entry-point`, which nothing in linker-diff could detect at all until the
// `macho.entry-point` pass was written.
//
// The expected keys are also chosen so that this test keeps its meaning once the rebase bug is
// fixed: each names the check specific to its own corruption, and each is compared against the
// clean link rather than against a hard-coded baseline.
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
// Detection requires something to diff against. Apple's `ld` ships with the command line tools,
// so it's the reference that is actually present on a developer's machine; `ld64.lld`, the
// default Mach-O reference, usually isn't installed. Naming it explicitly also keeps the
// comparison two-way when both are available.
//#ReferenceLinkers:ld

// Drops the `seg_info_offset` for the segment that owns the fixups, so dyld skips the whole
// segment. This is the shape of the real bug that motivated Mach-O verification work, so any
// checker claiming to detect that bug must fail this config.
//#Config:malfunction-macho-drop-segment-starts:default
//#Malfunction:macho-drop-segment-starts
//#MalfunctionExpectKey:macho.fixups.segments

// Truncates the page's fixup chain after its first entry. The import table is untouched, so only
// a checker that walks the chain notices.
//#Config:malfunction-macho-drop-fixup:default
//#Malfunction:macho-drop-fixup
//#MalfunctionExpectKey:macho.fixups

// Points the starts record one page too high, so every fixup slot in the chain is computed from
// the wrong base.
//
// This one is also caught by `verify_chained_fixups_segment_offsets` in integration_tests.rs.
// That used to make it unusable as a malfunction config, because the binary assertion fired
// before any diffing and produced a hard failure rather than a diff snapshot. `check_macho_path`
// now skips the structural self-consistency verifiers when a malfunction is active, so detection
// is left to linker-diff, where it belongs.
//#Config:malfunction-macho-wrong-segment-offset:default
//#Malfunction:macho-wrong-segment-offset
//#MalfunctionExpectKey:macho.fixups.presence

// Binds every import against the wrong library ordinal while keeping the symbol names correct.
//#Config:malfunction-macho-bad-import-ordinal:default
//#Malfunction:macho-bad-import-ordinal
//#MalfunctionExpectKey:macho.fixups.imports

// Clears MH_PIE, silently disabling ASLR for the output binary.
//#Config:malfunction-macho-no-pie:default
//#Malfunction:macho-no-pie
//#MalfunctionExpectKey:file-header.flags.MH_PIE

// Under-reports LC_SYMTAB's nsyms, hiding the last symbol.
//#Config:malfunction-macho-truncate-symtab:default
//#Malfunction:macho-truncate-symtab
//#MalfunctionExpectKey:macho.dyld-info.exports

// Shifts LC_MAIN's entryoff by one instruction.
//#Config:malfunction-macho-wrong-entry-point:default
//#Malfunction:macho-wrong-entry-point
//#MalfunctionExpectKey:macho.entry-point

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
