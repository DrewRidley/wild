//#Object:runtime.c
//#ExpectSym:_main
//#TestUpdateInPlace:true
//#DiffIgnore:section.__unwind_info

// Regression test for LC_MAIN's `entryoff` being set to the start of __text rather than to the
// address of the entry symbol. `decoy` is defined before `main`, so it gets laid out first in
// __text. With the bug, execution starts in `decoy` and the program exits 1 instead of 42.
//
// Note that this has to be in the same file as `main` rather than a separate object, because the
// test harness always passes the file defining `main` as the first linker input.

#include "../common/runtime.h"

void decoy(void) { exit_syscall(1); }

void main(void) { exit_syscall(42); }
