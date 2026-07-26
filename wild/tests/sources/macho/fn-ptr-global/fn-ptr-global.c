//#Config:default
//#LinkerDriver:clang
//#ExpectSym:_main
//#DiffIgnore:section.__unwind_info
//#KnownFailure:wild emits no chained-fixup rebase for function pointers in __data, so the indirect call branches to an un-slid address and the binary dies with SIGSEGV. ld64 emits the rebases and the same binary exits 42.

// Indirect calls through function pointers held in initialised data. Like data
// pointers these require a load-time rebase, but the failure mode is worse: an
// un-slid code address is *branched to* rather than loaded from, so a missing
// fixup can transfer control anywhere.
//
// `main` is defined first on purpose so that this test isolates the fixup
// behaviour from LC_MAIN entry-point selection - see `main-not-first` for the
// test that covers the latter.

#include <stdio.h>

static int add_two(int x);
static int times_two(int x);

extern int (*global_fn)(int);
extern int (*global_table[2])(int);

int main(void) {
  int v = global_fn(19);
  v = global_table[0](v);
  if (v != 42) {
    printf("bad value: %d\n", v);
    return 1;
  }
  if (global_table[1](0) != 2) {
    return 2;
  }
  printf("v=%d\n", v);
  return 42;
}

static int add_two(int x) { return x + 2; }
static int times_two(int x) { return x * 2; }

int (*global_fn)(int) = add_two;
int (*global_table[2])(int) = {times_two, add_two};
