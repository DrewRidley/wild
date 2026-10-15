//#Config:default
//#LinkerDriver:clang
//#Object:helper.c
//#ExpectSym:_main
//#ExpectSym:_level1

// `main` is deliberately the *last* function in this file, and part of the work
// lives in a second input object. That exercises entry-point resolution
// (LC_MAIN's entryoff) against a symbol that is neither the first symbol of the
// first section nor at the start of __text.
//
// Note: the harness always passes the object defining `main` first on the link
// line (see the comment in the ELF `entry-point` test), so "not first" is
// achieved by ordering within this file plus the extra `//#Object:helper.c`.

#include <stdio.h>

int helper_value(void);

static int level3(int x) { return x + 1; }

static int level2(int x) { return level3(x) * 2; }

int level1(int x) { return level2(x) + 3; }

int main(void) {
  int v = level1(4) + helper_value();
  if (v != 42) {
    printf("bad value: %d\n", v);
    return 1;
  }
  printf("v=%d\n", v);
  return 42;
}
