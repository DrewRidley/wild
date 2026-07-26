//#Config:default
//#LinkerDriver:clang
//#Object:only-data.c
//#ExpectSym:_main
//#DiffIgnore:section.__unwind_info

// An input object that contains only initialised data and no code at all. This
// is completely ordinary in real links (generated tables, `const` blobs, Rust
// `.rodata`-only CGUs). Such an object still carries a zero-sized `__TEXT,__text`
// section, which used to make wild abort while laying out the Mach-O output.
//
// It also covers GOT-load relaxation: `table` is defined by another object, so the
// compiler reaches it through the GOT, and the linker has to turn that back into
// direct page-relative addressing.

#include <stdio.h>

extern int table[4];

int main(void) {
  int total = table[0] + table[1] + table[2] + table[3];
  if (total != 42) {
    printf("bad total: %d\n", total);
    return 1;
  }
  printf("total=%d\n", total);
  return 42;
}
