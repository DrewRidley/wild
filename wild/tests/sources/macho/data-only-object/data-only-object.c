//#Config:default
//#LinkerDriver:clang
//#Object:only-data.c
//#ExpectSym:_main
//#DiffIgnore:section.__unwind_info
//#KnownFailure:wild panics while laying out the output when an input object contains only data and no code (todo!() in Platform::is_zero_sized_section_content). ld64 links it and the binary exits 42.

// An input object that contains only initialised data and no code at all. This
// is completely ordinary in real links (generated tables, `const` blobs, Rust
// `.rodata`-only CGUs) but currently makes wild abort while laying out the
// Mach-O output.

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
