//#Config:default
//#LinkerDriver:clang
//#CompArgs:-fcommon
//#Object:common-symbol-other.c:-fcommon
//#ExpectSym:_main

// Tentative definitions compiled with -fcommon: each object that mentions one emits a common
// symbol, spelled in the object as an undefined external with a size in its value. The linker has
// to merge them into one zero-filled definition, as large and as aligned as the biggest claim.
// mimalloc is built this way, which is what made a link of it fail with an undefined symbol.

#include <stdint.h>
#include <stdio.h>

// Declared at 16 bytes here and 32 in the other object, where it is also read back.
int shared_counters[4];

// 64-byte aligned, like mimalloc's page map, and private to the image.
char aligned_buf[64] __attribute__((aligned(64), visibility("hidden")));

extern int* other_counters(void);
extern char* other_aligned_buf(void);
extern int other_sum(void);

int main(void) {
  for (int i = 0; i < 4; i++) {
    if (shared_counters[i] != 0) {
      return 1;
    }
  }
  for (int i = 0; i < 4; i++) {
    shared_counters[i] = i + 1;
  }

  // One definition: the other object sees what this one wrote, and the bigger size won, so the
  // upper half is there too and starts out zero.
  if (other_counters() != shared_counters || other_sum() != 10) {
    return 2;
  }

  if (((uintptr_t)aligned_buf & 63) != 0 || other_aligned_buf() != aligned_buf) {
    return 3;
  }

  printf("ok\n");
  return 42;
}
