//#Config:default
//#LinkerDriver:clang
//#ExpectSym:_main
//#DiffIgnore:section.__unwind_info
//#KnownFailure:wild emits no chained-fixup rebase for pointers in __data, so the binary dereferences an un-slid address and dies with SIGSEGV. ld64 emits the rebase and the same binary exits 42.

// Pointers stored in initialised data. Every initialiser below needs a
// load-time rebase (a chained-fixup entry in __DATA) because the value written
// by the compiler is a link-time address that dyld must slide by the load bias.
//
// This covers three shapes that are easy to get wrong independently:
//   * a bare pointer to a global      (_pg)
//   * an array of pointers            (_parr)
//   * a pointer inside a struct       (_h, including a pointer to a string
//                                      literal, which lives in __TEXT/__cstring
//                                      rather than __DATA)
//
// If the linker emits no rebase for any of these, the program dereferences an
// un-slid address and dies with SIGSEGV as soon as ASLR gives a non-zero slide.

#include <stdio.h>

struct holder {
  const char* name;
  int* value;
};

int g = 7;
int* pg = &g;

int a = 10;
int b = 25;
int* parr[2] = {&a, &b};

struct holder h = {"answer", &g};

int main(void) {
  int total = *pg + *parr[0] + *parr[1];
  if (total != 42) {
    printf("bad total: %d\n", total);
    return 1;
  }
  if (h.value != pg) {
    return 2;
  }
  if (h.name[0] != 'a') {
    return 3;
  }
  printf("%s=%d\n", h.name, total);
  return 42;
}
