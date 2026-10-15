//#Config:default
//#LinkerDriver:clang
//#Object:strings-a.c
//#Object:strings-b.c

// Identical string literals appear in every object that mentions them - a header full of them gets
// a copy per translation unit. The compiler puts them in `__cstring` precisely so the linker can
// keep one copy and point every reference at it.
//
// Getting this wrong is not a size difference but a wrong answer, because folding changes what
// address a reference resolves to. The check that both objects' copies came out at the *same*
// address is what says the folding happened at all; the string comparisons are what say it folded
// the right things together.

#include <string.h>

extern const char *a_shared1, *a_shared2, *a_unique;
extern const char *b_shared1, *b_shared2, *b_unique;

int main(void) {
  if (strcmp(a_shared1, "a string in both objects")) {
    return 1;
  }
  if (strcmp(b_shared1, "a string in both objects")) {
    return 2;
  }
  if (strcmp(a_shared2, "another shared string")) {
    return 3;
  }
  if (strcmp(b_shared2, "another shared string")) {
    return 4;
  }
  if (strcmp(a_unique, "only in a")) {
    return 5;
  }
  if (strcmp(b_unique, "only in b")) {
    return 6;
  }

  // Folded, so the two objects' references have to name one copy.
  if (a_shared1 != b_shared1) {
    return 7;
  }
  if (a_shared2 != b_shared2) {
    return 8;
  }

  // And distinct strings must not have been folded together.
  if (a_unique == b_unique) {
    return 9;
  }

  return 42;
}
