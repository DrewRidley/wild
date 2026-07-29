//#Config:default
//#LinkerDriver:clang++
//#Object:weak-a.cc
//#Object:weak-b.cc

// The same inline function compiled into two objects.
//
// Every translation unit that uses a template or an inline function gets its own copy, all marked
// weak, and the linker is meant to keep one. ELF gets this for free because the copies arrive in
// COMDAT groups and the losing group is discarded as it's read; Mach-O has no groups, so the
// duplicates are ordinary content that only the symbol table tells apart. Without dropping them
// deliberately, every copy reaches the output.
//
// Note this has to hold whether or not unreachable code is being removed. With `-dead_strip` the
// losing copies fall away on their own, because references go to the winner and nothing reaches
// them - so a test that only ran with stripping on would pass even if coalescing did nothing.

#include <cstdio>

template <typename T>
T shared_template(T a, T b) {
  return a + b;
}

// Instantiated in both objects, so both carry a copy.
extern int from_a();
extern int from_b();

// Taking the address in both places is what makes the folding observable: if the copies had not
// been coalesced, the two objects would name different addresses for the same function.
using Fn = int (*)(int, int);
extern Fn address_from_a();
extern Fn address_from_b();

int main() {
  if (from_a() != 30) {
    return 1;
  }
  if (from_b() != 70) {
    return 2;
  }

  if (address_from_a() != address_from_b()) {
    std::printf("not coalesced: %p vs %p\n", (void*)address_from_a(), (void*)address_from_b());
    return 3;
  }

  if (shared_template(1, 2) != 3) {
    return 4;
  }
  return 42;
}
