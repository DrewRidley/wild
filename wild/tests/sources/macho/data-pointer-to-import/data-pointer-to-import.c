// A global initialised to the address of a function in a dylib. The slot needs a bind rather than
// a rebase: before binds were emitted for anything outside __got, it got a rebase of a nonsense
// address and the binary took SIGBUS the first time the pointer was called.
//#LinkerDriver:clang

#include <stdio.h>

int (*fn)(const char *, ...) = printf;

int main(void) {
  fn("via pointer\n");
  return 42;
}
