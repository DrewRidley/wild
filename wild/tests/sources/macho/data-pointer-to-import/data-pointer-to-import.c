// A global initialised to the address of a function in a dylib. The slot needs a bind, which needs
// an import ordinal, but only symbols that get a __got or __stubs entry are recorded as imports -
// and this one is never called directly, so it gets neither. Wild reports that instead of writing
// the nonsense address it used to, which took SIGBUS the first time the pointer was used.
//#LinkerDriver:clang
// ld64 and lld both link this fine, so there is nothing to compare against until wild can too.
//#ReferenceLinkers:
//#ExpectErrorWild:only referenced by a pointer in data

#include <stdio.h>

int (*fn)(const char *, ...) = printf;

int main(void) {
  fn("via pointer\n");
  return 42;
}
