//#Config:default
//#LinkerDriver:clang
//#DiffIgnore:section.__init_offsets
//#DiffIgnore:section.__mod_init_func

// Nothing in the image refers to an initialiser list - dyld finds it from the section type - so a
// linker that only keeps sections something points at drops it, and the constructors silently
// never run. That's a wrong answer with no diagnostic, which is the worst kind: the program runs
// and quietly sees uninitialised state.

#include <stdio.h>

static int ctor_ran;
static int value;

__attribute__((constructor)) static void init(void) {
  ctor_ran = 1;
  value = 40;
}

int main(void) {
  if (!ctor_ran) {
    printf("constructor did not run\n");
    return 1;
  }
  return value + 2;
}
