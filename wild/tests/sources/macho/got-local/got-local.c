//#Config:default
//#LinkerDriver:clang
//#Object:got-local-data.s

// A reference that stores where a symbol's GOT slot is, rather than reading through it, for a
// symbol defined in this image.
//
// GOT-load relocations are relaxed into direct addressing whenever the address is known at link
// time, so a locally defined symbol normally gets no slot at all. This one can't be relaxed:
// whoever reads the stored address dereferences it, so the slot has to exist and hold the symbol's
// address. That is how an `__eh_frame` CIE reaches a personality routine defined in the same image,
// which is what Rust does - so without this, keeping `__eh_frame` fails the link outright.

#include <stdint.h>

extern int got_delta;
int target(void);

int main(void) {
  // The stored value is the distance from itself to the GOT slot.
  uintptr_t slot = (uintptr_t)&got_delta + (intptr_t)got_delta;
  int (*via_got)(void) = *(int (**)(void))slot;

  // Reaching the function through the slot and calling it directly must agree - the two paths must
  // not have been handed different addresses.
  if (via_got != target) {
    return 1;
  }
  if (via_got() != 7) {
    return 2;
  }
  return 42;
}
