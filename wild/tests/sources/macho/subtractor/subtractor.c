//#Config:default
//#LinkerDriver:clang
//#Object:subtractor-data.s

// `ARM64_RELOC_SUBTRACTOR` and `ARM64_RELOC_ADDEND` are both only half a relocation: each one
// modifies the relocation that follows it, so applying them one at a time gets the wrong answer.
// A subtractor stores the distance between two symbols, which - unlike a lone pointer-sized
// absolute - must not be given a rebase, since a difference doesn't move when dyld slides the
// image. An addend supplies a displacement in the field that would otherwise name a symbol.

extern long distance;
extern long displaced;
extern int anchor[4];

int main(void) {
  // `_target_b` is one four-byte instruction past `_target_a`.
  if (distance != 4) { return 1; }
  // `displaced` was formed as `anchor + 8`, expressed as an addend on the anchor symbol.
  if (displaced != (long)(anchor + 2)) { return 2; }
  return 42;
}
