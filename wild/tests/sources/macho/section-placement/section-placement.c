//#Config:default
//#LinkerDriver:clang
//#Object:placement-data.s
//#DiffIgnore:section.__unwind_info

// Input sections that wild has no built-in output section for. Every one of these used to abort
// the link: layout would let each object reserve bytes for the section, but nothing gave the
// section a place in any segment, so it got no space in the output file and the write ran off the
// end of the buffer part way through.
//
// `__literal16` and friends are what a compiler emits for constant pools, and an unrecognised
// section like `__mystuff` is what hand-written assembly and other toolchains produce. `__bss` and
// `__common` are ordinary zerofill sections that simply had no mapping.

extern const long long literal16[2];
extern long long mystuff;
extern long long zeroed;
extern long long common_value;

int main(void) {
  if (literal16[0] != 0x1122334455667788LL) { return 1; }
  if (mystuff != 0x0f0f0f0f0f0f0f0fLL) { return 2; }
  // A zerofill section takes up no space in the file but must still be readable and zeroed.
  if (zeroed != 0) { return 3; }
  if (common_value != 0) { return 4; }
  return 42;
}
