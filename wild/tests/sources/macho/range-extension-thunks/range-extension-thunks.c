//#Config:default
//#LinkerDriver:clang
//#Object:bulk0.s
//#Object:bulk1.s
//#Object:bulk2.s
//#Object:bulk3.s
//#Object:bulk4.s
//#Object:bulk5.s
//#Object:far.s

// A branch that can't reach its target.
//
// `ARM64_RELOC_BRANCH26` holds a 26-bit signed word displacement, so it reaches 128 MiB. Past that
// the instruction physically cannot encode the target and there is no way to fix it up in place -
// the linker has to plant an island within reach that does the long jump, and point the branch at
// that instead. Without one the link fails outright, so this is a wall rather than a slow path.
//
// Note this test is expensive: the inputs come to 144 MiB, and so does the output. That is the
// cheapest way to get past a 128 MiB reach, and the ELF range-extension test carries the same cost
// for the same reason. The padding is split across many 1 MiB functions rather than one large one
// because ld64 places its islands between atoms, and an atom bigger than the branch range defeats
// that - it cannot link a single oversized block either.

int far_target(void);

int main(void) {
  // 144 MiB of padding sits between here and the target.
  return far_target();
}
