//#Config:default
//#LinkerDriver:clang
//#Object:debug-map-helper.c
//#CompArgs:-g
//#LinkArgs:-g
//#ExpectSym:_main

// The debug map, which is how a Mach-O image says where its debug info went.
//
// Mach-O doesn't gather DWARF into the linked image. It stays in the object files, and the image
// carries only a map back to them - stabs naming each object and where its functions ended up.
// `dsymutil` and `lldb` read that map to find the DWARF; without it a `-g` link produces something
// that cannot be debugged at all, with the information sitting in the `.o` files and nothing
// saying so.
//
// What this test can check by itself is that the map is measured and written consistently: the
// space for it is reserved while sizing the symbol table and filled in while writing it, from two
// separate walks of the same symbols, and a disagreement between them is a hard error rather than
// a quiet one. Two objects rather than one, because the map is per object and a mistake in where
// one ends and the next begins only shows up with more than one.
//
// That the resulting map is usable - that `dsymutil` builds a `.dSYM` from it and `lldb` can put a
// breakpoint on a source line - is checked by hand against ld64's output, since running those
// tools is beyond what this harness does.

int helper_value(int scale);

int main(void) { return helper_value(7); }
