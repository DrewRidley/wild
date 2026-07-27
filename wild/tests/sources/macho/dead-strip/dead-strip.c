//#Config:default
//#LinkerDriver:clang
//#Object:dead-strip-lib.c
//#LinkArgs:-Wl,-dead_strip
//#NoSym:_never_called_a
//#NoSym:_never_called_b
//#NoSym:_never_referenced_data
//#ExpectSym:_actually_called

// Dropping what nothing reaches.
//
// A Mach-O object puts every function in one `__text` rather than one section each, so this only
// works if the section has first been cut at its symbol boundaries - otherwise keeping any function
// keeps the whole object's code. `MH_SUBSECTIONS_VIA_SYMBOLS` on the object is the compiler saying
// that cutting there is safe.
//
// The assertions are on the symbol table: the unreached functions must be gone and the reached one
// must remain. Checking sizes instead would be brittle, and checking only that the program runs
// would pass even if nothing were stripped at all.

int actually_called(int n);

int main(void) {
  return actually_called(21);
}
