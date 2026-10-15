//#Config:default
//#LinkerDriver:clang
//#Object:unwind-region-frames.s
//#LinkArgs:-Wl,-dead_strip
//#ExpectSym:_regions

// A `__compact_unwind` entry that defers to DWARF and its FDE agree on nothing but the function
// they describe - and "the function" means an address, not a symbol. Hand-written assembly covers
// one symbol with several unwind regions, so most of its FDEs name that symbol plus an offset;
// pairing by symbol address alone finds no frame for any region past the first and refuses the
// link.
//
// Control flows through both of `_regions`' regions on the way to returning 42, so running this
// also proves the boundary is just an unwinding matter, not an execution one.

int regions(void);

int main(void) { return regions(); }
