//#Config:default
//#LinkerDriver:clang
//#Object:eh-frame-frames.s
//#LinkArgs:-Wl,-dead_strip
//#NoSym:_frame_unused
//#ExpectSym:_frame_used

// `__eh_frame` describes functions; it must not be the reason they are kept.
//
// An FDE names the function it describes, so copying `__eh_frame` through as ordinary content
// makes every one of those names a reference and anchors the whole program - and since anything
// that can be unwound through has an FDE, that is very nearly everything. Read as frame data
// instead, the FDE hangs off its function and is emitted only if the function is.
//
// `_frame_unused` is here to prove it: nothing refers to it except its own FDE, so it goes, and
// `_frame_used` stays because `main` calls it.
//
// The other half is that what survives has to still be readable. Dropping records shifts the ones
// after them, so an FDE's distance back to its CIE changes, and so does every field it stored as
// a distance from where it sits - including the one saying which function it describes. Both of
// these functions are described by DWARF rather than compactly, so their `__unwind_info` entries
// send the unwinder into `__eh_frame` by offset, and that offset is the linker's to work out.

int frame_used(void);

int main(void) { return frame_used(); }
