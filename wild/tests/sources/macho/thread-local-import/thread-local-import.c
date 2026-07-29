//#Config:default
//#LinkerDriver:clang
//#LinkArgs:-lncurses

// Referring to a thread-local variable defined by a system library.
//
// A stub library lists these under `thread-local-symbols` rather than alongside the rest, and we
// read only the lists we recognised - so every one of them looked undefined and any program
// touching one failed to link. `ld` links the same program without complaint.
//
// Nothing about the reference is special. What makes a variable thread-local is how the defining
// image lays it out, not anything the referring image says: the symbol is named and bound exactly
// as any other import is, and the binary this produces has the same `__got` bind that `ld`'s does.
//
// `_nc_abiver` is the only such symbol in a library that is reasonable to link against - the rest
// are in private frameworks - which is a fair account of why this went unnoticed.

extern __thread int _nc_abiver;

// The value is the library's ABI version and not ours to predict; that reading it at all
// works is the whole of what this checks.
int main(void) { return _nc_abiver > 0 ? 42 : 1; }
