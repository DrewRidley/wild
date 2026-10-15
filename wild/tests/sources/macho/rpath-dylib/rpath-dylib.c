//#Config:default
//#LinkerDriver:clang
//#Shared:rpath-dylib-lib.c
//#LinkSoArgs:-lSystem
//#LinkArgs:-Wl,-rpath,@loader_path -Wl,-rpath,@loader_path

// Linking against a dylib with `-rpath`.
//
// `-rpath` records one `LC_RPATH` per directory for dyld to try when resolving a dependency that
// names itself `@rpath/...`. Until it was accepted, passing it failed the link outright, which
// ruled out linking against any dylib not installed at a fixed absolute path - the normal case for
// anything shipped inside an application bundle.
//
// The repeat is deliberate. dyld tries the paths in order, so a second copy of one it has already
// tried cannot change the answer; ld64 emits it once and so do we.
//
// `@loader_path` also covers a second thing worth pinning down: an argument beginning with `@` is
// not a response file just because it starts that way. Mach-O spells its relocatable path prefixes
// `@loader_path`, `@executable_path` and `@rpath`, and reading one as a file of arguments fails the
// link.
//
// What this does not pin down is which name the dependency is recorded under. That comes from the
// library's own `LC_ID_DYLIB` rather than the path it was opened by, and the two only differ for a
// library built to be relocatable - which this harness has no way to name consistently across the
// linkers it compares.

int lib_answer(void);

int main(void) { return lib_answer(); }
