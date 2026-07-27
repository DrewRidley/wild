//#Config:default
//#LinkerDriver:clang
//#Shared:dylib-output-lib.c
//#LinkSoArgs:-lSystem -lc -lm
//#ExpectSym:_main

// Producing a dylib rather than an executable.
//
// The `Shared` input is itself linked by whichever linker is under test, so this exercises wild's
// `-dylib` output: no entry point, a base address of zero so the image can be placed anywhere, an
// `LC_ID_DYLIB` naming it, and an export trie listing what it offers. The executable then binds
// against that trie, so a name missing from it fails the link rather than the run.
//
// It is linked with `-lSystem -lc -lm` because on macOS all three are libSystem, reached through
// three separate stub files that share one install name. They have to collapse into a single
// `LC_LOAD_DYLIB`: dyld refuses to load a dylib whose load commands name the same library twice, so
// leaving all three in makes this fail at startup rather than at link time. An executable is no
// test of that - dyld tolerates the duplicates there and runs anyway.

int lib_add(int n);
int lib_uses_hidden(int n);
extern int lib_value;

int main(void) {
    if (lib_value != 40) return 1;
    if (lib_add(2) != 42) return 2;
    if (lib_uses_hidden(21) != 42) return 3;
    return 42;
}
