//#Config:default
//#LinkerDriver:clang
//#LinkArgs:-bundle
//#RunEnabled:false
//#ExpectSym:_bundle_answer

// A bundle: loaded with `dlopen` rather than named as a dependency.
//
// It is a dylib in nearly every respect - no entry point, no page zero, a base address of zero so
// it can be placed anywhere, and an export trie saying what it offers - and differs in the file
// type it declares and in recording no install name, because nothing depends on it by name.
//
// A bundle cannot be executed, so the harness links it and stops there. That it loads is checked
// by hand: `dlopen` and `dlsym` find this function and calling it returns 42, and the header
// matches ld64's byte for byte - file type 8, and the same flags, with no `MH_PIE` since nothing
// about a bundle is entered at an address.

int bundle_answer(void) { return 42; }
