//#Config:default
//#LinkerDriver:clang
//#Shared:exported-symbol-lib.c
//#LinkSoArgs:-lSystem -Wl,-exported_symbol,_keep_me
//#ExpectSym:_main

// Saying which symbols a dylib offers.
//
// A dylib exports everything it defines unless told otherwise, and on Mach-O the way to tell it
// otherwise is a list - `-exported_symbol` for one name, `-exported_symbols_list` for a file of
// them. There is no version script here to take things away afterwards, so the list has to narrow
// the export trie rather than merely add to it. We were reading the list and then exporting
// everything anyway, which is worse than refusing the flag: a dylib built to offer one symbol
// offered all of them, and nothing said so.
//
// `_hide_me` is what proves it. It is defined and not hidden, so only the list keeps it out of the
// trie, and the executable binds against the trie - so if the narrowing stopped working, the link
// would still succeed and only the shape of the library would quietly change.

int keep_me(void);

int main(void) { return keep_me(); }
