//#Config:default
//#LinkerDriver:clang
//#Shared:unexported-symbol-lib.c
//#LinkSoArgs:-lSystem -Wl,-unexported_symbol,_hide_me
//#ExpectSym:_main

// Saying which symbols a dylib withholds, rather than which it offers.
//
// The two lists are alternatives and neither implies the other: `-exported_symbol` names what to
// keep and says nothing about the rest, this names what to drop and says nothing about the rest.
// So this one has to apply whatever else would have exported the symbol - everything is exported
// by default, and a list that only got a say once something had already decided to export would
// never get one at all.
//
// Withholding makes the symbol local rather than making it disappear. It still names its own code
// for a debugger and for anything reading the symbol table; it just stops being something another
// image can bind to. `ld` does the same, and this produces the same three things it does: the same
// global symbols, the same export trie, and `_hide_me` demoted to a local.
//
// That the symbol is local and not absent is why the measuring and the writing of the symbol table
// both have to ask - Mach-O keeps locals and globals in separate runs that `LC_DYSYMTAB` names by
// index, so counting a symbol as one kind and writing it as the other would misplace every symbol
// after it.

extern int keep_me(void);

int main(void) { return keep_me(); }
