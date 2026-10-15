//#Config:default
//#LinkerDriver:clang
//#LinkArgs:-Wl,-map,/dev/null
//#ExpectSym:_main

// `-map` asks for a plain-text account of what ended up where: the inputs numbered, the sections
// with their addresses and sizes, and every symbol against the object it came from. Nothing reads
// it at run time - it exists so that a person, or a size-analysis tool, can answer "what is taking
// up the space" without picking the binary apart. Build systems ask for it routinely, and until it
// was accepted the link failed outright.
//
// Writing it to /dev/null is enough here: what this checks is that asking for one doesn't disturb
// the image, since the map is produced from the same layout the image was written from. The
// contents are checked by hand against ld64's, which lists the same symbols with the same sizes
// attributed to the same objects.

int main(void) { return 42; }
