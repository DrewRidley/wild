//#Config:default
//#LinkerDriver:clang
//#LinkArgs:-weak_framework CoreFoundation
//#ExpectSym:_main

// A dependency wanted only if it happens to be there.
//
// `-weak_framework` records the library with `LC_LOAD_WEAK_DYLIB` and marks everything imported
// from it weak, which together tell dyld to carry on with those symbols resolved to zero rather
// than refuse to start the image. It is how a program built against a new system runs on an older
// one, and until it was accepted the link failed outright.
//
// Recording it the ordinary way instead would look fine here - the framework is present - and fail
// only on the system that didn't have it, which is the one case the flag exists for.

#include <CoreFoundation/CoreFoundation.h>

int main(void) {
  CFStringRef s = CFStringCreateWithCString(NULL, "wild", kCFStringEncodingUTF8);
  CFIndex length = CFStringGetLength(s);
  CFRelease(s);

  return length == 4 ? 42 : 1;
}
