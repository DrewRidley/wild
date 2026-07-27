//#Config:default
//#LinkerDriver:clang
//#LinkArgs:-framework CoreFoundation

// Linking against a system framework.
//
// A framework is a directory `Name.framework` holding a library called `Name`, found on its own
// search path (`-F` and the system directories, all of them under the SDK when one is given)
// rather than the library one. In an SDK the library is a `.tbd` stub rather than the dylib
// itself, so this also covers finding the stub and binding against what it says it exports.
//
// Until `-framework` was accepted this failed the link outright, which ruled out linking anything
// that touches a system framework - most macOS programs that do more than compute.
//
// The versions matter too, and are the library's to state rather than ours to invent: dyld refuses
// to load a library older than the image was built against, so a made-up compatibility version
// either waves through one that should have been rejected or rejects one that was fine. These come
// from the stub, and for CoreFoundation they are nothing like a default.

#include <CoreFoundation/CoreFoundation.h>

int main(void) {
  CFStringRef s = CFStringCreateWithCString(NULL, "wild", kCFStringEncodingUTF8);
  CFIndex length = CFStringGetLength(s);
  CFRelease(s);

  return length == 4 ? 42 : 1;
}
