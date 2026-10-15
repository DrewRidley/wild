//#Config:default
//#LinkerDriver:clang
//#LinkArgs:-framework ApplicationServices

// Linking against an umbrella framework, whose stub library is a tree rather than a list.
//
// `ApplicationServices.tbd` is eight documents in one file, and they are nested: `ATSUI` is
// re-exported by one of the children rather than by the umbrella itself. We gathered the
// re-exports from the first document only, so every library deeper than one level looked like it
// had wandered in uninvited and the file was refused outright:
//
//   child library '.../ATSUI.framework/Versions/A/ATSUI' not listed as reexported by the main
//
// Which is not a corner case. It is what stopped a Dioxus desktop application linking - AppKit
// pulls in ApplicationServices, so this refused most of the macOS UI stack.
//
// A document may also state its re-exports in several entries, one per group of targets, so the
// ones for our architecture are taken together rather than being required to be a single entry.

#include <ApplicationServices/ApplicationServices.h>

int main(void) {
  CFStringRef name = CGColorSpaceCopyName(CGColorSpaceCreateDeviceRGB());

  return name != NULL ? 42 : 1;
}
