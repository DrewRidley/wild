//#Config:default
//#LinkerDriver:clang
//#CompArgs:-fobjc-arc
//#LinkArgs:-framework Foundation -fobjc-arc
//#ExpectSym:_main

// Selector references from two sources, in one section.
//
// clang compiles a message send as a call to `_objc_msgSend$selector` and leaves the callee to the
// linker: a trampoline that loads a selector reference into x1 and tail-calls `_objc_msgSend`. The
// reference, the selector name it points at and the trampoline are all the linker's to write. An
// `@selector(...)` expression, on the other hand, is a selector reference the compiler writes into
// its own `__objc_selrefs`.
//
// The runtime finds `__objc_selrefs` by name when the image loads and rewrites every reference in
// it to the uniqued selector. It looks the section up once, so the two sources have to end up in
// the same section - a reference in a second section of the same name is never uniqued, and a
// message sent with it is "unrecognized selector". `sel_registerName` tells: it returns the uniqued
// selector, which is the compiler's reference only if the runtime got to it.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

int main(void) {
  @autoreleasepool {
    NSString *text = [NSString stringWithUTF8String:"wild"];

    // The compiler's own reference.
    SEL length = @selector(length);

    if (length != sel_registerName("length")) {
      return 1;
    }

    // The linker's, by way of the trampoline for `respondsToSelector:` and for `length`.
    if (![text respondsToSelector:length]) {
      return 2;
    }

    return [text length] == 4 ? 42 : 3;
  }
}
