//#Config:default
//#LinkerDriver:clang
//#CompArgs:-fobjc-arc
//#LinkArgs:-framework Foundation -fobjc-arc
//#ExpectSym:_main

// Linking Objective-C.
//
// A `.tbd` stub names an Objective-C class once, under `objc-classes`, and leaves the linker to
// form the several symbols that class actually defines: the class, the metaclass behind it, and
// for some, an exception type. An object referring to `NSString` names `_OBJC_CLASS_$_NSString` in
// full, so a linker that reads only the `symbols` key finds nothing - and every Objective-C
// program failed to link, whatever it did.
//
// Instance variables are listed the same way, as `Class.ivar`, and become `_OBJC_IVAR_$_Class.ivar`.

#import <Foundation/Foundation.h>

int main(void) {
  @autoreleasepool {
    NSString* text = [NSString stringWithUTF8String:"wild"];
    NSArray* parts = @[ text, @"linker" ];

    return (int)[text length] == 4 && [parts count] == 2 ? 42 : 1;
  }
}
