//#Config:default
//#LinkerDriver:clang
//#Archive:objc-cat.m
//#LinkArgs:-ObjC -framework Foundation

// `-ObjC`: taking an archive member for what it defines rather than for what refers to it.
//
// A category adds methods to a class it doesn't define. Calling one compiles to a message send by
// selector, so nothing in the program names anything the member defines - the archive's table of
// contents here is empty, and `ranlib` says as much when building it. The usual rule leaves the
// member out and the program builds and links cleanly, then dies the moment it sends the message:
//
//   -[__NSCFConstantString shout]: unrecognized selector sent to instance
//
// So the flag can't be quietly ignored, which is why it used to be refused outright. A member that
// defines a class or category is listed in `__objc_classlist` or `__objc_catlist`, and those are
// the lists the runtime walks when the image loads, so they are what we look for.

#import <Foundation/Foundation.h>

@interface NSString (Shout)
- (NSString *)shout;
@end

int main(void) {
  NSString *shouted = [@"wild" shout];

  return [shouted isEqualToString:@"WILD"] ? 42 : 1;
}
