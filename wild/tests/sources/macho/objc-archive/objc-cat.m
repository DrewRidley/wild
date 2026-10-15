#import <Foundation/Foundation.h>

@interface NSString (Shout)
- (NSString *)shout;
@end

@implementation NSString (Shout)
- (NSString *)shout {
  return [self uppercaseString];
}
@end
