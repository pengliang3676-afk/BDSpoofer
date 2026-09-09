#import <Foundation/Foundation.h>
#import "HMFileStore.h"

extern NSString *const HMTargetID;
NSError *HMError(NSString *message);
NSString *HMHex(const unsigned char *bytes, NSUInteger length);
NSString *HMErrnoText(int code);

@interface HMEnvironment : NSObject
@property(nonatomic, copy, readonly) NSString *detail;
- (NSArray<NSDictionary *> *)containers:(NSError **)error;
- (int)openVerifiedContainer:(NSDictionary *)container error:(NSError **)error;
- (BOOL)targetStopped:(NSError **)error;
@end
