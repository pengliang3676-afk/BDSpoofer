#import "HMEnvironment.h"

@interface HMScanItem : NSObject
@property(nonatomic) NSUInteger index;
@property(nonatomic) int readError;
@property(nonatomic) HMFileState state;
@property(nonatomic) BOOL selected;
- (NSString *)name;
- (NSString *)summary;
@end

@interface HMEngine : NSObject
@property(nonatomic, strong, readonly) HMEnvironment *environment;
@property(nonatomic, copy, readonly) NSString *storePath;
@property(atomic) BOOL cancelRequested;
- (instancetype)initWithEnvironment:(HMEnvironment *)environment storePath:(NSString *)path;
- (NSArray<HMScanItem *> *)scan:(NSDictionary *)container error:(NSError **)error;
- (NSDictionary *)clean:(NSDictionary *)container items:(NSArray<HMScanItem *> *)items error:(NSError **)error;
- (NSArray<NSDictionary *> *)history:(NSError **)error;
- (NSDictionary *)verify:(NSDictionary *)record error:(NSError **)error;
- (NSDictionary *)restore:(NSDictionary *)record error:(NSError **)error;
@end
