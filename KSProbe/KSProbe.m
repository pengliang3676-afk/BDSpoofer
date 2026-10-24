//
//  KSProbe.m —— 快手检测探针（只读，不修改任何东西）
//
//  注入快手后，在快手进程内检查：
//    ① Dopamine rootless 特征路径（/jb/amfid_payload.dylib 等）
//    ② 越狱路径（apt / sshd / cydia / MobileSubstrate）
//    ③ dyld 镜像列表（_dyld_image_count —— 快手 Weapon 用它枚举 dylib）
//    ④ DYLD_INSERT_LIBRARIES 环境变量
//    ⑤ cydia:// scheme 是否可打开
//
//  结果写到 Documents/ksprobe_log.txt
//  用途：判断 RootHide 对这些检测项是否有效
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>
#import <stdlib.h>

static NSString *KSProbeLogPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"ksprobe_log.txt"];
}

__attribute__((constructor))
static void KSProbeInit(void) {
    @autoreleasepool {
        @try {
            NSString *bid = [NSBundle mainBundle].bundleIdentifier ?: @"";
            NSString *low = bid.lowercaseString;
            if (!([low containsString:@"kuaishou"] ||
                  [low containsString:@"jiangjia"] ||
                  [low containsString:@"kwai"])) {
                return;
            }

            NSMutableString *log = [NSMutableString string];
            NSDateFormatter *df = [NSDateFormatter new];
            df.dateFormat = @"yyyy-MM-dd HH:mm:ss";
            [log appendFormat:@"==== KSProbe %@  bid=%@ ====\n",
                              [df stringFromDate:[NSDate date]], bid];

            NSArray *paths = @[
                @"/jb/amfid_payload.dylib",
                @"/jb/libjailbreak.dylib",
                @"/var/jb",
                @"/private/var/lib/apt",
                @"/usr/sbin/sshd",
                @"/etc/apt",
                @"/usr/bin/ssh",
                @"/private/jailbreak.txt",
                @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                @"/Applications/Cydia.app",
                @"/usr/lib/libsubstitute.dylib",
                @"/usr/lib/libhooker.dylib",
            ];
            [log appendString:@"\n-- 路径检测（stat / lstat）--\n"];
            for (NSString *p in paths) {
                struct stat st;
                int r1 = stat(p.UTF8String, &st);
                struct stat lst;
                int r2 = lstat(p.UTF8String, &lst);
                [log appendFormat:@"%-46s stat=%d lstat=%d\n",
                                  p.UTF8String, r1, r2];
            }

            [log appendString:@"\n-- dyld 镜像 --\n"];
            uint32_t n = _dyld_image_count();
            [log appendFormat:@"dyld_image_count=%u\n", n];
            for (uint32_t i = 0; i < n && i < 400; i++) {
                const char *nm = _dyld_get_image_name(i);
                if (nm) [log appendFormat:@"  img[%u]=%s\n", i, nm];
            }

            const char *env = getenv("DYLD_INSERT_LIBRARIES");
            [log appendFormat:@"\nDYLD_INSERT_LIBRARIES=%s\n",
                              env ? env : "(null)"];

            BOOL cydia = NO;
            @try {
                cydia = [[UIApplication sharedApplication]
                            canOpenURL:[NSURL URLWithString:@"cydia://"]];
            } @catch (NSException *e) {}
            [log appendFormat:@"cydia_scheme_openable=%d\n", cydia];

            [log appendString:@"\n-- 进程环境 --\n"];
            [log appendFormat:@"uid=%d euid=%d\n", getuid(), geteuid()];
            NSDictionary *envDict = [[NSProcessInfo processInfo] environment];
            for (NSString *k in @[@"DYLD_INSERT_LIBRARIES", @"DYLD_LIBRARY_PATH",
                                  @"DYLD_FRAMEWORK_PATH", @"_MSSafeMode",
                                  @"JB_ROOT", @"ROOTHIDE"]) {
                [log appendFormat:@"env[%@]=%@\n", k,
                                  envDict[k] ?: @"(null)"];
            }

            [log writeToFile:KSProbeLogPath()
                  atomically:YES
                    encoding:NSUTF8StringEncoding
                       error:NULL];
        } @catch (NSException *e) {}
    }
}
