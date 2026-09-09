#import "HMEnvironment.h"
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <fcntl.h>
#import <limits.h>
#import <unistd.h>

NSString *const HMTargetID = @"com.cbn.hmjc";
NSError *HMError(NSString *message) {
    return [NSError errorWithDomain:@"HMCleaner" code:1 userInfo:@{NSLocalizedDescriptionKey:message ?: @"未知错误"}];
}
NSString *HMHex(const unsigned char *bytes, NSUInteger length) {
    NSMutableString *s = [NSMutableString string];
    for (NSUInteger i = 0; i < length; i++) [s appendFormat:@"%02x", bytes[i]];
    return s;
}
NSString *HMErrnoText(int code) {
    if (code == ENOENT) return @"不存在";
    if (code == ESTALE) return @"文件已变化，请重新扫描";
    if (code == EEXIST) return @"已有文件，未覆盖";
    if (code == ELOOP || code == ENOTDIR) return @"路径含链接或不是目录，已拒绝";
    if (code == EBUSY) return @"出现并发变化或临时项未恢复，请检查备份记录";
    if (code == EACCES || code == EPERM) return @"无访问权限";
    if (code == EINVAL) return @"不是允许的普通文件、存在硬链接，或超过 1 MiB";
    return [NSString stringWithFormat:@"%s（%d）", strerror(code), code];
}

// Read-only subset of the author's public libCrane API. No container switching/wiping.
@interface CraneManager : NSObject
+ (instancetype)sharedManager;
- (BOOL)isApplicationSupportedByCrane:(NSString *)app;
- (NSArray *)containerIdentifiersOfApplicationWithIdentifier:(NSString *)app;
- (NSString *)activeContainerIdentifierForApplicationWithIdentifier:(NSString *)app;
- (NSString *)displayNameForContainerWithIdentifier:(NSString *)cid ofApplicationWithIdentifier:(NSString *)app shouldUseShortVersion:(BOOL)shortVersion;
- (void)enumerate:(void (^)(NSInteger type, NSString *identifier, NSString *path))block pathsAssociatedToContainerWithIdentifier:(NSString *)cid ofApplicationWithIdentifier:(NSString *)app;
@end
@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier;
@property(nonatomic, readonly) NSURL *dataContainerURL;
@property(nonatomic, readonly) NSURL *bundleURL;
@end

static NSString *HMCanonical(NSString *path) {
    if (![path isKindOfClass:NSString.class] || !path.isAbsolutePath) return nil;
    char result[PATH_MAX];
    return realpath(path.fileSystemRepresentation, result) ? [NSString stringWithUTF8String:result] : nil;
}
static BOOL HMWithin(NSString *path, NSString *parent) {
    return parent.length && ([path isEqual:parent] || [path hasPrefix:[parent stringByAppendingString:@"/"]]);
}

@interface HMEnvironment ()
@property(nonatomic, copy, readwrite) NSString *detail;
@property(nonatomic, strong) CraneManager *crane;
@end
@implementation HMEnvironment
- (BOOL)load:(NSError **)error {
    if (self.crane) return YES;
    NSMutableOrderedSet *candidates = [NSMutableOrderedSet orderedSet];
    for (NSString *app in @[NSBundle.mainBundle.bundlePath, HMCanonical(NSBundle.mainBundle.bundlePath) ?: @""]) {
        NSRange mark = [app rangeOfString:@"/Applications/" options:NSBackwardsSearch];
        if (mark.location != NSNotFound) [candidates addObject:[[app substringToIndex:mark.location] stringByAppendingString:@"/usr/lib/libcrane.dylib"]];
    }
    [candidates addObjectsFromArray:@[@"/var/jb/usr/lib/libcrane.dylib", @"/usr/lib/libcrane.dylib"]];
    for (NSString *path in candidates) {
        if (dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL)) {
            self.detail = [@"libCrane：" stringByAppendingString:path]; break;
        }
    }
    Class cls = NSClassFromString(@"CraneManager");
    if (![cls respondsToSelector:@selector(sharedManager)]) {
        if (error) *error = HMError(@"未找到 libCrane。请在已越狱的环境安装 Crane 完整版，并从桌面打开本 App。"); return NO;
    }
    self.crane = [(id)cls sharedManager];
    if (![self.crane respondsToSelector:@selector(enumerate:pathsAssociatedToContainerWithIdentifier:ofApplicationWithIdentifier:)]) {
        if (error) *error = HMError(@"此 Crane 版本缺少路径枚举接口，已停止。不会猜测容器目录。"); self.crane = nil; return NO;
    }
    return YES;
}
- (LSApplicationProxy *)proxy {
    dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY | RTLD_LOCAL);
    Class cls = NSClassFromString(@"LSApplicationProxy");
    return [cls respondsToSelector:@selector(applicationProxyForIdentifier:)] ? [(id)cls applicationProxyForIdentifier:HMTargetID] : nil;
}
- (NSArray<NSDictionary *> *)containers:(NSError **)error {
    @try {
        if (![self load:error]) return nil;
        NSString *base = HMCanonical([self proxy].dataContainerURL.path);
        if (!base.length || ![base hasPrefix:@"/private/var/mobile/Containers/Data/Application/"]) {
            if (error) *error = HMError(@"无法核对河马剧场的系统注册数据目录，已停止。"); return nil;
        }
        if (![self.crane isApplicationSupportedByCrane:HMTargetID]) {
            if (error) *error = HMError(@"Crane 未启用河马剧场，或未安装 com.cbn.hmjc。"); return nil;
        }
        NSArray *ids = [self.crane containerIdentifiersOfApplicationWithIdentifier:HMTargetID];
        if (![ids isKindOfClass:NSArray.class] || !ids.count) {
            if (error) *error = HMError(@"Crane 没有返回容器列表。"); return nil;
        }
        NSString *active = [self.crane activeContainerIdentifierForApplicationWithIdentifier:HMTargetID];
        NSMutableArray *rows = [NSMutableArray array];
        for (id cid in ids) {
            if (![cid isKindOfClass:NSString.class] || ![cid length]) continue;
            NSMutableArray *paths = [NSMutableArray array], *main = [NSMutableArray array];
            [self.crane enumerate:^(NSInteger type, NSString *identifier, NSString *path) {
                if (![path isKindOfClass:NSString.class]) return;
                NSString *real = HMCanonical(path);
                [paths addObject:@{@"type":@(type), @"id":identifier ?: @"", @"path":path, @"canonical":real ?: @""}];
                if (type == 0 && real.length) [main addObject:real];
            } pathsAssociatedToContainerWithIdentifier:cid ofApplicationWithIdentifier:HMTargetID];
            NSString *root = main.count == 1 ? main.firstObject : nil;
            NSString *problem = @"";
            if (!root.length || !HMWithin(root, base)) problem = @"主目录缺失、多义或不属于已注册应用，禁止操作";
            struct stat st = {0};
            int fd = problem.length ? -1 : hm_open_dir(root.fileSystemRepresentation);
            if (fd < 0 && !problem.length) problem = HMErrnoText(errno);
            if (fd >= 0) { if (fstat(fd, &st)) problem = HMErrnoText(errno); close(fd); }
            NSString *name = [self.crane displayNameForContainerWithIdentifier:cid ofApplicationWithIdentifier:HMTargetID shouldUseShortVersion:NO] ?: cid;
            [rows addObject:[@{@"id":cid, @"name":name, @"root":root ?: @"", @"paths":paths,
                              @"active":@([cid isEqual:active]), @"problem":problem,
                              @"dev":@((uint64_t)st.st_dev), @"ino":@((uint64_t)st.st_ino)} mutableCopy]];
        }
        // Multiple identities pointing at one main directory cannot be safely distinguished.
        for (NSMutableDictionary *row in rows) for (NSDictionary *other in rows) {
            if (row != other && [row[@"root"] length] && [row[@"root"] isEqual:other[@"root"]]) row[@"problem"] = @"多个容器返回相同主目录，禁止操作";
        }
        return [rows sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [a[@"name"] localizedStandardCompare:b[@"name"]];
        }];
    } @catch (NSException *exception) {
        if (error) *error = HMError([@"Crane 接口异常：" stringByAppendingString:exception.reason ?: @"未知"]); return nil;
    }
}
- (int)openVerifiedContainer:(NSDictionary *)container error:(NSError **)error {
    NSArray *rows = [self containers:error];
    if (!rows) return -1;
    NSDictionary *fresh = nil;
    for (NSDictionary *row in rows) if ([row[@"id"] isEqual:container[@"id"]]) fresh = row;
    if (!fresh || [fresh[@"problem"] length] || ![fresh[@"root"] isEqual:container[@"root"]] ||
        ![fresh[@"dev"] isEqual:container[@"dev"]] || ![fresh[@"ino"] isEqual:container[@"ino"]]) {
        if (error) *error = HMError(@"容器已删除、路径发生变化或无法唯一确认。请重新扫描。"); return -1;
    }
    int fd = hm_open_dir([fresh[@"root"] fileSystemRepresentation]);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || (uint64_t)st.st_dev != [fresh[@"dev"] unsignedLongLongValue] ||
        (uint64_t)st.st_ino != [fresh[@"ino"] unsignedLongLongValue]) {
        if (fd >= 0) close(fd);
        if (error) *error = HMError(@"打开目录时身份发生变化或访问失败。"); return -1;
    }
    return fd;
}
- (BOOL)targetStopped:(NSError **)error {
    @try {
        NSString *bundlePath = HMCanonical([self proxy].bundleURL.path);
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]];
        NSString *executable = info[@"CFBundleExecutable"];
        if (!bundlePath.length || !executable.length) {
            if (error) *error = HMError(@"无法确定目标可执行文件，不能确认 App 已退出。"); return NO;
        }
        NSMutableArray<NSString *> *names = [NSMutableArray arrayWithObject:executable];
        NSString *plugins = [bundlePath stringByAppendingPathComponent:@"PlugIns"];
        for (NSString *name in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:plugins error:nil]) {
            NSDictionary *ext = [NSDictionary dictionaryWithContentsOfFile:[[plugins stringByAppendingPathComponent:name] stringByAppendingPathComponent:@"Info.plist"]];
            if ([ext[@"CFBundleExecutable"] isKindOfClass:NSString.class]) [names addObject:ext[@"CFBundleExecutable"]];
        }
        int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
        size_t size = 0;
        if (sysctl(mib, 4, NULL, &size, NULL, 0) || !size || size > 32 * 1024 * 1024) {
            if (error) *error = HMError(@"读取进程列表失败，清理和恢复已禁用。"); return NO;
        }
        size += size / 2;
        struct kinfo_proc *list = calloc(1, size);
        if (!list) { if (error) *error = HMError(@"进程检查内存不足。"); return NO; }
        if (sysctl(mib, 4, list, &size, NULL, 0)) {
            free(list); if (error) *error = HMError(@"进程列表变化或无权限，请稍后重试。"); return NO;
        }
        typedef int (*PathFunction)(int, void *, uint32_t);
        PathFunction getPath = (PathFunction)dlsym(RTLD_DEFAULT, "proc_pidpath");
        BOOL running = NO;
        for (size_t i = 0; i < size / sizeof(*list); i++) {
            for (NSString *name in names) {
                // p_comm is byte-truncated, including UTF-8 names; compare the same prefix.
                if (!strncmp(list[i].kp_proc.p_comm, name.UTF8String, sizeof(list[i].kp_proc.p_comm) - 1)) running = YES;
            }
            char processPath[4096] = {0};
            if (getPath && getPath(list[i].kp_proc.p_pid, processPath, sizeof(processPath)) > 0) {
                NSString *path = HMCanonical([NSString stringWithUTF8String:processPath]);
                if (HMWithin(path, bundlePath)) running = YES;
            }
        }
        free(list);
        if (running && error) *error = HMError(@"河马剧场或其扩展仍在运行。请从多任务界面划掉河马剧场，再重试；操作期间不要重新打开。");
        return !running;
    } @catch (NSException *exception) {
        if (error) *error = HMError(@"进程检查异常，已停止操作。"); return NO;
    }
}
@end
