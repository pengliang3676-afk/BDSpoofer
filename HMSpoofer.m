//
//  HMSpoofer.m
//  河马剧场 (com.cbn.hmjc) 设备参数伪装 dylib 1.1.1
//
//  1.1.1：修复 C 返回契约、安装发布、配置持久化及屏幕查询一致性。
//   - 业务后端 /api/free-video-ios/portal/2000、2001 的 deviceInfo 字段多由系统 API
//     现取；本文件 Hook 系统出口。注意：单个字段的具体采集路径未逐一独立验证，
//     mntId / fileSetupTime 等字段依赖"新 Crane 容器天然全新"，不在本文件伪造。
//   - 数美/听云/UMID 等 SDK 同样从系统出口取值，清掉本地残留后重新生成；
//     本文件不直接 Hook 任何风控 SDK。
//   - 运营商、时区、语言、国家码保持真实。
//   - 不做任何清理动作（清理由独立的 HMCleaner 在 App 停止时完成）。
//   - 进程内身份不可变：首启随机一套并保存；"换一套"只写磁盘，杀进程重启后生效。
//
//  自洽要求：machName(如 iPhone12,8) 与主板号(D79AP)、内存、屏幕、iOS 版本、
//  磁盘容量必须成套绑定；机型池只收录已核实主板号与真实容量 SKU 的机型。
//

#import <Foundation/Foundation.h>
#ifndef HM_HOST_TEST
#import <UIKit/UIKit.h>
#else
#import <CoreGraphics/CoreGraphics.h>
typedef struct { CGFloat top, left, bottom, right; } UIEdgeInsets;
#endif
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <errno.h>
#import <dlfcn.h>
#import <stdatomic.h>
#import <os/lock.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <math.h>
#import <string.h>

static NSString *const HMVersion = @"1.1.1";
static const NSInteger HMSchema = 2;

// ----------------------------- 门控 -----------------------------

static BOOL hm_isTargetApp(void) {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
        NSString *exe = [[NSBundle mainBundle] executablePath] ?: @"";
        if ([exe rangeOfString:@".appex"].location != NSNotFound ||
            [exe rangeOfString:@"/PlugIns/"].location != NSNotFound) return NO;
        return [bid caseInsensitiveCompare:@"com.cbn.hmjc"] == NSOrderedSame;
    }
}

// interpose 自 dylib 装载即存在；只有 constructor 完成门控与身份装载后才放行覆写
static _Atomic(int) g_active = 0;

// ----------------------------- 机型池 -----------------------------

@interface HMPoolEntry : NSObject
@property (nonatomic, copy) NSString *machine, *board, *market;
@property (nonatomic, assign) uint64_t mem;
@property (nonatomic, assign) CGFloat w, h, scale, nw, nh, status, safeTop, safeBottom;
@property (nonatomic, strong) NSArray<NSNumber *> *disks;     // 该机型真实容量 SKU（十进制字节）
@property (nonatomic, strong) NSArray<NSString *> *sysVers;  // 该机型可装的 iOS 版本
@end
@implementation HMPoolEntry @end

static NSArray<HMPoolEntry *> *hm_pool(void) {
    static NSArray *pool;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableArray *a = [NSMutableArray array];
        void (^add)(NSString *, NSString *, NSString *, uint64_t,
                    CGFloat, CGFloat, CGFloat, CGFloat, CGFloat,
                    CGFloat, CGFloat, CGFloat, NSArray<NSNumber *> *, NSArray<NSString *> *) =
        ^(NSString *m, NSString *b, NSString *mk, uint64_t mem,
          CGFloat w, CGFloat h, CGFloat s, CGFloat nw, CGFloat nh,
          CGFloat st, CGFloat tp, CGFloat bt, NSArray<NSNumber *> *disks, NSArray *vers) {
            HMPoolEntry *e = [HMPoolEntry new];
            e.machine = m; e.board = b; e.market = mk; e.mem = mem;
            e.w = w; e.h = h; e.scale = s; e.nw = nw; e.nh = nh;
            e.status = st; e.safeTop = tp; e.safeBottom = bt;
            e.disks = disks; e.sysVers = vers;
            [a addObject:e];
        };
        const uint64_t G = 1000ull * 1000ull * 1000ull; // Apple 十进制容量口径
        NSNumber *d64 = @(64ull * G), *d128 = @(128ull * G),
                 *d256 = @(256ull * G), *d512 = @(512ull * G);
        const uint64_t GB3 = 3ull * 1024 * 1024 * 1024;
        const uint64_t GB4 = 4ull * 1024 * 1024 * 1024;
        // iPhone X 最高只能到 iOS 16；容量 64/256
        NSArray *xOnly16 = @[@"16.3.1", @"16.5.1", @"16.7.2", @"16.7.8"];
        // XS/XR/11/SE2 支持下列 16/17 版本；本池不选 15.7.x。
        NSArray *v1617 = @[@"16.3.1", @"16.5.1", @"16.7.2", @"17.1.1", @"17.4.1"];
        add(@"iPhone10,6", @"D221AP", @"iPhone X", GB3,
            375, 812, 3, 1125, 2436, 44, 44, 34, (@[d64, d256]), xOnly16);
        add(@"iPhone11,2", @"D321AP", @"iPhone XS", GB4,
            375, 812, 3, 1125, 2436, 44, 44, 34, (@[d64, d256, d512]), v1617);
        add(@"iPhone11,6", @"D331pAP", @"iPhone XS Max", GB4,
            414, 896, 3, 1242, 2688, 44, 44, 34, (@[d64, d256, d512]), v1617);
        add(@"iPhone11,8", @"N841AP", @"iPhone XR", GB3,
            414, 896, 2, 828, 1792, 44, 44, 34, (@[d64, d128, d256]), v1617);
        add(@"iPhone12,1", @"N104AP", @"iPhone 11", GB4,
            414, 896, 2, 828, 1792, 44, 44, 34, (@[d64, d128, d256]), v1617);
        add(@"iPhone12,3", @"D421AP", @"iPhone 11 Pro", GB4,
            375, 812, 3, 1125, 2436, 44, 44, 34, (@[d64, d256, d512]), v1617);
        add(@"iPhone12,5", @"D431AP", @"iPhone 11 Pro Max", GB4,
            414, 896, 3, 1242, 2688, 44, 44, 34, (@[d64, d256, d512]), v1617);
        add(@"iPhone12,8", @"D79AP", @"iPhone SE (2nd generation)", GB3,
            375, 667, 2, 750, 1334, 20, 20, 0, (@[d64, d128, d256]), v1617);
        pool = [a copy];
    });
    return pool;
}

// ----------------------------- 当前身份 -----------------------------

static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;
static NSDictionary *g_profile = nil;   // constructor 发布一次，进程内不再替换
static NSDictionary *g_pending = nil;   // 已成功落盘、下次冷启动使用的配置
static os_unfair_lock g_ioLock = OS_UNFAIR_LOCK_INIT;
static NSString *g_startupError = nil;
#ifdef HM_HOST_TEST
static NSString *g_testCfgPath;
#endif

static NSString *hm_cfgPath(void) {
#ifdef HM_HOST_TEST
    return g_testCfgPath;
#else
    static NSString *p;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                             NSUserDomainMask, YES).firstObject;
        p = [docs stringByAppendingPathComponent:@"hmspoofer_config.plist"];
    });
    return p;
#endif
}

static NSArray<NSString *> *hm_requiredKeys(void) {
    static NSArray *keys;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        keys = @[@"enabled", @"machine", @"board", @"market", @"sysVer", @"mem",
                 @"disk", @"freeFrac", @"w", @"h", @"scale", @"nw", @"nh",
                 @"status", @"safeTop", @"safeBottom", @"idfv", @"bootEpoch",
                 @"deviceName", @"poolIndex"];
    });
    return keys;
}

static BOOL hm_profileComplete(NSDictionary *d) {
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    for (NSString *k in hm_requiredKeys()) if (!d[k]) return NO;
    NSArray *strings = @[@"machine", @"board", @"market", @"sysVer", @"idfv", @"deviceName"];
    for (NSString *k in strings) if (![d[k] isKindOfClass:NSString.class]) return NO;
    for (NSString *k in hm_requiredKeys()) {
        if (![strings containsObject:k] && ![d[k] isKindOfClass:NSNumber.class]) return NO;
    }
    if (d[@"schema"] && (![d[@"schema"] isKindOfClass:NSNumber.class] ||
                         ![d[@"schema"] isEqualToNumber:@(HMSchema)])) return NO;
    NSInteger index = [d[@"poolIndex"] integerValue];
    if (![d[@"poolIndex"] isEqualToNumber:@(index)] || index < 0 ||
        (NSUInteger)index >= hm_pool().count) return NO;
    HMPoolEntry *e = hm_pool()[(NSUInteger)index];
    NSDictionary *expected = @{@"machine":e.machine, @"board":e.board, @"market":e.market,
        @"mem":@(e.mem), @"w":@(e.w), @"h":@(e.h), @"scale":@(e.scale),
        @"nw":@(e.nw), @"nh":@(e.nh), @"status":@(e.status),
        @"safeTop":@(e.safeTop), @"safeBottom":@(e.safeBottom)};
    for (NSString *k in expected) if (![d[k] isEqual:expected[k]]) return NO;
    if (![e.disks containsObject:d[@"disk"]] || ![e.sysVers containsObject:d[@"sysVer"]]) return NO;
    double fraction = [d[@"freeFrac"] doubleValue];
    double epoch = [d[@"bootEpoch"] doubleValue];
    double enabled = [d[@"enabled"] doubleValue];
    if (!isfinite(fraction) || fraction < 0.25 || fraction > 0.70 ||
        !isfinite(epoch) || epoch <= 0 || floor(epoch) != epoch ||
        epoch > NSDate.date.timeIntervalSince1970 ||
        !(enabled == 0 || enabled == 1)) return NO;
    if (![[NSUUID alloc] initWithUUIDString:d[@"idfv"]] ||
        ![d[@"deviceName"] isEqualToString:@"iPhone"]) return NO;
    return YES;
}

static uint32_t hm_randU32(uint32_t lo, uint32_t hi) {
    if (hi <= lo) return lo;
    return lo + arc4random_uniform(hi - lo + 1);
}

// 生成一套全新自洽身份
static NSDictionary *hm_makeProfile(void) {
    NSArray<HMPoolEntry *> *pool = hm_pool();
    HMPoolEntry *e = pool[arc4random_uniform((uint32_t)pool.count)];
    NSString *sysVer = e.sysVers[arc4random_uniform((uint32_t)e.sysVers.count)];
    uint64_t disk = [e.disks[arc4random_uniform((uint32_t)e.disks.count)] unsignedLongLongValue];
    double freeFrac = 0.25 + (arc4random_uniform(4501) / 10000.0); // 0.25~0.70
    int64_t boot = (int64_t)[[NSDate date] timeIntervalSince1970]
                   - (int64_t)hm_randU32(2 * 3600, 10 * 24 * 3600);
    return @{
        @"schema": @(HMSchema),
        @"enabled": @YES,
        @"machine": e.machine, @"board": e.board, @"market": e.market,
        @"sysVer": sysVer, @"mem": @(e.mem),
        @"disk": @(disk), @"freeFrac": @(freeFrac),
        @"w": @(e.w), @"h": @(e.h), @"scale": @(e.scale),
        @"nw": @(e.nw), @"nh": @(e.nh),
        @"status": @(e.status), @"safeTop": @(e.safeTop), @"safeBottom": @(e.safeBottom),
        @"idfv": [[NSUUID UUID] UUIDString],
        @"bootEpoch": @(boot),
        @"deviceName": @"iPhone",
        @"poolIndex": @([pool indexOfObject:e])
    };
}

static BOOL hm_saveProfile(NSDictionary *p, NSError **error) {
    if (!hm_profileComplete(p) || !hm_cfgPath()) {
        if (error) *error = [NSError errorWithDomain:@"HMSpoofer" code:EINVAL
            userInfo:@{NSLocalizedDescriptionKey:@"配置无效或保存路径不可用"}];
        return NO;
    }
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:p
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    return data && [data writeToFile:hm_cfgPath() options:NSDataWritingAtomic error:error];
}

static BOOL hm_loadOrInit(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:hm_cfgPath()];
    NSError *error = nil;
    if (!hm_profileComplete(d)) {
        d = hm_makeProfile();
        if (!hm_saveProfile(d, &error)) { g_startupError = error.localizedDescription; return NO; }
    } else if (!d[@"schema"]) {
        // 兼容值已自洽的旧配置，补版本而不偷偷更换身份。
        NSMutableDictionary *migrated = [d mutableCopy];
        migrated[@"schema"] = @(HMSchema);
        d = [migrated copy];
        if (!hm_saveProfile(d, &error)) { g_startupError = error.localizedDescription; return NO; }
    }
    os_unfair_lock_lock(&g_lock);
    g_profile = [d copy];
    g_pending = g_profile;
    os_unfair_lock_unlock(&g_lock);
    return YES;
}

static NSDictionary *hm_pending(void) {
    os_unfair_lock_lock(&g_lock);
    NSDictionary *s = g_pending;
    os_unfair_lock_unlock(&g_lock);
    return s;
}

// 所有读改写使用同一独立锁，Hook 不等磁盘 I/O；成功保存后才更新待生效状态。
static BOOL hm_changePending(BOOL randomize, NSError **error) {
    os_unfair_lock_lock(&g_ioLock);
    NSDictionary *previous = hm_pending();
    NSMutableDictionary *next = [(randomize ? hm_makeProfile() : previous) mutableCopy];
    if (randomize) next[@"enabled"] = previous[@"enabled"] ?: @YES;
    else next[@"enabled"] = @(![previous[@"enabled"] boolValue]);
    NSDictionary *saved = [next copy];
    BOOL ok = hm_saveProfile(saved, error);
    if (ok) {
        os_unfair_lock_lock(&g_lock);
        g_pending = saved;
        os_unfair_lock_unlock(&g_lock);
    }
    os_unfair_lock_unlock(&g_ioLock);
    return ok;
}

// 一次操作只读一份不可变快照，避免跨字段读到新旧混合
static NSDictionary *hm_snap(void) {
    if (!atomic_load(&g_active)) return nil;
    os_unfair_lock_lock(&g_lock);
    NSDictionary *s = [g_profile copy];
    os_unfair_lock_unlock(&g_lock);
    if (![s[@"enabled"] boolValue]) return nil;
    return s;
}

// ----------------------------- C 层系统出口 Hook -----------------------------

typedef int (*HMSysctl)(int *, u_int, void *, size_t *, void *, size_t);
typedef int (*HMSysctlByName)(const char *, void *, size_t *, void *, size_t);
typedef int (*HMUname)(struct utsname *);
typedef int (*HMStatfs)(const char *, struct statfs *);
static _Atomic(HMSysctl) real_sysctl;
static _Atomic(HMSysctlByName) real_sysctlbyname;
static _Atomic(HMUname) real_uname;
static _Atomic(HMStatfs) real_statfs;
static _Thread_local unsigned g_cDepth;

// 每个符号独立解析、原子发布；同一符号解析期重入时失败返回，禁止自等死锁。
#define HM_RESOLVER(slot, type, symbol) \
static type hm_get_##slot(void) { \
    type fn = atomic_load_explicit(&slot, memory_order_acquire); \
    if (fn) return fn; \
    static _Thread_local BOOL resolving; \
    if (resolving) return NULL; \
    int saved = errno; \
    resolving = YES; \
    type found = (type)dlsym(RTLD_NEXT, symbol); \
    resolving = NO; \
    if (found) { \
        type empty = NULL; \
        atomic_compare_exchange_strong_explicit(&slot, &empty, found, \
            memory_order_release, memory_order_acquire); \
    } \
    errno = saved; \
    return atomic_load_explicit(&slot, memory_order_acquire); \
}
HM_RESOLVER(real_sysctl, HMSysctl, "sysctl")
HM_RESOLVER(real_sysctlbyname, HMSysctlByName, "sysctlbyname")
HM_RESOLVER(real_uname, HMUname, "uname")
HM_RESOLVER(real_statfs, HMStatfs, "statfs")
#undef HM_RESOLVER

#ifndef HW_MEMSIZE
#define HW_MEMSIZE 24
#endif

static int hm_error(int error) { errno = error; return -1; }
static int hm_cReturn(int rv, int error) { --g_cDepth; errno = error; return rv; }

// 避免在 interposer 中直接解引用不可访问的用户指针，将访问错误交回调用方。
static BOOL hm_readBytes(const void *source, void *destination, size_t size) {
    if (!size) return YES;
    mach_vm_size_t copied = 0;
    return source && destination &&
        mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(uintptr_t)source,
            size, (mach_vm_address_t)(uintptr_t)destination, &copied) == KERN_SUCCESS && copied == size;
}
static BOOL hm_writeBytes(void *destination, const void *source, size_t size) {
    if (!size) return YES;
    return source && destination && size <= UINT32_MAX &&
        mach_vm_write(mach_task_self(), (mach_vm_address_t)(uintptr_t)destination,
            (vm_offset_t)(uintptr_t)source, (mach_msg_type_number_t)size) == KERN_SUCCESS;
}

typedef enum { HMNone, HMMachine, HMBoard, HMMemory, HMBoot } HMQuery;
static HMQuery hm_nameQuery(const char *name) {
    // 四个已知名称最长 13 字节；逐字节安全读取，不跨越字符串末尾探测下一页。
    char local[16] = {0};
    for (size_t i = 0; i < sizeof(local); ++i) {
        if (!name || !hm_readBytes((const void *)((uintptr_t)name + i), &local[i], 1)) return HMNone;
        if (!local[i]) {
            if (!strcmp(local, "hw.machine")) return HMMachine;
            if (!strcmp(local, "hw.model")) return HMBoard;
            if (!strcmp(local, "hw.memsize")) return HMMemory;
            if (!strcmp(local, "kern.boottime")) return HMBoot;
            return HMNone;
        }
    }
    return HMNone;
}
static HMQuery hm_mibQuery(const int *name, u_int count) {
    int mib[2];
    if (count != 2 || !hm_readBytes(name, mib, sizeof(mib))) return HMNone;
    if (mib[0] == CTL_HW) {
        if (mib[1] == HW_MACHINE) return HMMachine;
        if (mib[1] == HW_MODEL) return HMBoard;
        if (mib[1] == HW_MEMSIZE) return HMMemory;
    }
    return mib[0] == CTL_KERN && mib[1] == KERN_BOOTTIME ? HMBoot : HMNone;
}

static size_t hm_queryValue(HMQuery query, NSDictionary *s, unsigned char value[256]) {
    if (query == HMMachine || query == HMBoard) {
        const char *str = [s[query == HMMachine ? @"machine" : @"board"] UTF8String];
        if (!str) return 0;
        size_t need = strlen(str) + 1;
        if (need > 256) return 0;
        memcpy(value, str, need);
        return need;
    }
    if (query == HMMemory) {
        uint64_t memory = [s[@"mem"] unsignedLongLongValue];
        memcpy(value, &memory, sizeof(memory));
        return sizeof(memory);
    }
    if (query == HMBoot) {
        struct timeval boot = { (time_t)[s[@"bootEpoch"] longLongValue], 0 };
        memcpy(value, &boot, sizeof(boot));
        return sizeof(boot);
    }
    return 0;
}

// oldp=NULL 不读取未初始化的容量；容量来自真实调用前保存的值。
// 这些标量/字符串使用整值写入：短缓冲不写 oldp，回写所需长度并报告 ENOMEM。
static int hm_emitSysctl(void *oldp, size_t cap, size_t *oldlenp, BOOL capOK,
                        const void *value, size_t need) {
    if (!capOK || !oldlenp || !hm_writeBytes(oldlenp, &need, sizeof(need))) return hm_error(EFAULT);
    if (!oldp) return 0;
    if (cap < need) return hm_error(ENOMEM);
    if (!hm_writeBytes(oldp, value, need)) return hm_error(EFAULT);
    return 0;
}

static int hm_my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                              void *newp, size_t newlen) {
    HMSysctlByName fn = hm_get_real_sysctlbyname();
    if (!fn) return hm_error(ENOSYS);
    if (g_cDepth || !atomic_load(&g_active) || newp || newlen || !oldlenp)
        return fn(name, oldp, oldlenp, newp, newlen);
    ++g_cDepth;
    HMQuery query = hm_nameQuery(name);
    if (query == HMNone) {
        int rv = fn(name, oldp, oldlenp, newp, newlen), error = errno;
        return hm_cReturn(rv, error);
    }
    size_t cap = 0;
    BOOL capOK = !oldp || hm_readBytes(oldlenp, &cap, sizeof(cap));
    unsigned char value[256] = {0};
    size_t realLength = sizeof(value);
    // 先读真实函数到内部缓冲，消除真实/伪装长度不同导致的两阶段读取矛盾。
    int rv = fn(name, value, &realLength, NULL, 0), error = errno;
    if (rv != 0) return hm_cReturn(rv, error);
    NSDictionary *s = hm_snap();
    size_t need = s ? hm_queryValue(query, s, value) : realLength;
    if (!need || need > sizeof(value)) return hm_cReturn(-1, EOVERFLOW);
    rv = hm_emitSysctl(oldp, cap, oldlenp, capOK, value, need);
    return hm_cReturn(rv, rv == 0 ? error : errno);
}

static int hm_my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                        void *newp, size_t newlen) {
    HMSysctl fn = hm_get_real_sysctl();
    if (!fn) return hm_error(ENOSYS);
    if (g_cDepth || !atomic_load(&g_active) || newp || newlen || !oldlenp)
        return fn(name, namelen, oldp, oldlenp, newp, newlen);
    ++g_cDepth;
    HMQuery query = hm_mibQuery(name, namelen);
    if (query == HMNone) {
        int rv = fn(name, namelen, oldp, oldlenp, newp, newlen), error = errno;
        return hm_cReturn(rv, error);
    }
    size_t cap = 0;
    BOOL capOK = !oldp || hm_readBytes(oldlenp, &cap, sizeof(cap));
    unsigned char value[256] = {0};
    size_t realLength = sizeof(value);
    int rv = fn(name, namelen, value, &realLength, NULL, 0), error = errno;
    if (rv != 0) return hm_cReturn(rv, error);
    NSDictionary *s = hm_snap();
    size_t need = s ? hm_queryValue(query, s, value) : realLength;
    if (!need || need > sizeof(value)) return hm_cReturn(-1, EOVERFLOW);
    rv = hm_emitSysctl(oldp, cap, oldlenp, capOK, value, need);
    return hm_cReturn(rv, rv == 0 ? error : errno);
}

static int hm_my_uname(struct utsname *u) {
    HMUname fn = hm_get_real_uname();
    if (!fn) return hm_error(ENOSYS);
    if (g_cDepth || !atomic_load(&g_active)) return fn(u);
    ++g_cDepth;
    int rv = fn(u), error = errno;
    if (rv != 0) return hm_cReturn(rv, error);
    NSDictionary *s = hm_snap();
    if (s && u) {
        char machine[sizeof(u->machine)] = {0};
        strlcpy(machine, [s[@"machine"] UTF8String], sizeof(machine));
        if (!hm_writeBytes(u->machine, machine, sizeof(machine))) return hm_cReturn(-1, EFAULT);
    }
    return hm_cReturn(rv, error);
}

static BOOL hm_isDataVolume(const struct statfs *buf) {
    if (strncmp(buf->f_fstypename, "apfs", sizeof(buf->f_fstypename)) != 0) return NO;
    return strncmp(buf->f_mntonname, "/var", sizeof(buf->f_mntonname)) == 0 ||
           strncmp(buf->f_mntonname, "/private/var", sizeof(buf->f_mntonname)) == 0;
}
static int hm_my_statfs(const char *path, struct statfs *buf) {
    HMStatfs fn = hm_get_real_statfs();
    if (!fn) return hm_error(ENOSYS);
    if (g_cDepth || !atomic_load(&g_active)) return fn(path, buf);
    ++g_cDepth;
    int rv = fn(path, buf), error = errno;
    if (rv != 0) return hm_cReturn(rv, error);
    NSDictionary *s = hm_snap();
    struct statfs value;
    if (s && hm_readBytes(buf, &value, sizeof(value)) && hm_isDataVolume(&value) && value.f_bsize > 0) {
        uint64_t blockSize = value.f_bsize;
        uint64_t minimumBlocks = (50000000000ull + blockSize - 1) / blockSize;
        if (value.f_blocks >= minimumBlocks) {
            uint64_t blocks = [s[@"disk"] unsignedLongLongValue] / blockSize;
            double frac = [s[@"freeFrac"] doubleValue];
            uint64_t freeBlocks = (uint64_t)(blocks * frac);
            uint64_t reserved = blocks / 200;
            value.f_blocks = blocks;
            value.f_bfree = freeBlocks;
            value.f_bavail = freeBlocks > reserved ? freeBlocks - reserved : 0;
            if (!hm_writeBytes(buf, &value, sizeof(value))) return hm_cReturn(-1, EFAULT);
        }
    }
    return hm_cReturn(rv, error);
}

#define DYLD_INTERPOSE(_repl, _replacee) \
  __attribute__((used)) static struct { const void *repl; const void *replacee; } \
  _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = \
  { (const void *)(uintptr_t)&_repl, (const void *)(uintptr_t)&_replacee };

#ifndef HM_HOST_TEST
DYLD_INTERPOSE(hm_my_sysctl, sysctl)
DYLD_INTERPOSE(hm_my_sysctlbyname, sysctlbyname)
DYLD_INTERPOSE(hm_my_uname, uname)
DYLD_INTERPOSE(hm_my_statfs, statfs)
#endif

static BOOL hm_encodingOK(Method method, const char *expected) {
    if (!method || method_getNumberOfArguments(method) != 2) return NO;
    char result[256] = {0}, receiver[32] = {0}, command[32] = {0};
    method_getReturnType(method, result, sizeof(result));
    method_getArgumentType(method, 0, receiver, sizeof(receiver));
    method_getArgumentType(method, 1, command, sizeof(command));
    // 比较完整返回结构布局；不把所有以 '{' 开头的类型视为同一种 ABI。
    return !strcmp(result, expected) && !strcmp(receiver, @encode(id)) &&
           !strcmp(command, @encode(SEL));
}

static BOOL hm_install(Class cls, SEL sel, IMP newImp, _Atomic(IMP) *store, const char *encoding) {
    Method method = class_getInstanceMethod(cls, sel);
    if (!newImp || !store || !hm_encodingOK(method, encoding)) return NO;
    IMP previous = method_getImplementation(method);
    if (!previous || previous == newImp) return NO;
    // 先发布可调用的原 IMP，再让任何线程看见新方法；不手工剥离 PAC。
    atomic_store_explicit(store, previous, memory_order_release);
    const char *types = method_getTypeEncoding(method);
    if (class_addMethod(cls, sel, newImp, types)) return YES;
    // 本类已有方法时才替换，继承的 Method 不会写到父类上。
    method = class_getInstanceMethod(cls, sel);
    previous = method_setImplementation(method, newImp);
    if (!previous) return NO;
    atomic_store_explicit(store, previous, memory_order_release);
    return YES;
}

static CGRect hm_profileBounds(NSDictionary *s, CGRect real, BOOL pixels) {
    CGFloat w = [s[pixels ? @"nw" : @"w"] doubleValue];
    CGFloat h = [s[pixels ? @"nh" : @"h"] doubleValue];
    if (real.size.width > real.size.height) { CGFloat t = w; w = h; h = t; }
    return CGRectMake(real.origin.x, real.origin.y, w, h);
}

static UIEdgeInsets hm_hardwareInsets(NSDictionary *s, BOOL landscape, BOOL statusVisible) {
    CGFloat top = [s[@"safeTop"] doubleValue], bottom = [s[@"safeBottom"] doubleValue];
    if (landscape) return (UIEdgeInsets){0, bottom > 0 ? top : 0, bottom > 0 ? 21 : 0, bottom > 0 ? top : 0};
    return (UIEdgeInsets){bottom > 0 || statusVisible ? top : 0, 0, bottom, 0};
}

static UIEdgeInsets hm_overlapInsets(CGRect view, CGRect window, UIEdgeInsets hardware) {
    return (UIEdgeInsets){
        fmin(view.size.height, fmax(0, CGRectGetMinY(window) + hardware.top - CGRectGetMinY(view))),
        fmin(view.size.width, fmax(0, CGRectGetMinX(window) + hardware.left - CGRectGetMinX(view))),
        fmin(view.size.height, fmax(0, CGRectGetMaxY(view) - (CGRectGetMaxY(window) - hardware.bottom))),
        fmin(view.size.width, fmax(0, CGRectGetMaxX(view) - (CGRectGetMaxX(window) - hardware.right)))};
}

static UIEdgeInsets hm_replaceHardwareInsets(UIEdgeInsets real, UIEdgeInsets old, UIEdgeInsets next) {
    return (UIEdgeInsets){fmax(0, real.top - old.top) + next.top,
        fmax(0, real.left - old.left) + next.left,
        fmax(0, real.bottom - old.bottom) + next.bottom,
        fmax(0, real.right - old.right) + next.right};
}

#ifndef HM_HOST_TEST

// ----------------------------- ObjC 层 Hook -----------------------------
// 统一：校验方法存在且返回类型编码符合预期后才替换，保存原 IMP

static _Atomic(IMP) orig_systemVersion, orig_model, orig_localizedModel, orig_name, orig_idfv;
static _Atomic(IMP) orig_osVer;                                   // NSProcessInfo operatingSystemVersion
static _Atomic(IMP) orig_screenBounds, orig_nativeBounds, orig_appFrame, orig_scale, orig_nativeScale;

static NSString *hm_hook_systemVersion(id self, SEL cmd) {
    NSDictionary *s = hm_snap();
    return s ? s[@"sysVer"] : ((NSString *(*)(id, SEL))atomic_load(&orig_systemVersion))(self, cmd);
}
static NSString *hm_hook_model(id self, SEL cmd) {
    NSDictionary *s = hm_snap();
    return s ? @"iPhone" : ((NSString *(*)(id, SEL))atomic_load(&orig_model))(self, cmd);
}
static NSString *hm_hook_localizedModel(id self, SEL cmd) {
    NSDictionary *s = hm_snap();
    return s ? @"iPhone" : ((NSString *(*)(id, SEL))atomic_load(&orig_localizedModel))(self, cmd);
}
static NSString *hm_hook_name(id self, SEL cmd) {
    NSDictionary *s = hm_snap();
    return s ? s[@"deviceName"] : ((NSString *(*)(id, SEL))atomic_load(&orig_name))(self, cmd);
}
static NSUUID *hm_hook_idfv(id self, SEL cmd) {
    NSDictionary *s = hm_snap();
    if (s) {
        NSUUID *u = [[NSUUID alloc] initWithUUIDString:s[@"idfv"]];
        if (u) return u;
    }
    return ((NSUUID *(*)(id, SEL))atomic_load(&orig_idfv))(self, cmd);
}

// NSProcessInfo -[operatingSystemVersion] 返回 NSOperatingSystemVersion（3×NSInteger）
static NSOperatingSystemVersion hm_hook_osVer(id self, SEL cmd) {
    NSDictionary *s = hm_snap();
    if (s) {
        NSArray *p = [s[@"sysVer"] componentsSeparatedByString:@"."];
        NSOperatingSystemVersion v = {0, 0, 0};
        if (p.count >= 1) v.majorVersion = [p[0] integerValue];
        if (p.count >= 2) v.minorVersion = [p[1] integerValue];
        if (p.count >= 3) v.patchVersion = [p[2] integerValue];
        return v;
    }
    return ((NSOperatingSystemVersion(*)(id, SEL))atomic_load(&orig_osVer))(self, cmd);
}

// 调用 UIKit 原实现时禁止嵌套变换，避免 applicationFrame/安全区内部再次调用 bounds。
static _Thread_local unsigned g_uiDepth;
static _Atomic(IMP) orig_statusFrame, orig_managerStatusFrame, orig_viewSafe, orig_windowSafe;
#define HM_UI_ORIGINAL(type, slot) \
    ++g_uiDepth; \
    type real = ((type(*)(id, SEL))atomic_load_explicit(&(slot), memory_order_acquire))(self, cmd); \
    --g_uiDepth

static CGRect hm_hook_bounds(id self, SEL cmd) {
    HM_UI_ORIGINAL(CGRect, orig_screenBounds);
    NSDictionary *s = g_uiDepth ? nil : hm_snap();
    return s && self == UIScreen.mainScreen ? hm_profileBounds(s, real, NO) : real;
}
static CGRect hm_hook_nativeBounds(id self, SEL cmd) {
    HM_UI_ORIGINAL(CGRect, orig_nativeBounds);
    NSDictionary *s = g_uiDepth ? nil : hm_snap();
    return s && self == UIScreen.mainScreen ? hm_profileBounds(s, real, YES) : real;
}
static CGRect hm_hook_appFrame(id self, SEL cmd) {
    HM_UI_ORIGINAL(CGRect, orig_appFrame);
    NSDictionary *s = g_uiDepth ? nil : hm_snap();
    if (!s || self != UIScreen.mainScreen) return real;
    ++g_uiDepth;
    CGRect bounds = ((CGRect(*)(id, SEL))atomic_load(&orig_screenBounds))(self, @selector(bounds));
    --g_uiDepth;
    CGRect next = hm_profileBounds(s, bounds, NO);
    // 保留原实现的窗口边缘语义；顶边是可见状态栏时，替换成所选机型高度。
    CGFloat top = fmax(0, CGRectGetMinY(real) - CGRectGetMinY(bounds));
    CGFloat bottom = fmax(0, CGRectGetMaxY(bounds) - CGRectGetMaxY(real));
    CGFloat left = fmax(0, CGRectGetMinX(real) - CGRectGetMinX(bounds));
    CGFloat right = fmax(0, CGRectGetMaxX(bounds) - CGRectGetMaxX(real));
    if (top > 0 && top <= 64 && bounds.size.height >= bounds.size.width)
        top = [s[@"status"] doubleValue];
    return UIEdgeInsetsInsetRect(next, (UIEdgeInsets){top, left, bottom, right});
}
static CGFloat hm_hook_scale(id self, SEL cmd) {
    HM_UI_ORIGINAL(CGFloat, orig_scale);
    NSDictionary *s = g_uiDepth ? nil : hm_snap();
    return s && self == UIScreen.mainScreen ? [s[@"scale"] doubleValue] : real;
}
static CGFloat hm_hook_nativeScale(id self, SEL cmd) {
    HM_UI_ORIGINAL(CGFloat, orig_nativeScale);
    NSDictionary *s = g_uiDepth ? nil : hm_snap();
    return s && self == UIScreen.mainScreen ? [s[@"scale"] doubleValue] : real;
}
static CGRect hm_statusFrame(CGRect real, NSDictionary *s, BOOL landscape) {
    if (CGRectIsEmpty(real)) return real; // 隐藏状态栏继续返回 CGRectZero。
    if (landscape && [s[@"safeBottom"] doubleValue] > 0) return CGRectZero;
    CGRect next = real;
    next.size.width = [s[landscape ? @"h" : @"w"] doubleValue];
    next.size.height = [s[@"status"] doubleValue];
    return next;
}
static CGRect hm_hook_statusFrame(id self, SEL cmd) {
    HM_UI_ORIGINAL(CGRect, orig_statusFrame);
    NSDictionary *s = g_uiDepth ? nil : hm_snap();
    if (!s) return real;
    ++g_uiDepth;
    CGRect bounds = ((CGRect(*)(id, SEL))atomic_load(&orig_screenBounds))(UIScreen.mainScreen, @selector(bounds));
    --g_uiDepth;
    return hm_statusFrame(real, s, bounds.size.width > bounds.size.height);
}
static CGRect hm_hook_managerStatusFrame(id self, SEL cmd) {
    HM_UI_ORIGINAL(CGRect, orig_managerStatusFrame);
    NSDictionary *s = g_uiDepth ? nil : hm_snap();
    if (s) for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        UIWindowScene *windowScene = (UIWindowScene *)scene;
        if (windowScene.statusBarManager == self && windowScene.screen == UIScreen.mainScreen) {
            if (UIInterfaceOrientationIsLandscape(windowScene.interfaceOrientation)) {
                if ([s[@"safeBottom"] doubleValue] > 0) return CGRectZero;
                if (!CGRectIsEmpty(real)) return CGRectMake(0, 0, [s[@"h"] doubleValue], [s[@"status"] doubleValue]);
                return real;
            }
            return hm_statusFrame(real, s, NO);
        }
    }
    return real;
}
static UIEdgeInsets hm_adjustSafe(UIView *view, UIEdgeInsets real, NSDictionary *s) {
    UIWindow *window = [view isKindOfClass:UIWindow.class] ? (UIWindow *)view : view.window;
    if (!window || window.hidden || view.hidden || window.screen != UIScreen.mainScreen) return real;
    // 只处理普通全屏窗口，外接屏、非全屏窗口保留 UIKit 语义。
    CGRect windowBounds = window.bounds;
    ++g_uiDepth;
    CGRect screenBounds = ((CGRect(*)(id, SEL))atomic_load(&orig_screenBounds))(UIScreen.mainScreen, @selector(bounds));
    UIEdgeInsets originalHardware = ((UIEdgeInsets(*)(id, SEL))atomic_load(&orig_windowSafe))(window, @selector(safeAreaInsets));
    --g_uiDepth;
    CGRect virtualBounds = hm_profileBounds(s, screenBounds, NO);
    if (!CGSizeEqualToSize(windowBounds.size, screenBounds.size) &&
        !CGSizeEqualToSize(windowBounds.size, virtualBounds.size)) return real;
    BOOL landscape = windowBounds.size.width > windowBounds.size.height;
    BOOL statusVisible = !CGRectIsEmpty(window.windowScene.statusBarManager.statusBarFrame);
    UIEdgeInsets next = hm_hardwareInsets(s, landscape, statusVisible);
    CGRect viewInWindow = [view convertRect:view.bounds toView:window];
    UIEdgeInsets oldOverlap = hm_overlapInsets(viewInWindow, windowBounds, originalHardware);
    UIEdgeInsets nextOverlap = hm_overlapInsets(viewInWindow, windowBounds, next);
    UIEdgeInsets result = hm_replaceHardwareInsets(real, oldOverlap, nextOverlap);
    result.top = fmin(result.top, view.bounds.size.height);
    result.bottom = fmin(result.bottom, view.bounds.size.height);
    result.left = fmin(result.left, view.bounds.size.width);
    result.right = fmin(result.right, view.bounds.size.width);
    return result;
}
static UIEdgeInsets hm_hook_viewSafe(id self, SEL cmd) {
    HM_UI_ORIGINAL(UIEdgeInsets, orig_viewSafe);
    NSDictionary *s = g_uiDepth ? nil : hm_snap();
    return s ? hm_adjustSafe(self, real, s) : real;
}
static UIEdgeInsets hm_hook_windowSafe(id self, SEL cmd) {
    HM_UI_ORIGINAL(UIEdgeInsets, orig_windowSafe);
    NSDictionary *s = g_uiDepth ? nil : hm_snap();
    return s ? hm_adjustSafe(self, real, s) : real;
}
#undef HM_UI_ORIGINAL

static BOOL hm_installObjCHooks(void) {
    BOOL ok = YES;
#define HM_INSTALL(cls, selector, replacement, original, type) \
    ok = hm_install(cls, @selector(selector), (IMP)replacement, &original, @encode(type)) && ok
    Class dev = UIDevice.class, pi = NSProcessInfo.class, scr = UIScreen.class;
    HM_INSTALL(dev, systemVersion, hm_hook_systemVersion, orig_systemVersion, id);
    HM_INSTALL(dev, model, hm_hook_model, orig_model, id);
    HM_INSTALL(dev, localizedModel, hm_hook_localizedModel, orig_localizedModel, id);
    HM_INSTALL(dev, name, hm_hook_name, orig_name, id);
    HM_INSTALL(dev, identifierForVendor, hm_hook_idfv, orig_idfv, id);
    HM_INSTALL(pi, operatingSystemVersion, hm_hook_osVer, orig_osVer, NSOperatingSystemVersion);
    HM_INSTALL(scr, bounds, hm_hook_bounds, orig_screenBounds, CGRect);
    HM_INSTALL(scr, nativeBounds, hm_hook_nativeBounds, orig_nativeBounds, CGRect);
    HM_INSTALL(scr, applicationFrame, hm_hook_appFrame, orig_appFrame, CGRect);
    HM_INSTALL(scr, scale, hm_hook_scale, orig_scale, CGFloat);
    HM_INSTALL(scr, nativeScale, hm_hook_nativeScale, orig_nativeScale, CGFloat);
    HM_INSTALL(UIApplication.class, statusBarFrame, hm_hook_statusFrame, orig_statusFrame, CGRect);
    HM_INSTALL(UIStatusBarManager.class, statusBarFrame, hm_hook_managerStatusFrame, orig_managerStatusFrame, CGRect);
    HM_INSTALL(UIView.class, safeAreaInsets, hm_hook_viewSafe, orig_viewSafe, UIEdgeInsets);
    HM_INSTALL(UIWindow.class, safeAreaInsets, hm_hook_windowSafe, orig_windowSafe, UIEdgeInsets);
#undef HM_INSTALL
    return ok;
}

// ----------------------------- 浮窗 -----------------------------

@interface HMPassWindow : UIWindow @end
@implementation HMPassWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (v == self || v == self.rootViewController.view) return nil;
    return v;
}
@end

@interface HMFloatVC : UIViewController
@property (nonatomic, strong) UILabel *info;
@end
@implementation HMFloatVC
- (void)viewDidLoad {
    [super viewDidLoad];
    UIView *card = [[UIView alloc] initWithFrame:CGRectMake(8, 60, 230, 150)];
    card.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.72];
    card.layer.cornerRadius = 10;
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self
                                                                         action:@selector(onPan:)];
    [card addGestureRecognizer:pan];
    [self.view addSubview:card];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(10, 6, 210, 18)];
    title.text = [@"HMSpoofer " stringByAppendingString:HMVersion];
    title.textColor = [UIColor colorWithRed:0.4 green:0.85 blue:1 alpha:1];
    title.font = [UIFont boldSystemFontOfSize:12];
    [card addSubview:title];

    self.info = [[UILabel alloc] initWithFrame:CGRectMake(10, 26, 210, 66)];
    self.info.numberOfLines = 0;
    self.info.textColor = [UIColor whiteColor];
    self.info.font = [UIFont systemFontOfSize:10];
    [card addSubview:self.info];

    UIButton *btnRand = [UIButton buttonWithType:UIButtonTypeSystem];
    btnRand.frame = CGRectMake(10, 98, 100, 22);
    [btnRand setTitle:@"换一套(重启生效)" forState:UIControlStateNormal];
    btnRand.titleLabel.font = [UIFont systemFontOfSize:11];
    [btnRand addTarget:self action:@selector(onRandom) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:btnRand];

    UIButton *btnToggle = [UIButton buttonWithType:UIButtonTypeSystem];
    btnToggle.frame = CGRectMake(120, 98, 100, 22);
    [btnToggle setTitle:@"开/关(重启生效)" forState:UIControlStateNormal];
    btnToggle.titleLabel.font = [UIFont systemFontOfSize:10];
    [btnToggle addTarget:self action:@selector(onToggle) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:btnToggle];

    UIButton *btnHide = [UIButton buttonWithType:UIButtonTypeSystem];
    btnHide.frame = CGRectMake(10, 122, 210, 20);
    [btnHide setTitle:@"收起（重启后再现）" forState:UIControlStateNormal];
    btnHide.titleLabel.font = [UIFont systemFontOfSize:10];
    [btnHide addTarget:self action:@selector(onHide) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:btnHide];
    [self refresh];
}
- (void)refresh {
    os_unfair_lock_lock(&g_lock);
    NSDictionary *p = [g_profile copy];
    os_unfair_lock_unlock(&g_lock);
    if (g_startupError) {
        self.info.text = [@"本次未启用：\n" stringByAppendingString:g_startupError];
        return;
    }
    NSDictionary *pending = hm_pending();
    NSString *idfv = p[@"idfv"] ?: @"-";
    if (idfv.length > 8) idfv = [idfv substringToIndex:8];
    self.info.text = [NSString stringWithFormat:
        @"状态:%@\n机型:%@ (%@)\niOS:%@  内存:%lluGB\nIDFV:%@…",
        ![pending isEqual:p] ? @"待重启生效" : ([p[@"enabled"] boolValue] ? @"开启" : @"关闭"),
        p[@"machine"], p[@"board"], p[@"sysVer"],
        (unsigned long long)([p[@"mem"] unsignedLongLongValue] / (1024ull*1024*1024)),
        idfv];
}
- (void)onPan:(UIPanGestureRecognizer *)g {
    UIView *card = g.view;
    CGPoint t = [g translationInView:self.view];
    card.center = CGPointMake(card.center.x + t.x, card.center.y + t.y);
    [g setTranslation:CGPointZero inView:self.view];
}
- (void)changePending:(BOOL)randomize {
    NSError *error = nil;
    BOOL saved = hm_changePending(randomize, &error);
    NSDictionary *p = hm_pending();
    NSString *message = saved ? [NSString stringWithFormat:
        @"下次冷启动：%@ / iOS %@ / %@。请彻底杀掉河马后重新打开。",
        p[@"machine"], p[@"sysVer"], [p[@"enabled"] boolValue] ? @"开启" : @"关闭"]
        : (error.localizedDescription ?: @"写入失败，请重试；当前身份未变。");
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:saved ? @"已保存，重启生效" : @"保存失败"
        message:message preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault
                                         handler:^(UIAlertAction *a) { [self refresh]; }]];
    [self presentViewController:ac animated:YES completion:nil];
}
- (void)onRandom { [self changePending:YES]; }
- (void)onToggle { [self changePending:NO]; }
- (void)onHide { self.view.window.hidden = YES; }
@end

static HMPassWindow *g_win = nil;
static void hm_showFloat(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_win) { g_win.hidden = NO; return; }
        g_win = [[HMPassWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if ([scene isKindOfClass:UIWindowScene.class] &&
                scene.activationState == UISceneActivationStateForegroundActive &&
                ((UIWindowScene *)scene).screen == UIScreen.mainScreen) {
                g_win.windowScene = (UIWindowScene *)scene;
                break;
            }
        }
        g_win.windowLevel = UIWindowLevelAlert + 20;
        g_win.backgroundColor = [UIColor clearColor];
        HMFloatVC *vc = [HMFloatVC new];
        vc.view.backgroundColor = [UIColor clearColor];
        g_win.rootViewController = vc;
        g_win.hidden = NO;
    });
}

// ----------------------------- 启动 -----------------------------

__attribute__((constructor))
static void hm_ctor(void) {
    @autoreleasepool {
    if (!hm_isTargetApp()) return;
    // 不短路：四个符号均独立尝试解析，任何必需出口缺失都保持透传。
    BOOL cReady = hm_get_real_sysctl() != NULL;
    cReady = (hm_get_real_sysctlbyname() != NULL) && cReady;
    cReady = (hm_get_real_uname() != NULL) && cReady;
    cReady = (hm_get_real_statfs() != NULL) && cReady;
    BOOL profileReady = hm_loadOrInit();
    BOOL hooksReady = profileReady && hm_installObjCHooks();
    if (!cReady) g_startupError = @"系统函数解析失败";
    else if (profileReady && !hooksReady) g_startupError = @"系统方法签名或 Hook 安装不兼容";
    if (cReady && profileReady && hooksReady && [g_profile[@"enabled"] boolValue])
        atomic_store_explicit(&g_active, 1, memory_order_release);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ hm_showFloat(); });
    }
}
#endif // !HM_HOST_TEST
