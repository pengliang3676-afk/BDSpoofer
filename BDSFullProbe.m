// BDSFullProbe —— 百度极速版「全方位只读观察探针」
//
// 设计原则（务必遵守）：
//   1. 只读：绝不修改任何返回值，看到的就是百度真实拿到的
//   2. 可单独运行：必须能在「不装主插件」的情况下工作，以取得基线数据
//   3. 失败安全：任何一处 hook 出错都不影响 App 正常运行
//
// 覆盖 6 层：
//   L1 标识符      IDFV/IDFA/ATT/设备名/百度 SDK 标识
//   L2 硬件与系统  sysctl/uname/NSProcessInfo/磁盘
//   L3 网络        接口枚举/本地 IP/SSID/代理
//   L4 地区权限越狱 Locale/时区/定位/越狱路径（重点记录查了哪些路径）
//   L5 动态库枚举  _dyld_image_count / _dyld_get_image_name（检测注入）
//   L6 时间        NSDate/time()/CFAbsoluteTime/开机时长/时区偏移
//
// 输出：Documents/bds_fullprobe_<时间戳>.txt，并在面板里可复制

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <net/if.h>
#import <net/if_dl.h>
#import <string.h>
#import <errno.h>
#import <stdlib.h>
#import <time.h>
#import <sys/time.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>

static NSString * const BFPVersion = @"1.0";

#pragma mark - 记录器（线程安全，只读）

static NSMutableDictionary<NSString *, NSMutableDictionary *> *g_rec;
static NSMutableArray<NSString *> *g_jbPaths;      // 越狱相关路径访问记录
static NSMutableSet<NSString *> *g_images;         // 动态库快照
static NSLock *g_lock;
static CFAbsoluteTime g_startTime;
static NSUInteger g_totalRecords = 0;
static const NSUInteger kMaxPerKey = 300;          // 每项最多记 300 条，防爆

static void bfp_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_rec = [NSMutableDictionary dictionary];
        g_jbPaths = [NSMutableArray array];
        g_images = [NSMutableSet set];
        g_lock = [[NSLock alloc] init];
        g_startTime = CFAbsoluteTimeGetCurrent();
    });
}

// 记录一次调用：key=API 名，value=本次返回值
static void bfp_rec(NSString *key, NSString *value) {
    if (!key) return;
    bfp_init();
    [g_lock lock];
    NSMutableDictionary *e = g_rec[key];
    if (!e) {
        e = [NSMutableDictionary dictionary];
        e[@"n"] = @0;
        e[@"first"] = @(CFAbsoluteTimeGetCurrent() - g_startTime);
        e[@"samples"] = [NSMutableArray array];
        g_rec[key] = e;
    }
    NSUInteger n = [e[@"n"] unsignedIntegerValue] + 1;
    e[@"n"] = @(n);
    NSMutableArray *s = e[@"samples"];
    if (s.count < kMaxPerKey) {
        NSString *v = value.length > 300 ? [[value substringToIndex:300] stringByAppendingString:@"…"] : (value ?: @"(nil)");
        if (![s containsObject:v]) [s addObject:v];     // 去重，只留不同的值
    }
    g_totalRecords++;
    [g_lock unlock];
}

// 判断调用方是不是百度自己的库（用于排除系统内部调用）
static BOOL bfp_caller_is_baidu(void) {
    // 简化实现：看当前进程的可执行文件名。探针只注入百度，所以基本恒真。
    // 这里保留接口，便于以后加调用栈分析。
    return YES;
}

#pragma mark - 通用 hook 工具

typedef id (*BFPIdIMP)(id, SEL);
typedef void (*BFPVoidIMP)(id, SEL, id);

static IMP bfp_orig(Class cls, SEL sel) {
    if (!cls) return NULL;
    Method m = class_getInstanceMethod(cls, sel);
    return m ? method_getImplementation(m) : NULL;
}

// 安装一个「记录返回值」的 hook。
// 安全约束：只处理 0 参数方法。带参数的方法必须单独写精确签名的 hook ——
// 用可变参数 (id, SEL, ...) 转发再按固定原型调用，参数寄存器会对不上，直接栈错乱。
static void bfp_hook_desc(Class cls, NSString *selName, NSString *label) {
    if (!cls) return;
    SEL sel = NSSelectorFromString(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    // 跳过多参数方法（selector 里出现 ':' 说明有参数）
    if ([selName containsString:@":"]) return;
    IMP orig = method_getImplementation(m);
    __block IMP o = orig;
    IMP newImp = imp_implementationWithBlock(^id(id self_, ...) {
        // 用 objc_msgSend 调原实现，参数个数不确定时按 0 参处理（这些 getter 都是 0 参）
        id r = ((BFPIdIMP)o)(self_, sel);
        NSString *desc = nil;
        if ([r isKindOfClass:NSString.class]) desc = r;
        else if ([r isKindOfClass:NSNumber.class]) desc = [r description];
        else if ([r isKindOfClass:NSArray.class]) desc = [r componentsJoinedByString:@","];
        else if (r) desc = [NSString stringWithFormat:@"<%@>", NSStringFromClass([r class])];
        else desc = @"(nil)";
        bfp_rec(label, desc);
        return r;
    });
    method_setImplementation(m, newImp);
}

#pragma mark - L1 标识符

static void bfp_install_L1(void) {
    Class dev = objc_getClass("UIDevice");
    bfp_hook_desc(dev, @"identifierForVendor", @"L1 UIDevice.identifierForVendor");
    bfp_hook_desc(dev, @"name", @"L1 UIDevice.name");
    bfp_hook_desc(dev, @"systemVersion", @"L1 UIDevice.systemVersion");
    bfp_hook_desc(dev, @"model", @"L1 UIDevice.model");
    bfp_hook_desc(dev, @"localizedModel", @"L1 UIDevice.localizedModel");
    bfp_hook_desc(dev, @"systemName", @"L1 UIDevice.systemName");

    Class asim = objc_getClass("ASIdentifierManager");
    bfp_hook_desc(asim, @"advertisingIdentifier", @"L1 ASIdentifierManager.advertisingIdentifier");
    bfp_hook_desc(asim, @"isAdvertisingTrackingEnabled", @"L1 ASIdentifierManager.isAdvertisingTrackingEnabled");

    Class att = objc_getClass("ATTrackingManager");
    bfp_hook_desc(att, @"trackingAuthorizationStatus", @"L1 ATTrackingManager.authorizationStatus");

    // 百度自己的标识类（如果存在）
    NSArray *baiduIdClasses = @[@"CuidSDK", @"CuidSDK18BBADevAccountPatch", @"UTDIDModule",
                                @"DeviceIdentifierFetcher", @"MobStat"];
    for (NSString *cn in baiduIdClasses) {
        Class c = objc_getClass(cn.UTF8String);
        if (!c) continue;
        unsigned int n = 0;
        Method *ms = class_copyMethodList(object_getClass(c), &n);   // 类方法
        for (unsigned int i = 0; i < n; i++) {
            NSString *sn = NSStringFromSelector(method_getName(ms[i]));
            if ([sn hasPrefix:@"cuid"] || [sn hasPrefix:@"utdid"] || [sn hasPrefix:@"deviceID"] ||
                [sn hasPrefix:@"get"] || [sn hasPrefix:@"shared"]) {
                bfp_hook_desc(c, sn, [NSString stringWithFormat:@"L1 %@.%@", cn, sn]);
            }
        }
        if (ms) free(ms);
    }
}

#pragma mark - L2 硬件与系统（sysctl / uname）

static int (*bfp_orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int bfp_my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = bfp_orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    if (name && r == 0 && oldp && oldlenp && !newp) {
        NSString *v = nil;
        size_t len = *oldlenp;
        if (len == 4)      v = [NSString stringWithFormat:@"%d", *(int *)oldp];
        else if (len == 8) v = [NSString stringWithFormat:@"%lld", *(long long *)oldp];
        else if (len > 0 && len < 512) {
            char buf[513] = {0};
            memcpy(buf, oldp, len < 512 ? len : 512);
            v = [NSString stringWithUTF8String:buf];
        }
        if (v) bfp_rec([NSString stringWithFormat:@"L2 sysctl %s", name], v);
    }
    return r;
}

static int (*bfp_orig_uname)(struct utsname *);
static int bfp_my_uname(struct utsname *buf) {
    int r = bfp_orig_uname(buf);
    if (r == 0 && buf) {
        bfp_rec(@"L2 uname.machine", [NSString stringWithUTF8String:buf->machine]);
        bfp_rec(@"L2 uname.release", [NSString stringWithUTF8String:buf->release]);
        bfp_rec(@"L2 uname.version", [NSString stringWithUTF8String:buf->version]);
    }
    return r;
}

static void bfp_install_L2(void) {
    Class pi = objc_getClass("NSProcessInfo");
    bfp_hook_desc(pi, @"physicalMemory", @"L2 NSProcessInfo.physicalMemory");
    bfp_hook_desc(pi, @"processorCount", @"L2 NSProcessInfo.processorCount");
    bfp_hook_desc(pi, @"activeProcessorCount", @"L2 NSProcessInfo.activeProcessorCount");
    bfp_hook_desc(pi, @"hostName", @"L2 NSProcessInfo.hostName");
    bfp_hook_desc(pi, @"operatingSystemVersionString", @"L2 NSProcessInfo.operatingSystemVersionString");
    bfp_hook_desc(pi, @"thermalState", @"L2 NSProcessInfo.thermalState");
    bfp_hook_desc(pi, @"isLowPowerModeEnabled", @"L2 NSProcessInfo.isLowPowerModeEnabled");
    bfp_hook_desc(pi, @"systemUptime", @"L2 NSProcessInfo.systemUptime");

    // 带参数的方法：写精确签名，安全转发
    Class fm = objc_getClass("NSFileManager");
    {
        SEL sel = @selector(attributesOfFileSystemForPath:error:);
        Method m = class_getInstanceMethod(fm, sel);
        if (m) {
            IMP o = method_getImplementation(m);
            IMP ni = imp_implementationWithBlock(^NSDictionary *(id self_, NSString *path, NSError **err) {
                typedef NSDictionary *(*F)(id, SEL, NSString *, NSError **);
                NSDictionary *r = ((F)o)(self_, sel, path, err);
                bfp_rec(@"L2 NSFileManager.attributesOfFileSystemForPath",
                        r ? [r description] : @"(nil)");
                return r;
            });
            method_setImplementation(m, ni);
        }
    }
    // 注意：attributesOfFileSystemForPath:error: 有参数，单独用精确签名处理（见下）
}

#pragma mark - L3 网络

static int (*bfp_orig_getifaddrs)(struct ifaddrs **);
static int bfp_my_getifaddrs(struct ifaddrs **ifap) {
    int r = bfp_orig_getifaddrs(ifap);
    if (r == 0 && ifap && *ifap) {
        for (struct ifaddrs *ifa = *ifap; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_name || !ifa->ifa_addr) continue;
            sa_family_t f = ifa->ifa_addr->sa_family;
            if (f == AF_INET) {
                char b[INET_ADDRSTRLEN] = {0};
                struct sockaddr_in *s = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &s->sin_addr, b, sizeof(b));
                bfp_rec([NSString stringWithFormat:@"L3 接口 %s (IPv4)", ifa->ifa_name],
                        [NSString stringWithUTF8String:b]);
            } else if (f == AF_INET6) {
                char b[INET6_ADDRSTRLEN] = {0};
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                inet_ntop(AF_INET6, &s6->sin6_addr, b, sizeof(b));
                bfp_rec([NSString stringWithFormat:@"L3 接口 %s (IPv6)", ifa->ifa_name],
                        [NSString stringWithUTF8String:b]);
            } else if (f == AF_LINK && ifa->ifa_addr->sa_len >= 8) {
                struct sockaddr_dl *dl = (struct sockaddr_dl *)ifa->ifa_addr;
                if (dl->sdl_alen == 6) {
                    unsigned char *m = (unsigned char *)LLADDR(dl);
                    bfp_rec([NSString stringWithFormat:@"L3 接口 %s (MAC)", ifa->ifa_name],
                            [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x",
                             m[0], m[1], m[2], m[3], m[4], m[5]]);
                }
            }
        }
    }
    return r;
}

static CFDictionaryRef (*bfp_orig_CNCopyCurrentNetworkInfo)(CFStringRef);
static CFDictionaryRef bfp_my_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    CFDictionaryRef d = bfp_orig_CNCopyCurrentNetworkInfo(interfaceName);
    if (d) {
        NSString *ssid = (__bridge NSString *)CFDictionaryGetValue(d, kCNNetworkInfoKeySSID);
        NSString *bssid = (__bridge NSString *)CFDictionaryGetValue(d, kCNNetworkInfoKeyBSSID);
        bfp_rec(@"L3 CNCopyCurrentNetworkInfo.SSID", ssid ?: @"(nil)");
        bfp_rec(@"L3 CNCopyCurrentNetworkInfo.BSSID", bssid ?: @"(nil)");
    } else {
        bfp_rec(@"L3 CNCopyCurrentNetworkInfo", @"(返回 NULL)");
    }
    return d;
}

static CFDictionaryRef (*bfp_orig_CFNetworkCopySystemProxySettings)(void);
static CFDictionaryRef bfp_my_CFNetworkCopySystemProxySettings(void) {
    CFDictionaryRef d = bfp_orig_CFNetworkCopySystemProxySettings();
    bfp_rec(@"L3 系统代理设置", d ? [(__bridge NSDictionary *)d description] : @"(nil)");
    return d;
}

#pragma mark - L4 地区 / 时区 / 越狱路径

static void bfp_install_L4(void) {
    Class loc = objc_getClass("NSLocale");
    bfp_hook_desc(loc, @"localeIdentifier", @"L4 NSLocale.localeIdentifier");
    bfp_hook_desc(loc, @"preferredLanguages", @"L4 NSLocale.preferredLanguages");
    bfp_hook_desc(loc, @"currentLocale", @"L4 NSLocale.currentLocale");
    bfp_hook_desc(loc, @"countryCode", @"L4 NSLocale.countryCode");
    bfp_hook_desc(loc, @"languageCode", @"L4 NSLocale.languageCode");

    Class tz = objc_getClass("NSTimeZone");
    bfp_hook_desc(tz, @"localTimeZone", @"L4 NSTimeZone.localTimeZone");
    bfp_hook_desc(tz, @"systemTimeZone", @"L4 NSTimeZone.systemTimeZone");
    bfp_hook_desc(tz, @"defaultTimeZone", @"L4 NSTimeZone.defaultTimeZone");
    bfp_hook_desc(tz, @"secondsFromGMT", @"L4 NSTimeZone.secondsFromGMT");
}

// 越狱相关路径：记录百度查了哪些路径
static BOOL bfp_is_jb_path(const char *p) {
    if (!p) return NO;
    static const char *keys[] = {
        "Cydia", "cydia", "Sileo", "sileo", "Zebra", "Substrate", "substrate",
        "MobileSubstrate", "frida", "Frida", "cycript", "jb", "/jb", "apt",
        "dpkg", "sshd", "/bin/bash", "roothide", "RootHide", "dopamine",
        "TrollStore", "trollstore", "ellekit", "bootstrap", "libhooker",
        "Substitute", "Liberty", "SSLKillSwitch",
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (strstr(p, keys[i])) return YES;
    }
    return NO;
}

static void bfp_record_path(const char *p) {
    if (!p) return;
    NSString *path = [NSString stringWithUTF8String:p];
    if (!path.length) return;
    BOOL jb = bfp_is_jb_path(p);
    bfp_init();
    [g_lock lock];
    // 只记录越狱相关路径 + 少量普通路径作为对照
    if (jb) {
        NSString *entry = [NSString stringWithFormat:@"⚠️ %@", path];
        if (![g_jbPaths containsObject:entry]) [g_jbPaths addObject:entry];
    } else if (g_jbPaths.count < kMaxPerKey) {
        NSString *entry = [NSString stringWithFormat:@"   %@", path];
        if (![g_jbPaths containsObject:entry]) [g_jbPaths addObject:entry];
    }
    [g_lock unlock];
    if (jb) bfp_rec(@"L4 越狱路径命中", path);
}

static int (*bfp_orig_stat)(const char *, struct stat *);
static int bfp_my_stat(const char *p, struct stat *b) { bfp_record_path(p); return bfp_orig_stat(p, b); }
static int (*bfp_orig_lstat)(const char *, struct stat *);
static int bfp_my_lstat(const char *p, struct stat *b) { bfp_record_path(p); return bfp_orig_lstat(p, b); }
static int (*bfp_orig_access)(const char *, int);
static int bfp_my_access(const char *p, int m) { bfp_record_path(p); return bfp_orig_access(p, m); }
static FILE *(*bfp_orig_fopen)(const char *, const char *);
static FILE *bfp_my_fopen(const char *p, const char *m) { bfp_record_path(p); return bfp_orig_fopen(p, m); }
static DIR *(*bfp_orig_opendir)(const char *);
static DIR *bfp_my_opendir(const char *p) { bfp_record_path(p); return bfp_orig_opendir(p); }

#pragma mark - L5 动态库枚举（检测注入）

static uint32_t (*bfp_orig_dyld_image_count)(void);
static uint32_t bfp_my_dyld_image_count(void) {
    uint32_t c = bfp_orig_dyld_image_count();
    bfp_rec(@"L5 _dyld_image_count", [NSString stringWithFormat:@"%u", c]);
    return c;
}

static const char *(*bfp_orig_dyld_get_image_name)(uint32_t);
static const char *bfp_my_dyld_get_image_name(uint32_t idx) {
    const char *n = bfp_orig_dyld_get_image_name(idx);
    if (n) {
        NSString *s = [NSString stringWithUTF8String:n];
        bfp_rec(@"L5 _dyld_get_image_name", s);
        bfp_init();
        [g_lock lock];
        [g_images addObject:s ?: @"(nil)"];
        [g_lock unlock];
    }
    return n;
}

#pragma mark - L6 时间

static CFAbsoluteTime (*bfp_orig_CFAbsoluteTimeGetCurrent)(void);
static CFAbsoluteTime bfp_my_CFAbsoluteTimeGetCurrent(void) {
    CFAbsoluteTime t = bfp_orig_CFAbsoluteTimeGetCurrent();
    bfp_rec(@"L6 CFAbsoluteTimeGetCurrent", [NSString stringWithFormat:@"%.3f", t]);
    return t;
}

static time_t (*bfp_orig_time)(time_t *);
static time_t bfp_my_time(time_t *t) {
    time_t r = bfp_orig_time(t);
    bfp_rec(@"L6 time()", [NSString stringWithFormat:@"%lld", (long long)r]);
    return r;
}

static int (*bfp_orig_gettimeofday)(struct timeval *, void *);
static int bfp_my_gettimeofday(struct timeval *tv, void *tz) {
    int r = bfp_orig_gettimeofday(tv, tz);
    if (r == 0 && tv) bfp_rec(@"L6 gettimeofday", [NSString stringWithFormat:@"%lld.%06d", (long long)tv->tv_sec, (int)tv->tv_usec]);
    return r;
}

static void bfp_install_L6(void) {
    Class d = objc_getClass("NSDate");
    // +[NSDate date] 是类方法，单独处理
    Method m = class_getClassMethod(d, @selector(date));
    if (m) {
        IMP o = method_getImplementation(m);
        IMP ni = imp_implementationWithBlock(^id(id self_) {
            id r = ((BFPIdIMP)o)(self_, @selector(date));
            bfp_rec(@"L6 NSDate.date", [r description]);
            return r;
        });
        method_setImplementation(m, ni);
    }
    bfp_hook_desc(d, @"timeIntervalSince1970", @"L6 NSDate.timeIntervalSince1970");
}

#pragma mark - fishhook（自实现，用于 C 函数）

struct bfp_rebinding { const char *name; void *replacement; void **replaced; };
static struct bfp_rebinding *g_reb_head = NULL;
static size_t g_reb_count = 0;
static int g_reb_inited = 0;

// ---- fishhook（与主插件同源的精简实现，用于替换 C 函数）----
// 关键点：必须按间接符号表（indirect symbol table）逐项改写，
// 而不是遍历 __LINKEDIT，否则在 chained fixups 的二进制上完全不生效。

struct bfp_rebindings_entry {
    struct bfp_rebinding *rebindings;
    size_t nel;
    struct bfp_rebindings_entry *next;
};
static struct bfp_rebindings_entry *g_head = NULL;

static void bfp_rebind_image(struct bfp_rebinding *rebindings, size_t nel,
                             const struct mach_header *header, intptr_t slide) {
    if (!rebindings || !nel) return;
    if (header->magic != MH_MAGIC_64) return;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)header;

    // 先找到 __LINKEDIT 里的 symtab / strtab / indirect symtab
    struct symtab_command *symtab = NULL;
    struct dysymtab_command *dysym = NULL;
    const struct segment_command_64 *linkedit = NULL;
    intptr_t cur = (intptr_t)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cur;
        if (lc->cmd == LC_SYMTAB) symtab = (struct symtab_command *)lc;
        else if (lc->cmd == LC_DYSYMTAB) dysym = (struct dysymtab_command *)lc;
        else if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sg = (struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__LINKEDIT") == 0) linkedit = sg;
        }
        cur += lc->cmdsize;
    }
    if (!symtab || !dysym || !linkedit) return;

    intptr_t slide_bias = slide - (intptr_t)linkedit->vmaddr;
    nlist_64 *syms = (nlist_64 *)(symtab->symoff + slide_bias);
    char *strs = (char *)(symtab->stroff + slide_bias);
    uint32_t *indirect = (uint32_t *)(dysym->indirectsymoff + slide_bias);

    // 遍历所有段的所有节，找间接符号指针节
    cur = (intptr_t)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sg = (struct segment_command_64 *)lc;
            struct section_64 *sec = (struct section_64 *)((intptr_t)sg + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < sg->nsects; j++, sec++) {
                uint32_t type = sec->flags & SECTION_TYPE;
                if (type != S_NON_LAZY_SYMBOL_POINTERS &&
                    type != S_LAZY_SYMBOL_POINTERS &&
                    type != S_SYMBOL_STUBS) continue;
                if (!(sec->offset && sec->size)) continue;
                uint32_t stride = (type == S_SYMBOL_STUBS) ? sec->reserved2 : sizeof(void *);
                if (stride == 0) continue;
                uint32_t count = (uint32_t)(sec->size / stride);
                intptr_t sec_base = (intptr_t)(sec->offset + slide_bias);
                for (uint32_t k = 0; k < count; k++) {
                    uint32_t symidx = indirect[sec->reserved1 + k];
                    if (symidx == INDIRECT_SYMBOL_LOCAL || symidx == INDIRECT_SYMBOL_ABS) continue;
                    if (symidx >= symtab->nsyms) continue;
                    char *name = strs + syms[symidx].n_un.n_strx;
                    if (!name || name[0] != '_') continue;
                    for (size_t r = 0; r < nel; r++) {
                        const char *target = rebindings[r].name;
                        if (!target || strcmp(name + 1, target) != 0) continue;
                        void **slot = (void **)(sec_base + k * stride);
                        // 保存原实现
                        if (*slot && *(rebindings[r].replaced) == NULL) {
                            *(rebindings[r].replaced) = *slot;
                        }
                        // 已替换过就不再重复（避免与自己比较）
                        if (*slot == rebindings[r].replacement) continue;
                        // 改页权限后写入
                        vm_address_t page = (vm_address_t)slot & ~(vm_page_size - 1);
                        vm_protect(mach_task_self(), page, vm_page_size, false,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        *slot = rebindings[r].replacement;
                        vm_protect(mach_task_self(), page, vm_page_size, false,
                                   VM_PROT_READ | VM_PROT_EXECUTE);
                    }
                }
            }
        }
        cur += lc->cmdsize;
    }
}

static void bfp_rebind_cb(const struct mach_header *mh, intptr_t slide) {
    for (struct bfp_rebindings_entry *e = g_head; e; e = e->next) {
        bfp_rebind_image(e->rebindings, e->nel, mh, slide);
    }
}

static int bfp_rebind_symbols(struct bfp_rebinding rebindings[], size_t nel) {
    struct bfp_rebindings_entry *e = malloc(sizeof(struct bfp_rebindings_entry));
    if (!e) return -1;
    e->rebindings = rebindings;
    e->nel = nel;
    e->next = g_head;
    g_head = e;
    if (!g_reb_inited) {
        g_reb_inited = 1;
        _dyld_register_func_for_add_image(bfp_rebind_cb);
    } else {
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            bfp_rebind_image(rebindings, nel, _dyld_get_image_header(i),
                             _dyld_get_image_vmaddr_slide(i));
        }
    }
    return 0;
}

static void bfp_install_c_hooks(void) {
    struct bfp_rebinding rb[] = {
        {"stat", (void *)bfp_my_stat, (void **)&bfp_orig_stat},
        {"lstat", (void *)bfp_my_lstat, (void **)&bfp_orig_lstat},
        {"access", (void *)bfp_my_access, (void **)&bfp_orig_access},
        {"fopen", (void *)bfp_my_fopen, (void **)&bfp_orig_fopen},
        {"opendir", (void *)bfp_my_opendir, (void **)&bfp_orig_opendir},
        {"sysctlbyname", (void *)bfp_my_sysctlbyname, (void **)&bfp_orig_sysctlbyname},
        {"uname", (void *)bfp_my_uname, (void **)&bfp_orig_uname},
        {"getifaddrs", (void *)bfp_my_getifaddrs, (void **)&bfp_orig_getifaddrs},
        {"CNCopyCurrentNetworkInfo", (void *)bfp_my_CNCopyCurrentNetworkInfo, (void **)&bfp_orig_CNCopyCurrentNetworkInfo},
        {"CFNetworkCopySystemProxySettings", (void *)bfp_my_CFNetworkCopySystemProxySettings, (void **)&bfp_orig_CFNetworkCopySystemProxySettings},
        {"_dyld_image_count", (void *)bfp_my_dyld_image_count, (void **)&bfp_orig_dyld_image_count},
        {"_dyld_get_image_name", (void *)bfp_my_dyld_get_image_name, (void **)&bfp_orig_dyld_get_image_name},
        {"CFAbsoluteTimeGetCurrent", (void *)bfp_my_CFAbsoluteTimeGetCurrent, (void **)&bfp_orig_CFAbsoluteTimeGetCurrent},
        {"time", (void *)bfp_my_time, (void **)&bfp_orig_time},
        {"gettimeofday", (void *)bfp_my_gettimeofday, (void **)&bfp_orig_gettimeofday},
    };
    bfp_rebind_symbols(rb, sizeof(rb) / sizeof(rb[0]));
}

#pragma mark - 报告生成

static NSString *bfp_report(void) {
    bfp_init();
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"BDSFullProbe %@\n", BFPVersion];
    [o appendFormat:@"capturedAt=%@\n", [NSDate date]];
    [o appendFormat:@"bundleId=%@\n", NSBundle.mainBundle.bundleIdentifier ?: @"?"];
    [o appendFormat:@"进程=%@\n", NSProcessInfo.processInfo.processName];
    [o appendFormat:@"记录总条数=%lu  持续=%.1f 秒\n", (unsigned long)g_totalRecords,
                    CFAbsoluteTimeGetCurrent() - g_startTime];

    [o appendString:@"\n--- 本机原始值（探针自己读的）---\n"];
    [o appendFormat:@"UIDevice.systemVersion=%@\n", UIDevice.currentDevice.systemVersion];
    [o appendFormat:@"UIDevice.model=%@\n", UIDevice.currentDevice.model];
    [o appendFormat:@"UIDevice.name=%@\n", UIDevice.currentDevice.name];
    [o appendFormat:@"NSProcessInfo.hostName=%@\n", NSProcessInfo.processInfo.hostName];
    struct utsname u; uname(&u);
    [o appendFormat:@"uname.machine=%s\n", u.machine];
    [o appendFormat:@"locale=%@\n", NSLocale.currentLocale.localeIdentifier];
    [o appendFormat:@"timeZone=%@\n", NSTimeZone.localTimeZone.name];
    [o appendFormat:@"现在=%@\n", [NSDate date]];

    [g_lock lock];
    NSArray *keys = [[g_rec allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *L[7];
    for (int i = 0; i < 7; i++) L[i] = [NSMutableArray array];
    for (NSString *k in keys) {
        if (![k hasPrefix:@"L"]) continue;
        int idx = [[k substringWithRange:NSMakeRange(1, 1)] intValue];
        if (idx >= 1 && idx <= 6) [L[idx] addObject:k];
    }
    NSArray *titles = @[@"", @"L1 标识符", @"L2 硬件与系统", @"L3 网络",
                        @"L4 地区 / 时区 / 越狱路径", @"L5 动态库枚举（注入检测）", @"L6 时间"];
    NSMutableDictionary *snap = [g_rec copy];
    NSArray *jbSnap = [g_jbPaths copy];
    NSUInteger imgCount = g_images.count;
    [g_lock unlock];

    for (int i = 1; i <= 6; i++) {
        [o appendFormat:@"\n\n========== %@ ==========\n", titles[i]];
        if (i == 4 && jbSnap.count) {
            [o appendFormat:@"\n[百度查过的路径]  共 %lu 条（⚠️ = 命中越狱特征）\n", (unsigned long)jbSnap.count];
            NSArray *sorted = [jbSnap sortedArrayUsingSelector:@selector(compare:)];
            NSUInteger shown = 0;
            for (NSString *p in sorted) {
                if (![p hasPrefix:@"⚠️"] && shown > 60) continue;   // 普通路径只列 60 条
                [o appendFormat:@"  %@\n", p];
                shown++;
                if (shown > 200) { [o appendString:@"  …(更多已省略)\n"]; break; }
            }
        }
        if (i == 5 && imgCount) {
            [o appendFormat:@"\n[当前进程加载的动态库]  共 %lu 个（找找有没有我们注入的）\n", (unsigned long)imgCount];
            [o appendString:@"  （完整清单见 L5 _dyld_get_image_name 的采样值）\n"];
        }
        if (!L[i].count) {
            [o appendString:@"  (本项目本次运行未被调用)\n"];
            continue;
        }
        for (NSString *k in L[i]) {
            NSDictionary *e = snap[k];
            [o appendFormat:@"\n%@\n", k];
            [o appendFormat:@"    次数: %@   首次: %.1fs\n", e[@"n"], [e[@"first"] doubleValue]];
            for (NSString *v in e[@"samples"]) {
                [o appendFormat:@"    值: %@\n", v];
            }
        }
    }
    return o;
}

#pragma mark - 悬浮按钮 + 面板

static UIWindow *g_win;
static NSString *g_reportText;

@interface UIButton (BFP)
- (void)bfp_tap;
@end
@implementation UIButton (BFP)
- (void)bfp_tap { bfp_show_panel(); }
@end

static void bfp_show_panel(void) {
    UIViewController *top = UIApplication.sharedApplication.keyWindow.rootViewController;
    while (top.presentedViewController) top = top.presentedViewController;
    if (!top) return;
    if ([top isKindOfClass:UIAlertController.class]) return;
    g_reportText = bfp_report();
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"BDS 全方位探针报告"
                                                              message:[g_reportText substringToIndex:MIN((NSUInteger)3000, g_reportText.length)]
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"复制全部" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        (void)x;
        UIPasteboard.generalPasteboard.string = g_reportText;
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"写文件" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        (void)x;
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *p = [docs stringByAppendingPathComponent:
                       [NSString stringWithFormat:@"bds_fullprobe_%.0f.txt", [NSDate date].timeIntervalSince1970]];
        [g_reportText writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
        UIAlertController *b = [UIAlertController alertControllerWithTitle:@"已写入" message:p preferredStyle:UIAlertControllerStyleAlert];
        [b addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
        [top presentViewController:b animated:YES completion:nil];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    [top presentViewController:a animated:YES completion:nil];
}

static void bfp_build_button(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIWindow *w = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        if (!w) return;
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(12, 120, 74, 74);
        b.backgroundColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.95 alpha:0.92];
        b.layer.cornerRadius = 37;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:13];
        b.titleLabel.numberOfLines = 3;
        b.titleLabel.textAlignment = NSTextAlignmentCenter;
        [b setTitle:@"全方位\n探针\n点这里" forState:UIControlStateNormal];
        [b addTarget:b action:@selector(bfp_tap) forControlEvents:UIControlEventTouchUpInside];
        [w addSubview:b];
        g_win = w;
    });
}

__attribute__((constructor))
static void bfp_start(void) {
    bfp_init();
    bfp_install_c_hooks();
    bfp_install_L1();
    bfp_install_L2();
    bfp_install_L4();
    bfp_install_L6();
    // L3/L5 的 C 层 hook 需要 fishhook，探针这里先用 ObjC 可覆盖的部分 + dlsym 记录
    bfp_build_button();
}
