//
//  BDSpoofer.m
//  百度极速版设备信息虚拟化插件（基础版）
//  注入方式：TrollFools
//  不依赖 Substrate/ElleKit，使用 Objective-C runtime method_setImplementation
//
//  基础版只 hook 低风险的系统 API，不拦截 Keychain/Cookie/User-Agent/App Group
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <WebKit/WebKit.h>
#import <errno.h>

#pragma mark - 配置

static NSDictionary *g_config = nil;

static NSString *configPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"bdspoofer_config.plist"];
}

static NSString *cfgStr(NSString *key, NSString *def) {
    NSString *v = g_config[key];
    return (v && [v isKindOfClass:[NSString class]]) ? v : def;
}
static BOOL cfgBool(NSString *key, BOOL def) {
    NSNumber *v = g_config[key];
    return v ? [v boolValue] : def;
}
static NSInteger cfgInt(NSString *key, NSInteger def) {
    NSNumber *v = g_config[key];
    return v ? [v integerValue] : def;
}

static void loadConfig() {
    NSString *p1 = configPath();
    NSString *p2 = [[NSBundle mainBundle] pathForResource:@"bdspoofer_config" ofType:@"plist"];
    NSString *path = [[NSFileManager defaultManager] fileExistsAtPath:p1] ? p1 : p2;
    if (path) g_config = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!g_config) g_config = @{};
}

static BOOL saveConfigValues(NSDictionary *values) {
    if (!values.count) return NO;
    NSMutableDictionary *next = [g_config mutableCopy] ?: [NSMutableDictionary dictionary];
    [next addEntriesFromDictionary:values];
    BOOL saved = [next writeToFile:configPath() atomically:YES];
    if (saved) g_config = [next copy];
    return saved;
}

#pragma mark - Hook 工具

static void hookInst(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        if (oldImp) *oldImp = method_getImplementation(m);
        method_setImplementation(m, newImp);
    }
}

static void hookClass(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    if (!cls) return;
    Method m = class_getClassMethod(cls, sel);
    if (m) {
        if (oldImp) *oldImp = method_getImplementation(m);
        method_setImplementation(m, newImp);
    }
}

#pragma mark - UIDevice Hook

static IMP orig_systemVersion = NULL;
static NSString *new_systemVersion(id self, SEL _cmd) {
    return cfgStr(@"systemVersion", @"17.5.1");
}

static IMP orig_model = NULL;
static NSString *new_model(id self, SEL _cmd) {
    // UIDevice.model 返回设备家族（iPhone/iPad），不是 iPhone15,2 这类硬件标识。
    return cfgStr(@"deviceModel", @"iPhone");
}

static IMP orig_localizedModel = NULL;
static NSString *new_localizedModel(id self, SEL _cmd) {
    return cfgStr(@"marketingModel", @"iPhone");
}

static IMP orig_name = NULL;
static NSString *new_name(id self, SEL _cmd) {
    return cfgStr(@"deviceName", @"iPhone");
}

static IMP orig_systemName = NULL;
static NSString *new_systemName(id self, SEL _cmd) {
    return @"iOS";
}

static IMP orig_identifierForVendor = NULL;
static NSUUID *new_identifierForVendor(id self, SEL _cmd) {
    NSString *uuid = cfgStr(@"idfv", @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
    NSUUID *value = [[NSUUID alloc] initWithUUIDString:uuid];
    if (value) return value;
    if (orig_identifierForVendor) {
        return ((NSUUID *(*)(id, SEL))orig_identifierForVendor)(self, _cmd);
    }
    return nil;
}

#pragma mark - ASIdentifierManager Hook

static IMP orig_advertisingIdentifier = NULL;
static NSUUID *new_advertisingIdentifier(id self, SEL _cmd) {
    NSString *uuid = cfgStr(@"idfa", @"FEDCBA98-7654-3210-FEDC-BA9876543210");
    NSUUID *value = [[NSUUID alloc] initWithUUIDString:uuid];
    if (value) return value;
    if (orig_advertisingIdentifier) {
        return ((NSUUID *(*)(id, SEL))orig_advertisingIdentifier)(self, _cmd);
    }
    return nil;
}

static IMP orig_isAdvertisingTrackingEnabled = NULL;
static BOOL new_isAdvertisingTrackingEnabled(id self, SEL _cmd) {
    return NO;
}

#pragma mark - ATTrackingManager Hook (iOS 14+)

static IMP orig_trackingAuthorizationStatus = NULL;
static NSInteger new_trackingAuthorizationStatus(id self, SEL _cmd) {
    return 2; // denied
}

#pragma mark - NSProcessInfo Hook

static IMP orig_operatingSystemVersionString = NULL;
static NSString *new_operatingSystemVersionString(id self, SEL _cmd) {
    NSString *v = cfgStr(@"systemVersion", @"17.5.1");
    NSString *b = cfgStr(@"systemBuild", @"21F79");
    return [NSString stringWithFormat:@"Version %@ (Build %@)", v, b];
}

static IMP orig_operatingSystemVersion = NULL;
static NSOperatingSystemVersion new_operatingSystemVersion(id self, SEL _cmd) {
    NSOperatingSystemVersion v = {17, 5, 1};
    NSString *s = cfgStr(@"systemVersion", @"17.5.1");
    NSArray *p = [s componentsSeparatedByString:@"."];
    if (p.count >= 1) v.majorVersion = [p[0] integerValue];
    if (p.count >= 2) v.minorVersion = [p[1] integerValue];
    if (p.count >= 3) v.patchVersion = [p[2] integerValue];
    return v;
}

static IMP orig_hostName = NULL;
static NSString *new_hostName(id self, SEL _cmd) {
    return cfgStr(@"kernHostname", @"iPhone");
}

static IMP orig_physicalMemory = NULL;
static unsigned long long new_physicalMemory(id self, SEL _cmd) {
    return (unsigned long long)cfgInt(@"memorySize", 6144) * 1024 * 1024;
}

#pragma mark - NSLocale Hook

static IMP orig_localeIdentifier = NULL;
static NSString *new_localeIdentifier(id self, SEL _cmd) {
    return cfgStr(@"localeIdentifier", @"zh_CN");
}

#pragma mark - CTTelephonyNetworkInfo / CTCarrier Hook

static IMP orig_subscriberCellularProvider = NULL;
static CTCarrier *new_subscriberCellularProvider(id self, SEL _cmd) {
    CTCarrier *fake = [[CTCarrier alloc] init];
    return fake;
}

static IMP orig_serviceSubscriberCellularProviders = NULL;
static NSDictionary *new_serviceSubscriberCellularProviders(id self, SEL _cmd) {
    CTCarrier *fake = [[CTCarrier alloc] init];
    return @{@"0000000100000001": fake};
}

static IMP orig_carrierName = NULL;
static NSString *new_carrierName(id self, SEL _cmd) {
    return cfgStr(@"carrierName", @"中国移动");
}

static IMP orig_mobileCountryCode = NULL;
static NSString *new_mobileCountryCode(id self, SEL _cmd) {
    return cfgStr(@"mcc", @"460");
}

static IMP orig_mobileNetworkCode = NULL;
static NSString *new_mobileNetworkCode(id self, SEL _cmd) {
    return cfgStr(@"mnc", @"00");
}

static IMP orig_isoCountryCode = NULL;
static NSString *new_isoCountryCode(id self, SEL _cmd) {
    return cfgStr(@"isoCountryCode", @"cn");
}

static IMP orig_allowsVOIP = NULL;
static BOOL new_allowsVOIP(id self, SEL _cmd) {
    return YES;
}

#pragma mark - UIScreen Hook

static IMP orig_bounds = NULL;
static CGRect new_bounds(id self, SEL _cmd) {
    CGFloat w = cfgInt(@"screenWidth", 393);
    CGFloat h = cfgInt(@"screenHeight", 852);
    return CGRectMake(0, 0, w, h);
}

static IMP orig_nativeBounds = NULL;
static CGRect new_nativeBounds(id self, SEL _cmd) {
    CGFloat scale = (CGFloat)cfgInt(@"screenScale", 3);
    CGFloat w = cfgInt(@"screenWidth", 393) * scale;
    CGFloat h = cfgInt(@"screenHeight", 852) * scale;
    return CGRectMake(0, 0, w, h);
}

static IMP orig_scale = NULL;
static CGFloat new_scale(id self, SEL _cmd) {
    return (CGFloat)cfgInt(@"screenScale", 3);
}

#pragma mark - NSFileManager Hook（磁盘大小）

static IMP orig_attributesOfFileSystemForPath = NULL;
static NSDictionary *new_attributesOfFileSystemForPath(id self, SEL _cmd, id path, NSError **error) {
    typedef NSDictionary *(*FileSystemAttributesIMP)(id, SEL, NSString *, NSError **);
    NSDictionary *orig = orig_attributesOfFileSystemForPath
        ? ((FileSystemAttributesIMP)orig_attributesOfFileSystemForPath)(self, _cmd, path, error)
        : nil;
    if (!orig) return orig;
    NSMutableDictionary *m = [orig mutableCopy];
    long long diskSize = cfgInt(@"diskSize", 256) * 1024LL * 1024LL * 1024LL;
    m[NSFileSystemSize] = @(diskSize);
    m[NSFileSystemFreeSize] = @(diskSize / 2);
    return m;
}

#pragma mark - 百度 SDK Hook

// 百度自研设备标识 SDK：CuidSDK / UTDIDModule / MobStat / DeviceIdentifierFetcher
// 安全策略：
//   1. 只 hook 同步无参数方法（argc==2），返回类型必须是对象（@）
//   2. 不 hook 带 block 回调的异步方法（避免改变回调线程/时序）
//   3. hook 函数中先调用原始 IMP，只有返回值确实是 NSString 时才替换
//   4. 保存原始 IMP（类方法/实例方法分别保存），支持与其他插件串联
//   5. 用 _dyld_register_func_for_add_image 支持延迟加载的 framework
//   6. 所有集合访问用 NSRecursiveLock 保护，防止 dyld 回调与 UI 自检并发

static NSRecursiveLock *g_baiduLock = nil;
static NSMutableDictionary<NSString *, NSValue *> *g_baiduOrigImps = nil;
static NSMutableSet<NSString *> *g_baiduHookedKeys = nil;

static NSString *bds_cuid_value(void) {
    return cfgStr(@"cuid", @"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6");
}
static NSString *bds_utdid_value(void) {
    return cfgStr(@"utdid", @"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
}
static NSString *bds_deviceID_value(void) {
    return cfgStr(@"deviceID", @"A1B2C3D4-E5F6-A7B8-C9D0-E1F2A3B4C5D6");
}

static NSString *bds_fake_value_for_cmd(SEL _cmd) {
    NSString *selName = NSStringFromSelector(_cmd).lowercaseString;
    if ([selName containsString:@"utdid"]) return bds_utdid_value();
    if ([selName containsString:@"cuid"]) return bds_cuid_value();
    return bds_deviceID_value();
}

// 通用 IMP：先调用原始实现，确认返回 NSString 后再替换
static NSString *new_baidu_string_sync(id self, SEL _cmd) {
    BOOL isClassMethod = object_isClass(self);
    NSString *className = isClassMethod ? NSStringFromClass(self) : NSStringFromClass([self class]);
    NSString *impKey = [NSString stringWithFormat:@"%@.%@.%@",
                        className, NSStringFromSelector(_cmd),
                        isClassMethod ? @"C" : @"I"];

    NSValue *origValue = nil;
    [g_baiduLock lock];
    origValue = g_baiduOrigImps[impKey];
    [g_baiduLock unlock];

    // 功能关闭时直接透传原始实现
    if (!cfgBool(@"spoofBaiduSDK", NO)) {
        if (origValue) {
            IMP orig = [origValue pointerValue];
            return ((NSString *(*)(id, SEL))orig)(self, _cmd);
        }
        return nil;
    }

    // 调用原始 IMP
    if (origValue) {
        IMP orig = [origValue pointerValue];
        id result = ((id (*)(id, SEL))orig)(self, _cmd);
        // 只有返回值确实是 NSString 时才替换；其他类型（NSDictionary 等）原样返回
        if ([result isKindOfClass:[NSString class]]) {
            return bds_fake_value_for_cmd(_cmd);
        }
        return result;
    }
    return bds_fake_value_for_cmd(_cmd);
}

// 检查方法签名是否安全：无参数、返回对象类型
static BOOL bds_isSafeSyncMethod(Method m) {
    if (!m) return NO;
    if (method_getNumberOfArguments(m) != 2) return NO;
    char retType[16];
    method_getReturnType(m, retType, sizeof(retType));
    return retType[0] == '@';
}

static void bds_tryHookMethod(Class cls, SEL sel, BOOL isClassMethod) {
    if (!cls) return;
    NSString *className = NSStringFromClass(cls);
    NSString *key = [NSString stringWithFormat:@"%@.%@.%s",
                     className, NSStringFromSelector(sel), isClassMethod ? "C" : "I"];
    NSString *impKey = [NSString stringWithFormat:@"%@.%@.%@",
                        className, NSStringFromSelector(sel),
                        isClassMethod ? @"C" : @"I"];

    [g_baiduLock lock];

    // 原子检查+安装，防止 dyld 回调与扫描线程重复 hook
    if ([g_baiduHookedKeys containsObject:key]) {
        [g_baiduLock unlock];
        return;
    }

    Method m = isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m || !bds_isSafeSyncMethod(m)) {
        [g_baiduLock unlock];
        return;
    }

    // 在当前类（类方法则在元类）上替换或添加方法，不修改父类实现
    Class targetCls = isClassMethod ? object_getClass(cls) : cls;
    IMP oldImp = class_replaceMethod(targetCls, sel, (IMP)new_baidu_string_sync,
                                     method_getTypeEncoding(m));
    if (!oldImp) {
        // 方法定义在父类：class_replaceMethod 已在当前类添加覆盖，保存父类原始 IMP
        oldImp = method_getImplementation(m);
    }

    [g_baiduOrigImps setObject:[NSValue valueWithPointer:oldImp] forKey:impKey];
    [g_baiduHookedKeys addObject:key];
    [g_baiduLock unlock];
}

static void bds_tryHookClass(NSString *className, NSArray<NSString *> *selectors) {
    Class cls = objc_getClass(className.UTF8String);
    if (!cls) return;
    for (NSString *selName in selectors) {
        SEL sel = NSSelectorFromString(selName);
        bds_tryHookMethod(cls, sel, YES);
        bds_tryHookMethod(cls, sel, NO);
    }
}

static NSArray<NSDictionary *> *bds_baiduTargets(void) {
    static NSArray *targets;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        targets = @[
            @{@"class": @"CuidSDK", @"selectors": @[@"cuid", @"getCUID", @"getCuid", @"CUID"]},
            @{@"class": @"CuidSDK18BBADevAccountPatch", @"selectors": @[@"cuid", @"getCUID", @"getCuid"]},
            @{@"class": @"UTDIDModule", @"selectors": @[@"utdid", @"getUTDID", @"UTDID"]},
            @{@"class": @"MobStat", @"selectors": @[@"deviceId", @"getDeviceId", @"deviceID", @"getDeviceID",
                                                     @"getDeviceIdentification", @"deviceIdentification"]},
            @{@"class": @"DeviceIdentifierFetcher", @"selectors": @[@"deviceIdentifier", @"getDeviceIdentifier",
                                                                     @"sharedIdentifier", @"fetchIdentifier"]}
        ];
    });
    return targets;
}

static void bds_scanBaiduSDKClasses(void) {
    if (!g_baiduLock) {
        g_baiduLock = [[NSRecursiveLock alloc] init];
        g_baiduOrigImps = [NSMutableDictionary dictionary];
        g_baiduHookedKeys = [NSMutableSet set];
    }
    for (NSDictionary *target in bds_baiduTargets()) {
        bds_tryHookClass(target[@"class"], target[@"selectors"]);
    }
}

// dyld 回调必须是普通 C 函数，不能是 block
static void bds_dyld_add_image_cb(const struct mach_header *mh, intptr_t vmaddr_slide) {
    (void)mh; (void)vmaddr_slide;
    bds_scanBaiduSDKClasses();
}

static void installBaiduSDKHooks(void) {
    bds_scanBaiduSDKClasses();
    _dyld_register_func_for_add_image(bds_dyld_add_image_cb);
}

#pragma mark - sysctlbyname Hook (DYLD_INTERPOSE)

static int (*bds_orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);

static int bds_my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                                void *newp, size_t newlen) {
    if (!bds_orig_sysctlbyname) {
        bds_orig_sysctlbyname = (int (*)(const char *, void *, size_t *, void *, size_t))dlsym(RTLD_NEXT, "sysctlbyname");
    }
    if (!bds_orig_sysctlbyname) return -1;

    // 异常参数或写入操作直接透传
    if (!name || (oldp && !oldlenp) || newp) {
        return bds_orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    // 配置未加载或未开启时直接透传
    if (!g_config || !cfgBool(@"spoofSysctl", NO)) {
        return bds_orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    // 判断是否是要 hook 的 key
    const char *fake = NULL;
    if (strcmp(name, "hw.machine") == 0) {
        fake = [cfgStr(@"hwMachine", @"iPhone15,2") UTF8String];
    } else if (strcmp(name, "hw.model") == 0) {
        fake = [cfgStr(@"hwModel", @"D54AP") UTF8String];
    } else if (strcmp(name, "kern.osversion") == 0) {
        fake = [cfgStr(@"kernOSVersion", @"21F79") UTF8String];
    } else if (strcmp(name, "kern.hostname") == 0) {
        fake = [cfgStr(@"kernHostname", @"iPhone") UTF8String];
    }

    // 非目标 key 直接透传
    if (!fake) {
        return bds_orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    size_t fakeLen = strlen(fake) + 1; // 包含结尾 \0

    // oldp=NULL：调用方在查询所需长度
    if (oldp == NULL) {
        if (oldlenp) *oldlenp = fakeLen;
        return 0;
    }

    // oldp 不为 NULL：缓冲区太小
    if (*oldlenp < fakeLen) {
        *oldlenp = fakeLen;
        return ENOMEM;
    }

    // 写入伪造值并更新实际长度
    memcpy(oldp, fake, fakeLen);
    *oldlenp = fakeLen;
    return 0;
}

__attribute__((used)) static struct {
    const void *replacement;
    const void *replacee;
} bds_interpose_sysctlbyname __attribute__((section("__DATA,__interpose"))) = {
    (const void *)bds_my_sysctlbyname,
    (const void *)sysctlbyname
};

#pragma mark - User-Agent Hook

static IMP orig_wk_customUserAgent = NULL;
static NSString *new_wk_customUserAgent(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    NSString *custom = cfgStr(@"userAgent", @"");
    if (custom.length > 0) return custom;
    // 自动生成与配置一致的 UA
    NSString *v = [cfgStr(@"systemVersion", @"17.5.1") stringByReplacingOccurrencesOfString:@"." withString:@"_"];
    return [NSString stringWithFormat:
        @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", v];
}

static IMP orig_nsmurl_setValue = NULL;
static void new_nsmurl_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if (field && value &&
        [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame &&
        cfgBool(@"spoofUserAgent", NO)) {
        NSString *custom = cfgStr(@"userAgent", @"");
        value = custom.length > 0 ? custom : nil;
        if (!value) {
            NSString *v = [cfgStr(@"systemVersion", @"17.5.1") stringByReplacingOccurrencesOfString:@"." withString:@"_"];
            value = [NSString stringWithFormat:
                @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", v];
        }
    }
    typedef void (*SetValueIMP)(id, SEL, NSString *, NSString *);
    if (orig_nsmurl_setValue) ((SetValueIMP)orig_nsmurl_setValue)(self, _cmd, value, field);
}

static IMP orig_nsmurl_addValue = NULL;
static void new_nsmurl_addValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if (field && value &&
        [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame &&
        cfgBool(@"spoofUserAgent", NO)) {
        NSString *custom = cfgStr(@"userAgent", @"");
        value = custom.length > 0 ? custom : nil;
        if (!value) {
            NSString *v = [cfgStr(@"systemVersion", @"17.5.1") stringByReplacingOccurrencesOfString:@"." withString:@"_"];
            value = [NSString stringWithFormat:
                @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", v];
        }
    }
    typedef void (*AddValueIMP)(id, SEL, NSString *, NSString *);
    if (orig_nsmurl_addValue) ((AddValueIMP)orig_nsmurl_addValue)(self, _cmd, value, field);
}

#pragma mark - 越狱检测绕过

static NSArray<NSString *> *bds_jailbreakPaths(void) {
    static NSArray *paths;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        paths = @[
            @"/Applications/Cydia.app",
            @"/Applications/Sileo.app",
            @"/Applications/Zebra.app",
            @"/Applications/Installer.app",
            @"/Library/MobileSubstrate",
            @"/Library/MobileSubstrate/DynamicLibraries",
            @"/usr/sbin/sshd",
            @"/usr/libexec/sftp-server",
            @"/usr/libexec/ssh-keysign",
            @"/etc/apt",
            @"/etc/ssh/sshd_config",
            @"/private/var/lib/apt",
            @"/private/var/lib/cydia",
            @"/private/var/stash",
            @"/private/var/tmp/cydia.log",
            @"/usr/bin/sshd",
            @"/usr/bin/cycript",
            @"/usr/lib/libsubstrate.dylib",
            @"/usr/lib/libhooker.dylib",
            @"/usr/lib/libellekit.dylib",
            @"/usr/lib/TweakInject",
            @"/bin/bash",
            @"/bin/sh",
            @"/usr/bin/ssh",
            @"/var/jb",
            @"/var/jb/Library",
            @"/var/jb/basebin",
            @"/var/jb/usr/lib/TweakInject",
            @"/.bootstrapped_electra",
            @"/.cydia_no_stash",
            @"/.installed_unc0ver",
            @"/jb",
            @"/var/LIY",
            @"/var/Memory.me",
            @"/var/checkra1n.dmg"
        ];
    });
    return paths;
}

static NSArray<NSString *> *bds_jailbreakSchemes(void) {
    static NSArray *schemes;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        schemes = @[@"cydia", @"sileo", @"zebra", @"installer", @"filza", @"undecimus", @"activator"];
    });
    return schemes;
}

static BOOL bds_isJailbreakPath(NSString *path) {
    if (!path) return NO;
    for (NSString *p in bds_jailbreakPaths()) {
        // 精确匹配或路径后接 "/"，避免 /bin/sh 误伤 /bin/shutdown 等
        if ([path isEqualToString:p]) return YES;
        if ([path hasPrefix:[p stringByAppendingString:@"/"]]) return YES;
    }
    return NO;
}

static IMP orig_fileExistsAtPath = NULL;
static BOOL new_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (cfgBool(@"bypassJailbreakDetect", NO) && bds_isJailbreakPath(path)) return NO;
    typedef BOOL (*ExistsIMP)(id, SEL, NSString *);
    if (orig_fileExistsAtPath) return ((ExistsIMP)orig_fileExistsAtPath)(self, _cmd, path);
    return NO;
}

static IMP orig_fileExistsAtPathIsDir = NULL;
static BOOL new_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDirectory) {
    if (cfgBool(@"bypassJailbreakDetect", NO) && bds_isJailbreakPath(path)) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    typedef BOOL (*ExistsDirIMP)(id, SEL, NSString *, BOOL *);
    if (orig_fileExistsAtPathIsDir) return ((ExistsDirIMP)orig_fileExistsAtPathIsDir)(self, _cmd, path, isDirectory);
    return NO;
}

static IMP orig_canOpenURL = NULL;
static BOOL new_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (cfgBool(@"bypassJailbreakDetect", NO)) {
        NSString *scheme = url.scheme.lowercaseString;
        if (scheme && [bds_jailbreakSchemes() containsObject:scheme]) return NO;
    }
    typedef BOOL (*CanOpenIMP)(id, SEL, NSURL *);
    if (orig_canOpenURL) return ((CanOpenIMP)orig_canOpenURL)(self, _cmd, url);
    return NO;
}

#pragma mark - 悬浮配置入口

static const void *BDSButtonKey = &BDSButtonKey;

@interface BDSUIController : NSObject
+ (instancetype)shared;
- (void)attachButton;
- (void)openPanel;
- (void)editSystemVersion;
- (void)editDeviceName;
- (void)editIdentifiers;
- (void)showOptionalSwitches;
- (void)showOptionalEditors;
- (void)showAdvancedSwitches;
- (void)showAdvancedEditors;
- (void)editProcessHardware;
- (void)editLocaleCarrier;
- (void)editScreenStorage;
- (void)showSelfTest;
- (void)presentMessage:(NSString *)message title:(NSString *)title;
- (void)showRestartNotice:(BOOL)saved;
@end

static UIWindow *BDSMainWindow(void) {
    UIWindow *fallback = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] ||
            scene.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window.isKeyWindow) return window;
            if (!fallback && window.rootViewController && window.windowLevel == UIWindowLevelNormal) {
                fallback = window;
            }
        }
    }
    return fallback;
}

static UIViewController *BDSTopController(void) {
    UIViewController *controller = BDSMainWindow().rootViewController;
    while (controller) {
        if (controller.presentedViewController) {
            controller = controller.presentedViewController;
        } else if ([controller isKindOfClass:UINavigationController.class]) {
            controller = ((UINavigationController *)controller).visibleViewController;
        } else if ([controller isKindOfClass:UITabBarController.class]) {
            controller = ((UITabBarController *)controller).selectedViewController;
        } else {
            break;
        }
    }
    return controller;
}

static NSString *BDSOnOff(BOOL value) {
    return value ? @"开" : @"关";
}

static NSString *BDSConfigSummary(void) {
    NSString *container = NSHomeDirectory().lastPathComponent ?: @"unknown";
    if (container.length > 12) container = [container substringFromIndex:container.length - 12];
    return [NSString stringWithFormat:
        @"容器: %@\n状态: %@\niOS: %@ (%@)\n设备名称: %@\nIDFV: %@\nIDFA: %@\n\n保存后重启百度极速版生效",
        container,
        cfgBool(@"enabled", NO) ? @"已开启" : @"已关闭",
        cfgStr(@"systemVersion", @"17.5.1"),
        cfgStr(@"systemBuild", @"21F79"),
        cfgStr(@"deviceName", @"iPhone"),
        cfgStr(@"idfv", @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890"),
        cfgStr(@"idfa", @"FEDCBA98-7654-3210-FEDC-BA9876543210")];
}

@implementation BDSUIController

+ (instancetype)shared {
    static BDSUIController *controller;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ controller = [BDSUIController new]; });
    return controller;
}

- (void)attachButton {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = BDSMainWindow();
        if (!window) return;
        UIButton *button = objc_getAssociatedObject(window, BDSButtonKey);
        if (!button) {
            CGFloat size = 42.0;
            CGFloat x = MAX(4.0, CGRectGetWidth(window.bounds) - size - 4.0);
            CGFloat y = MAX(100.0, CGRectGetHeight(window.bounds) * 0.52);
            button = [UIButton buttonWithType:UIButtonTypeSystem];
            button.frame = CGRectMake(x, y, size, size);
            button.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin |
                                      UIViewAutoresizingFlexibleTopMargin |
                                      UIViewAutoresizingFlexibleBottomMargin;
            button.backgroundColor = [UIColor colorWithRed:0.05 green:0.48 blue:0.95 alpha:0.90];
            button.layer.cornerRadius = size / 2.0;
            button.layer.borderWidth = 1.0;
            button.layer.borderColor = UIColor.whiteColor.CGColor;
            button.accessibilityLabel = @"设备隐私配置";
            [button setTitle:@"隐" forState:UIControlStateNormal];
            [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            button.titleLabel.font = [UIFont boldSystemFontOfSize:17.0];
            [button addTarget:self action:@selector(buttonTapped:) forControlEvents:UIControlEventTouchUpInside];
            UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(buttonPanned:)];
            [button addGestureRecognizer:pan];
            [window addSubview:button];
            objc_setAssociatedObject(window, BDSButtonKey, button, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        [window bringSubviewToFront:button];
    });
}

- (void)buttonTapped:(UIButton *)button {
    (void)button;
    [self openPanel];
}

- (void)buttonPanned:(UIPanGestureRecognizer *)gesture {
    UIView *button = gesture.view;
    UIView *container = button.superview;
    if (!button || !container) return;
    CGPoint translation = [gesture translationInView:container];
    CGPoint center = CGPointMake(button.center.x + translation.x, button.center.y + translation.y);
    CGFloat half = CGRectGetWidth(button.bounds) / 2.0;
    center.x = MIN(MAX(center.x, half + 2.0), CGRectGetWidth(container.bounds) - half - 2.0);
    center.y = MIN(MAX(center.y, half + 44.0), CGRectGetHeight(container.bounds) - half - 20.0);
    button.center = center;
    [gesture setTranslation:CGPointZero inView:container];
}

- (void)presentMessage:(NSString *)message title:(NSString *)title {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *presenter = BDSTopController();
        if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleCancel handler:nil]];
        [presenter presentViewController:alert animated:YES completion:nil];
    });
}

- (void)showRestartNotice:(BOOL)saved {
    [self presentMessage:(saved ? @"配置已写入。请彻底关闭百度极速版后重新打开。" : @"配置写入失败，请检查 App Documents 目录权限。")
                    title:(saved ? @"保存成功" : @"保存失败")];
}

- (void)openPanel {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"百度设备隐私"
                                                                   message:BDSConfigSummary()
                                                            preferredStyle:UIAlertControllerStyleAlert];
    NSString *toggleTitle = cfgBool(@"enabled", NO) ? @"关闭基础功能" : @"开启基础功能";
    [alert addAction:[UIAlertAction actionWithTitle:toggleTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self showRestartNotice:saveConfigValues(@{@"enabled": @(!cfgBool(@"enabled", NO))})];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"修改系统版本" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self editSystemVersion];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"修改设备名称" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self editDeviceName];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"修改 IDFV / IDFA" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self editIdentifiers];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"可选功能开关" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showOptionalSwitches];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"编辑可选参数" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showOptionalEditors];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"高级功能开关" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showAdvancedSwitches];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"编辑高级参数" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showAdvancedEditors];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"公开 API 自检" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self showSelfTest];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"恢复安全关闭状态" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        (void)action;
        NSDictionary *safe = @{
            @"enabled": @NO,
            @"spoofProcessHardware": @NO,
            @"spoofLocale": @NO,
            @"spoofCarrier": @NO,
            @"spoofScreen": @NO,
            @"spoofStorage": @NO,
            @"spoofBaiduSDK": @NO,
            @"spoofSysctl": @NO,
            @"spoofUserAgent": @NO,
            @"bypassJailbreakDetect": @NO
        };
        [self showRestartNotice:saveConfigValues(safe)];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editSystemVersion {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"修改系统版本"
                                                                   message:@"版本和 Build 必须保持匹配；保存后重启生效。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"例如 17.5.1";
        field.text = cfgStr(@"systemVersion", @"17.5.1");
        field.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"例如 21F79";
        field.text = cfgStr(@"systemBuild", @"21F79");
        field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *version = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *build = [alert.textFields[1].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].uppercaseString;
        NSRange match = [version rangeOfString:@"^[0-9]+\\.[0-9]+(\\.[0-9]+)?$" options:NSRegularExpressionSearch];
        if (match.location == NSNotFound || !build.length || build.length > 16) {
            [self presentMessage:@"请输入有效版本号和 Build，例如 17.5.1 / 21F79。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"systemVersion": version, @"systemBuild": build})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editDeviceName {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"修改设备名称"
                                                                   message:@"UIDevice.model 固定保持为 iPhone。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"deviceName", @"iPhone");
        field.placeholder = @"1 到 32 个字符";
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *name = [alert.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (!name.length || name.length > 32) {
            [self presentMessage:@"设备名称必须为 1 到 32 个字符。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"deviceName": name})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editIdentifiers {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"修改标识符"
                                                                   message:@"只接受标准 UUID；插件不会自动随机生成。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"idfv", @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
        field.placeholder = @"IDFV";
        field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"idfa", @"FEDCBA98-7654-3210-FEDC-BA9876543210");
        field.placeholder = @"IDFA";
        field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *idfv = alert.textFields[0].text.uppercaseString;
        NSString *idfa = alert.textFields[1].text.uppercaseString;
        if (![[NSUUID alloc] initWithUUIDString:idfv] || ![[NSUUID alloc] initWithUUIDString:idfa]) {
            [self presentMessage:@"IDFV 和 IDFA 都必须是有效 UUID。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"idfv": idfv, @"idfa": idfa})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)showOptionalSwitches {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"可选功能"
                                                                   message:@"这些功能默认关闭，修改后重启生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"key": @"spoofAdvertisingIdentifiers", @"name": @"广告标识符"},
        @{@"key": @"spoofProcessHardware", @"name": @"主机名与内存"},
        @{@"key": @"spoofLocale", @"name": @"语言地区"},
        @{@"key": @"spoofCarrier", @"name": @"运营商"},
        @{@"key": @"spoofScreen", @"name": @"屏幕尺寸"},
        @{@"key": @"spoofStorage", @"name": @"磁盘容量"}
    ];
    for (NSDictionary *item in items) {
        NSString *key = item[@"key"];
        NSString *title = [NSString stringWithFormat:@"%@：%@", item[@"name"], BDSOnOff(cfgBool(key, NO))];
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            [self showRestartNotice:saveConfigValues(@{key: @(!cfgBool(key, NO))})];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showOptionalEditors {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"编辑可选参数"
                                                                   message:@"这里只修改本机公开 API 的测试值；对应开关开启并重启后生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"name": @"主机名与内存", @"selector": NSStringFromSelector(@selector(editProcessHardware))},
        @{@"name": @"语言地区与运营商", @"selector": NSStringFromSelector(@selector(editLocaleCarrier))},
        @{@"name": @"屏幕与磁盘", @"selector": NSStringFromSelector(@selector(editScreenStorage))}
    ];
    for (NSDictionary *item in items) {
        [sheet addAction:[UIAlertAction actionWithTitle:item[@"name"] style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            SEL selector = NSSelectorFromString(item[@"selector"]);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                if ([self respondsToSelector:selector]) {
                    ((void (*)(id, SEL))objc_msgSend)(self, selector);
                }
            });
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showAdvancedSwitches {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"高级功能"
                                                                   message:@"这些功能有一定风险，建议逐项开启测试；修改后重启生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"key": @"spoofBaiduSDK", @"name": @"百度 SDK 标识（CUID/UTDID/DeviceID）"},
        @{@"key": @"spoofSysctl", @"name": @"sysctlbyname（hw.machine 等）"},
        @{@"key": @"spoofUserAgent", @"name": @"User-Agent 替换"},
        @{@"key": @"bypassJailbreakDetect", @"name": @"越狱检测绕过"}
    ];
    for (NSDictionary *item in items) {
        NSString *key = item[@"key"];
        NSString *title = [NSString stringWithFormat:@"%@：%@", item[@"name"], BDSOnOff(cfgBool(key, NO))];
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            [self showRestartNotice:saveConfigValues(@{key: @(!cfgBool(key, NO))})];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showAdvancedEditors {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"编辑高级参数"
                                                                   message:@"修改百度 SDK 标识和硬件底层参数；对应开关开启并重启后生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"name": @"百度 CUID / UTDID / DeviceID", @"selector": NSStringFromSelector(@selector(editBaiduIdentifiers))},
        @{@"name": @"sysctl 硬件参数", @"selector": NSStringFromSelector(@selector(editSysctlParams))},
        @{@"name": @"自定义 User-Agent", @"selector": NSStringFromSelector(@selector(editUserAgent))}
    ];
    for (NSDictionary *item in items) {
        [sheet addAction:[UIAlertAction actionWithTitle:item[@"name"] style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            SEL selector = NSSelectorFromString(item[@"selector"]);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                if ([self respondsToSelector:selector]) {
                    ((void (*)(id, SEL))objc_msgSend)(self, selector);
                }
            });
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)editBaiduIdentifiers {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"百度 SDK 标识"
                                                                   message:@"CUID/UTDID 为 32 位十六进制；DeviceID 为 UUID 格式。每台手机必须不同。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    NSArray<NSDictionary *> *fields = @[
        @{@"key": @"cuid", @"default": @"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6", @"placeholder": @"CUID（32位十六进制）"},
        @{@"key": @"utdid", @"default": @"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", @"placeholder": @"UTDID（32位十六进制）"},
        @{@"key": @"deviceID", @"default": @"A1B2C3D4-E5F6-A7B8-C9D0-E1F2A3B4C5D6", @"placeholder": @"DeviceID（UUID）"}
    ];
    for (NSDictionary *info in fields) {
        [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.text = cfgStr(info[@"key"], info[@"default"]);
            field.placeholder = info[@"placeholder"];
            field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        }];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *cuid = alert.textFields[0].text.uppercaseString;
        NSString *utdid = alert.textFields[1].text.lowercaseString;
        NSString *deviceID = alert.textFields[2].text.uppercaseString;
        NSCharacterSet *hexUpper = [NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEF"];
        NSCharacterSet *hexLower = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
        BOOL cuidValid = cuid.length == 32 && [cuid rangeOfCharacterFromSet:hexUpper.invertedSet].location == NSNotFound;
        BOOL utdidValid = utdid.length == 32 && [utdid rangeOfCharacterFromSet:hexLower.invertedSet].location == NSNotFound;
        BOOL deviceIDValid = [[NSUUID alloc] initWithUUIDString:deviceID] != nil;
        if (!cuidValid || !utdidValid || !deviceIDValid) {
            [self presentMessage:@"CUID/UTDID 必须是 32 位十六进制，DeviceID 必须是有效 UUID。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"cuid": cuid, @"utdid": utdid, @"deviceID": deviceID})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editSysctlParams {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"sysctl 硬件参数"
                                                                   message:@"这些值必须与设备型号匹配，否则容易被识别。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    NSArray<NSDictionary *> *fields = @[
        @{@"key": @"hwMachine", @"default": @"iPhone15,2", @"placeholder": @"hw.machine，例如 iPhone15,2"},
        @{@"key": @"hwModel", @"default": @"D54AP", @"placeholder": @"hw.model，例如 D54AP"},
        @{@"key": @"kernOSVersion", @"default": @"21F79", @"placeholder": @"kern.osversion，例如 21F79"}
    ];
    for (NSDictionary *info in fields) {
        [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.text = cfgStr(info[@"key"], info[@"default"]);
            field.placeholder = info[@"placeholder"];
            field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        }];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *machine = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *model = [alert.textFields[1].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *osver = [alert.textFields[2].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].uppercaseString;
        if (!machine.length || machine.length > 32 || !model.length || model.length > 32 || !osver.length || osver.length > 16) {
            [self presentMessage:@"请检查各参数长度（machine/model 不超过 32，osversion 不超过 16）。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"hwMachine": machine, @"hwModel": model, @"kernOSVersion": osver})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editUserAgent {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"自定义 User-Agent"
                                                                   message:@"留空则根据系统版本自动生成。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"userAgent", @"");
        field.placeholder = @"留空自动生成";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *ua = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        [self showRestartNotice:saveConfigValues(@{@"userAgent": ua ?: @""})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editProcessHardware {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"主机名与内存"
                                                                   message:@"内存单位为 MB，建议只用于兼容性测试。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"kernHostname", @"iPhone");
        field.placeholder = @"主机名（1 到 64 个字符）";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = [NSString stringWithFormat:@"%ld", (long)cfgInt(@"memorySize", 6144)];
        field.placeholder = @"内存 MB（512 到 16384）";
        field.keyboardType = UIKeyboardTypeNumberPad;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *host = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSInteger memory = alert.textFields[1].text.integerValue;
        if (!host.length || host.length > 64 || memory < 512 || memory > 16384) {
            [self presentMessage:@"主机名须为 1 到 64 个字符，内存须为 512 到 16384 MB。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"kernHostname": host, @"memorySize": @(memory)})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editLocaleCarrier {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"语言地区与运营商"
                                                                   message:@"依次填写 Locale、运营商、MCC、MNC、国家码。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    NSArray<NSDictionary *> *fields = @[
        @{@"key": @"localeIdentifier", @"default": @"zh_CN", @"placeholder": @"Locale，例如 zh_CN"},
        @{@"key": @"carrierName", @"default": @"中国移动", @"placeholder": @"运营商名称"},
        @{@"key": @"mcc", @"default": @"460", @"placeholder": @"MCC，例如 460"},
        @{@"key": @"mnc", @"default": @"00", @"placeholder": @"MNC，例如 00"},
        @{@"key": @"isoCountryCode", @"default": @"cn", @"placeholder": @"国家码，例如 cn"}
    ];
    for (NSDictionary *info in fields) {
        [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.text = cfgStr(info[@"key"], info[@"default"]);
            field.placeholder = info[@"placeholder"];
            field.autocapitalizationType = UITextAutocapitalizationTypeNone;
            if ([info[@"key"] isEqualToString:@"mcc"] || [info[@"key"] isEqualToString:@"mnc"]) {
                field.keyboardType = UIKeyboardTypeNumberPad;
            }
        }];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSMutableArray<NSString *> *values = [NSMutableArray array];
        for (UITextField *field in alert.textFields) {
            [values addObject:[field.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] ?: @""];
        }
        NSString *locale = values[0];
        NSString *carrier = values[1];
        NSString *mcc = values[2];
        NSString *mnc = values[3];
        NSString *country = values[4].lowercaseString;
        NSCharacterSet *nonDigits = NSCharacterSet.decimalDigitCharacterSet.invertedSet;
        BOOL valid = locale.length >= 2 && locale.length <= 16 && carrier.length >= 1 && carrier.length <= 32 &&
                     mcc.length == 3 && [mcc rangeOfCharacterFromSet:nonDigits].location == NSNotFound &&
                     mnc.length >= 2 && mnc.length <= 3 && [mnc rangeOfCharacterFromSet:nonDigits].location == NSNotFound &&
                     country.length == 2 && [country rangeOfCharacterFromSet:NSCharacterSet.letterCharacterSet.invertedSet].location == NSNotFound;
        if (!valid) {
            [self presentMessage:@"请检查 Locale、运营商名称、3 位 MCC、2 到 3 位 MNC 和 2 位国家码。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{
            @"localeIdentifier": locale, @"carrierName": carrier,
            @"mcc": mcc, @"mnc": mnc, @"isoCountryCode": country
        })];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editScreenStorage {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"屏幕与磁盘"
                                                                   message:@"屏幕参数会影响布局，建议先记录原值。磁盘单位为 GB。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    NSArray<NSDictionary *> *fields = @[
        @{@"key": @"screenWidth", @"default": @393, @"placeholder": @"逻辑宽度"},
        @{@"key": @"screenHeight", @"default": @852, @"placeholder": @"逻辑高度"},
        @{@"key": @"screenScale", @"default": @3, @"placeholder": @"缩放倍数"},
        @{@"key": @"diskSize", @"default": @256, @"placeholder": @"磁盘 GB"}
    ];
    for (NSDictionary *info in fields) {
        [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.text = [NSString stringWithFormat:@"%ld", (long)cfgInt(info[@"key"], [info[@"default"] integerValue])];
            field.placeholder = info[@"placeholder"];
            field.keyboardType = UIKeyboardTypeNumberPad;
        }];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSInteger width = alert.textFields[0].text.integerValue;
        NSInteger height = alert.textFields[1].text.integerValue;
        NSInteger scale = alert.textFields[2].text.integerValue;
        NSInteger disk = alert.textFields[3].text.integerValue;
        if (width < 200 || width > 1500 || height < 200 || height > 3000 ||
            scale < 1 || scale > 4 || disk < 8 || disk > 2048) {
            [self presentMessage:@"宽度须为 200–1500，高度 200–3000，缩放 1–4，磁盘 8–2048 GB。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{
            @"screenWidth": @(width), @"screenHeight": @(height),
            @"screenScale": @(scale), @"diskSize": @(disk)
        })];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)showSelfTest {
    UIDevice *device = UIDevice.currentDevice;
    NSProcessInfo *process = NSProcessInfo.processInfo;
    UIScreen *screen = UIScreen.mainScreen;

    typedef NSString *(*StringGetterIMP)(id, SEL);
    typedef NSUUID *(*UUIDGetterIMP)(id, SEL);
    typedef unsigned long long (*MemoryGetterIMP)(id, SEL);
    typedef CGRect (*BoundsGetterIMP)(id, SEL);
    typedef CGFloat (*ScaleGetterIMP)(id, SEL);

    NSString *currentVersion = device.systemVersion ?: @"nil";
    NSString *realVersion = orig_systemVersion
        ? ((StringGetterIMP)orig_systemVersion)(device, @selector(systemVersion)) : currentVersion;
    NSString *currentName = device.name ?: @"nil";
    NSString *realName = orig_name ? ((StringGetterIMP)orig_name)(device, @selector(name)) : currentName;
    NSString *currentIDFV = device.identifierForVendor.UUIDString ?: @"nil";
    NSUUID *realUUID = orig_identifierForVendor
        ? ((UUIDGetterIMP)orig_identifierForVendor)(device, @selector(identifierForVendor)) : device.identifierForVendor;
    NSString *realIDFV = realUUID.UUIDString ?: @"nil";
    NSString *currentProcess = process.operatingSystemVersionString ?: @"nil";
    NSString *realProcess = orig_operatingSystemVersionString
        ? ((StringGetterIMP)orig_operatingSystemVersionString)(process, @selector(operatingSystemVersionString)) : currentProcess;
    unsigned long long currentMemory = process.physicalMemory / (1024ULL * 1024ULL);
    unsigned long long realMemory = orig_physicalMemory
        ? ((MemoryGetterIMP)orig_physicalMemory)(process, @selector(physicalMemory)) / (1024ULL * 1024ULL) : currentMemory;
    CGRect currentBounds = screen.bounds;
    CGRect realBounds = orig_bounds ? ((BoundsGetterIMP)orig_bounds)(screen, @selector(bounds)) : currentBounds;
    CGFloat currentScale = screen.scale;
    CGFloat realScale = orig_scale ? ((ScaleGetterIMP)orig_scale)(screen, @selector(scale)) : currentScale;

    NSString *message = [NSString stringWithFormat:
        @"状态：%@\n\n"
         @"iOS\n原始 %@\n配置 %@ (%@)\n当前 %@\n\n"
         @"设备名称\n原始 %@\n配置 %@\n当前 %@\n\n"
         @"IDFV\n原始 %@\n配置 %@\n当前 %@\n\n"
         @"NSProcessInfo\n原始 %@\n当前 %@\n\n"
         @"内存(MB)\n原始 %llu\n配置 %ld\n当前 %llu\n\n"
         @"屏幕(points / scale)\n原始 %.0fx%.0f / %.2f\n配置 %ldx%ld / %ld\n当前 %.0fx%.0f / %.2f",
        cfgBool(@"enabled", NO) ? @"基础功能已开启" : @"基础功能已关闭",
        realVersion, cfgStr(@"systemVersion", @"17.5.1"), cfgStr(@"systemBuild", @"21F79"), currentVersion,
        realName, cfgStr(@"deviceName", @"iPhone"), currentName,
        realIDFV, cfgStr(@"idfv", @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890"), currentIDFV,
        realProcess, currentProcess,
        realMemory, (long)cfgInt(@"memorySize", 6144), currentMemory,
        CGRectGetWidth(realBounds), CGRectGetHeight(realBounds), realScale,
        (long)cfgInt(@"screenWidth", 393), (long)cfgInt(@"screenHeight", 852), (long)cfgInt(@"screenScale", 3),
        CGRectGetWidth(currentBounds), CGRectGetHeight(currentBounds), currentScale];

    // 高级功能自检
    NSMutableString *advanced = [NSMutableString stringWithString:@"\n\n--- 高级功能 ---"];

    [advanced appendFormat:@"\n百度SDK：%@", cfgBool(@"spoofBaiduSDK", NO) ? @"开" : @"关"];
    if (cfgBool(@"spoofBaiduSDK", NO)) {
        NSArray *classNames = @[@"CuidSDK", @"CuidSDK18BBADevAccountPatch", @"UTDIDModule", @"MobStat", @"DeviceIdentifierFetcher"];
        for (NSString *cn in classNames) {
            Class c = objc_getClass(cn.UTF8String);
            if (c) {
                NSUInteger hooked = 0;
                [g_baiduLock lock];
                for (NSString *key in g_baiduHookedKeys) {
                    if ([key hasPrefix:[cn stringByAppendingString:@"."]]) hooked++;
                }
                [g_baiduLock unlock];
                [advanced appendFormat:@"\n  %@：已hook %lu个方法", cn, (unsigned long)hooked];
            } else {
                [advanced appendFormat:@"\n  %@：类不存在", cn];
            }
        }
    }

    [advanced appendFormat:@"\nsysctlbyname：%@", cfgBool(@"spoofSysctl", NO) ? @"开" : @"关"];
    if (cfgBool(@"spoofSysctl", NO)) {
        char buf[64] = {0};
        size_t len = sizeof(buf);
        if (sysctlbyname("hw.machine", buf, &len, NULL, 0) == 0) {
            [advanced appendFormat:@"\n  hw.machine：%s", buf];
        }
        len = sizeof(buf); memset(buf, 0, sizeof(buf));
        if (sysctlbyname("kern.osversion", buf, &len, NULL, 0) == 0) {
            [advanced appendFormat:@"\n  kern.osversion：%s", buf];
        }
    }

    [advanced appendFormat:@"\nUser-Agent：%@", cfgBool(@"spoofUserAgent", NO) ? @"开" : @"关"];
    if (cfgBool(@"spoofUserAgent", NO)) {
        WKWebView *wv = [[WKWebView alloc] init];
        NSString *ua = [wv performSelector:@selector(customUserAgent)];
        [advanced appendFormat:@"\n  WKWebView getter：%@", ua ?: @"nil（App未设置）"];
        [advanced appendString:@"\n  注：仅验证getter，不代表实际请求头"];
    }

    [advanced appendFormat:@"\n越狱绕过：%@", cfgBool(@"bypassJailbreakDetect", NO) ? @"开" : @"关"];

    message = [message stringByAppendingString:advanced];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *presenter = BDSTopController();
        if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"公开 API 对照自检"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"复制结果" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            UIPasteboard.generalPasteboard.string = message;
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleCancel handler:nil]];
        [presenter presentViewController:alert animated:YES completion:nil];
    });
}

@end

static void BDSInstallUI(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil
                                                           queue:NSOperationQueue.mainQueue
                                                      usingBlock:^(NSNotification *note) {
            (void)note;
            [[BDSUIController shared] attachButton];
        }];
        for (NSNumber *delay in @[@0.8, @2.0, @5.0]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [[BDSUIController shared] attachButton];
            });
        }
    });
}

#pragma mark - 构造函数

__attribute__((constructor))
static void bds_initialize() {
    @autoreleasepool {
        loadConfig();

        NSString *bundleID = [NSBundle mainBundle].bundleIdentifier;
        if (![bundleID isEqualToString:@"com.baidu.BaiduMobileInfo"]) return;

        // 配置入口始终安装；即使功能关闭，也可以从右侧“隐”按钮重新开启。
        BDSInstallUI();

        // 配置缺失或读取失败时默认不启用，避免注入后意外改变百度行为。
        if (!cfgBool(@"enabled", NO)) return;

        // UIDevice
        Class cls = objc_getClass("UIDevice");
        hookInst(cls, @selector(systemVersion), (IMP)new_systemVersion, &orig_systemVersion);
        hookInst(cls, @selector(model), (IMP)new_model, &orig_model);
        hookInst(cls, @selector(localizedModel), (IMP)new_localizedModel, &orig_localizedModel);
        hookInst(cls, @selector(name), (IMP)new_name, &orig_name);
        hookInst(cls, @selector(systemName), (IMP)new_systemName, &orig_systemName);
        hookInst(cls, @selector(identifierForVendor), (IMP)new_identifierForVendor, &orig_identifierForVendor);

        if (cfgBool(@"spoofAdvertisingIdentifiers", YES)) {
            // ASIdentifierManager
            cls = objc_getClass("ASIdentifierManager");
            hookInst(cls, @selector(advertisingIdentifier), (IMP)new_advertisingIdentifier, &orig_advertisingIdentifier);
            hookInst(cls, @selector(isAdvertisingTrackingEnabled), (IMP)new_isAdvertisingTrackingEnabled, &orig_isAdvertisingTrackingEnabled);

            // ATTrackingManager (iOS 14+)
            cls = objc_getClass("ATTrackingManager");
            if (cls) {
                hookClass(cls, @selector(trackingAuthorizationStatus), (IMP)new_trackingAuthorizationStatus, &orig_trackingAuthorizationStatus);
            }
        }

        // NSProcessInfo
        cls = objc_getClass("NSProcessInfo");
        hookInst(cls, @selector(operatingSystemVersion), (IMP)new_operatingSystemVersion, &orig_operatingSystemVersion);
        hookInst(cls, @selector(operatingSystemVersionString), (IMP)new_operatingSystemVersionString, &orig_operatingSystemVersionString);
        if (cfgBool(@"spoofProcessHardware", NO)) {
            hookInst(cls, @selector(hostName), (IMP)new_hostName, &orig_hostName);
            hookInst(cls, @selector(physicalMemory), (IMP)new_physicalMemory, &orig_physicalMemory);
        }

        if (cfgBool(@"spoofLocale", NO)) {
            // NSLocale
            cls = objc_getClass("NSLocale");
            hookInst(cls, @selector(localeIdentifier), (IMP)new_localeIdentifier, &orig_localeIdentifier);
        }

        if (cfgBool(@"spoofCarrier", NO)) {
            // CTTelephonyNetworkInfo
            cls = objc_getClass("CTTelephonyNetworkInfo");
            hookInst(cls, @selector(subscriberCellularProvider), (IMP)new_subscriberCellularProvider, &orig_subscriberCellularProvider);
            hookInst(cls, @selector(serviceSubscriberCellularProviders), (IMP)new_serviceSubscriberCellularProviders, &orig_serviceSubscriberCellularProviders);

            // CTCarrier
            cls = objc_getClass("CTCarrier");
            hookInst(cls, @selector(carrierName), (IMP)new_carrierName, &orig_carrierName);
            hookInst(cls, @selector(mobileCountryCode), (IMP)new_mobileCountryCode, &orig_mobileCountryCode);
            hookInst(cls, @selector(mobileNetworkCode), (IMP)new_mobileNetworkCode, &orig_mobileNetworkCode);
            hookInst(cls, @selector(isoCountryCode), (IMP)new_isoCountryCode, &orig_isoCountryCode);
            hookInst(cls, @selector(allowsVOIP), (IMP)new_allowsVOIP, &orig_allowsVOIP);
        }

        // UIScreen：默认关闭，避免改变真实窗口尺寸导致布局或启动异常。
        if (cfgBool(@"spoofScreen", NO)) {
            cls = objc_getClass("UIScreen");
            hookInst(cls, @selector(bounds), (IMP)new_bounds, &orig_bounds);
            hookInst(cls, @selector(nativeBounds), (IMP)new_nativeBounds, &orig_nativeBounds);
            hookInst(cls, @selector(scale), (IMP)new_scale, &orig_scale);
        }

        if (cfgBool(@"spoofStorage", NO)) {
            // NSFileManager
            cls = objc_getClass("NSFileManager");
            hookInst(cls, @selector(attributesOfFileSystemForPath:error:), (IMP)new_attributesOfFileSystemForPath, &orig_attributesOfFileSystemForPath);
        }

        // 百度 SDK 设备标识 hook
        if (cfgBool(@"spoofBaiduSDK", NO)) {
            installBaiduSDKHooks();
        }

        // User-Agent hook
        if (cfgBool(@"spoofUserAgent", NO)) {
            cls = objc_getClass("WKWebView");
            if (cls) {
                hookInst(cls, @selector(customUserAgent), (IMP)new_wk_customUserAgent, &orig_wk_customUserAgent);
            }
            cls = objc_getClass("NSMutableURLRequest");
            if (cls) {
                hookInst(cls, @selector(setValue:forHTTPHeaderField:), (IMP)new_nsmurl_setValue, &orig_nsmurl_setValue);
                hookInst(cls, @selector(addValue:forHTTPHeaderField:), (IMP)new_nsmurl_addValue, &orig_nsmurl_addValue);
            }
        }

        // 越狱检测绕过
        if (cfgBool(@"bypassJailbreakDetect", NO)) {
            cls = objc_getClass("NSFileManager");
            hookInst(cls, @selector(fileExistsAtPath:), (IMP)new_fileExistsAtPath, &orig_fileExistsAtPath);
            hookInst(cls, @selector(fileExistsAtPath:isDirectory:), (IMP)new_fileExistsAtPathIsDir, &orig_fileExistsAtPathIsDir);

            cls = objc_getClass("UIApplication");
            hookInst(cls, @selector(canOpenURL:), (IMP)new_canOpenURL, &orig_canOpenURL);
        }

        // sysctlbyname 通过 DYLD_INTERPOSE 自动生效，无需在此安装。
        // 高级功能默认全部关闭，通过"隐"按钮逐项开启。
    }
}
