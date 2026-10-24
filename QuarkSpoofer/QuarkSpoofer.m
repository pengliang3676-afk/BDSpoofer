//
//  QuarkSpoofer.m  —  夸克浏览器（com.quark.browser）设备指纹伪装
//
//  v1：只做 ObjC 层（UIDevice / NSProcessInfo / UA / UTDID / AliSecX getter）
//      sysctl(C层) 放到 v2，用 fishhook 另写
//
//  每个 hook：g_enabled 为假 → 调原实现；原实现为 NULL → 返回安全默认值。
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#pragma mark - 配置

static NSString *const QKConfigFile = @"qk_config.plist";
static NSDictionary *g_cfg = nil;
static BOOL g_enabled = YES;

static id QKStr(NSString *key, id fallback) {
    id v = g_cfg[key];
    if ([v isKindOfClass:NSString.class] && [(NSString *)v length]) return v;
    return fallback;
}
static NSNumber *QKNum(NSString *key, NSNumber *fallback) {
    id v = g_cfg[key];
    if ([v isKindOfClass:NSNumber.class]) return v;
    return fallback;
}

static NSString *QKConfigPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:QKConfigFile];
}

static void QKLoadConfig(void) {
    @try {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:QKConfigPath()];
        if ([d isKindOfClass:NSDictionary.class]) {
            g_cfg = d;
            id en = d[@"enabled"];
            if ([en isKindOfClass:NSNumber.class]) g_enabled = [en boolValue];
        }
    } @catch (NSException *e) {}
    if (!g_cfg) g_cfg = @{};
}

static NSString *QKHW(void)        { return QKStr(@"hwMachine", @"iPhone15,2"); }
static NSString *QKModelName(void) { return QKStr(@"marketingName", @"iPhone 14 Pro"); }
static NSString *QKSysVer(void)    { return QKStr(@"systemVersion", @"17.0.1"); }
static NSString *QKSysBuild(void)  { return QKStr(@"systemBuild", @"21A340"); }
static NSString *QKUTDID(void)     { return QKStr(@"utdid", @""); }
static NSString *QKAAID(void)      { return QKStr(@"aaid", @""); }

#pragma mark - swizzle 工具

static IMP QKSwapInstance(Class cls, SEL sel, IMP newImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NULL;
    return method_setImplementation(m, newImp);
}
static IMP QKSwapClass(Class cls, SEL sel, IMP newImp) {
    Method m = class_getClassMethod(cls, sel);
    if (!m) return NULL;
    return method_setImplementation(m, newImp);
}

#pragma mark - UIDevice

static IMP qk_o_model, qk_o_name, qk_o_sysver, qk_o_idfv;

static NSString *qk_device_model(id self, SEL _cmd) {
    if (g_enabled) return QKHW();
    return qk_o_model ? ((NSString *(*)(id, SEL))qk_o_model)(self, _cmd) : @"iPhone";
}
static NSString *qk_device_name(id self, SEL _cmd) {
    if (g_enabled) return QKModelName();
    return qk_o_name ? ((NSString *(*)(id, SEL))qk_o_name)(self, _cmd) : @"iPhone";
}
static NSString *qk_device_sysver(id self, SEL _cmd) {
    if (g_enabled) return QKSysVer();
    return qk_o_sysver ? ((NSString *(*)(id, SEL))qk_o_sysver)(self, _cmd) : @"17.0";
}
static NSUUID *qk_device_idfv(id self, SEL _cmd) {
    if (g_enabled) {
        NSString *uuid = QKStr(@"idfv", @"");
        if (uuid.length) return [[NSUUID alloc] initWithUUIDString:uuid];
    }
    return qk_o_idfv ? ((NSUUID *(*)(id, SEL))qk_o_idfv)(self, _cmd) : nil;
}

#pragma mark - NSProcessInfo

static IMP qk_o_physmem, qk_o_osver, qk_o_osverstr;

static unsigned long long qk_physmem(id self, SEL _cmd) {
    if (g_enabled) {
        NSNumber *n = QKNum(@"memorySize", nil);
        if (n) return (unsigned long long)(n.doubleValue * 1024.0 * 1024.0);
    }
    return qk_o_physmem ? ((unsigned long long (*)(id, SEL))qk_o_physmem)(self, _cmd) : 0;
}
static NSOperatingSystemVersion qk_osver(id self, SEL _cmd) {
    if (g_enabled) {
        NSArray *p = [QKSysVer() componentsSeparatedByString:@"."];
        NSOperatingSystemVersion v = {0, 0, 0};
        if (p.count > 0) v.majorVersion = [p[0] integerValue];
        if (p.count > 1) v.minorVersion = [p[1] integerValue];
        if (p.count > 2) v.patchVersion = [p[2] integerValue];
        return v;
    }
    return qk_o_osver ? ((NSOperatingSystemVersion (*)(id, SEL))qk_o_osver)(self, _cmd) : (NSOperatingSystemVersion){0, 0, 0};
}
static NSString *qk_osverstr(id self, SEL _cmd) {
    if (g_enabled) return [NSString stringWithFormat:@"Version %@ (Build %@)", QKSysVer(), QKSysBuild()];
    return qk_o_osverstr ? ((NSString *(*)(id, SEL))qk_o_osverstr)(self, _cmd) : @"";
}

#pragma mark - UA 头

static IMP qk_o_setheader;
static void qk_set_header(id self, SEL _cmd, NSString *value, NSString *field) {
    @try {
        if (g_enabled && [field isKindOfClass:NSString.class] &&
            [field.lowercaseString isEqualToString:@"user-agent"]) {
            NSString *fake = QKStr(@"userAgent", nil);
            if (fake.length) value = fake;
        }
    } @catch (NSException *e) {}
    if (qk_o_setheader) ((void (*)(id, SEL, NSString *, NSString *))qk_o_setheader)(self, _cmd, value, field);
}

#pragma mark - UTDID

// 通用 keychain 读：service 前缀 com.UTDID 时返回伪装值
static IMP qk_o_pwd_svc;
static NSString *qk_pwd_svc(id self, SEL _cmd, NSString *service, NSString *account) {
    @try {
        if (g_enabled && service.length && QKUTDID().length) {
            NSString *low = service.lowercaseString;
            if ([service hasPrefix:@"com.UTDID"] || [low containsString:@"utdid"]) {
                return QKUTDID();
            }
        }
    } @catch (NSException *e) {}
    return qk_o_pwd_svc ? ((NSString *(*)(id, SEL, NSString *, NSString *))qk_o_pwd_svc)(self, _cmd, service, account) : nil;
}

// UTDIDKeychainItemWrapper 的 objectForKey:
static IMP qk_o_objforkey;
static id qk_objforkey(id self, SEL _cmd, NSString *key) {
    @try {
        if (g_enabled && QKUTDID().length && [key isKindOfClass:NSString.class]) {
            NSString *low = key.lowercaseString;
            if ([low containsString:@"utdid"] || [low containsString:@"device"]) {
                return QKUTDID();
            }
        }
    } @catch (NSException *e) {}
    return qk_o_objforkey ? ((id (*)(id, SEL, NSString *))qk_o_objforkey)(self, _cmd, key) : nil;
}

#pragma mark - AliSecX getter

static NSString *qk_alisec_getter(id self, SEL _cmd) {
    @try {
        if (g_enabled) {
            NSString *nm = NSStringFromSelector(_cmd);
            if ([nm containsString:@"odel"] || [nm containsString:@"Model"]) return QKHW();
            if ([nm containsString:@"ersion"] || [nm containsString:@"Version"]) return QKSysVer();
            if ([nm containsString:@"ame"] || [nm containsString:@"Name"]) return QKModelName();
        }
    } @catch (NSException *e) {}
    return QKHW();
}

#pragma mark - 安装

static void QKInstall(void) {
    @try {
        Class dev = NSClassFromString(@"UIDevice");
        if (dev) {
            qk_o_model  = QKSwapInstance(dev, @selector(model), (IMP)qk_device_model);
            qk_o_name   = QKSwapInstance(dev, @selector(name), (IMP)qk_device_name);
            qk_o_sysver = QKSwapInstance(dev, @selector(systemVersion), (IMP)qk_device_sysver);
            qk_o_idfv   = QKSwapInstance(dev, @selector(identifierForVendor), (IMP)qk_device_idfv);
        }
    } @catch (NSException *e) {}

    @try {
        Class pi = NSClassFromString(@"NSProcessInfo");
        if (pi) {
            qk_o_physmem  = QKSwapInstance(pi, @selector(physicalMemory), (IMP)qk_physmem);
            qk_o_osver    = QKSwapInstance(pi, @selector(operatingSystemVersion), (IMP)qk_osver);
            qk_o_osverstr = QKSwapInstance(pi, @selector(operatingSystemVersionString), (IMP)qk_osverstr);
        }
    } @catch (NSException *e) {}

    @try {
        Class req = NSClassFromString(@"NSMutableURLRequest");
        if (req) qk_o_setheader = QKSwapInstance(req, @selector(setValue:forHTTPHeaderField:), (IMP)qk_set_header);
    } @catch (NSException *e) {}

    @try {
        Class kcw = NSClassFromString(@"UTDIDKeychainItemWrapper");
        if (kcw) {
            qk_o_objforkey = QKSwapInstance(kcw, @selector(objectForKey:), (IMP)qk_objforkey);
        }
    } @catch (NSException *e) {}

    @try {
        for (NSString *cn in @[@"SSKeychain", @"AliSecXSSKeychain"]) {
            Class k = NSClassFromString(cn);
            if (!k) continue;
            // 先试类方法，再试实例方法
            IMP a = QKSwapClass(k, @selector(passwordForService:account:), (IMP)qk_pwd_svc);
            if (!a) a = QKSwapInstance(k, @selector(passwordForService:account:), (IMP)qk_pwd_svc);
            if (a && !qk_o_pwd_svc) qk_o_pwd_svc = a;
        }
    } @catch (NSException *e) {}

    @try {
        for (NSString *cn in @[@"AliSecXDeviceInfoMXXTIY", @"AliSecXPhoneInfoHolderMXXTIY"]) {
            Class k = NSClassFromString(cn);
            if (!k) continue;
            unsigned int n = 0;
            Method *ms = class_copyMethodList(k, &n);
            for (unsigned i = 0; i < n; i++) {
                const char *nm = sel_getName(method_getName(ms[i]));
                if (!nm) continue;
                if (!(strstr(nm, "deviceModel") || strstr(nm, "DeviceModel") ||
                      strstr(nm, "systemVersion") || strstr(nm, "SystemVersion") ||
                      strstr(nm, "deviceName") || strstr(nm, "DeviceName"))) continue;
                char *rt = method_copyReturnType(ms[i]);
                BOOL isObj = (rt && rt[0] == '@');
                free(rt);
                if (!isObj) continue;
                method_setImplementation(ms[i], (IMP)qk_alisec_getter);
            }
            free(ms);
        }
    } @catch (NSException *e) {}
}

#pragma mark - 入口

__attribute__((constructor))
static void QKInit(void) {
    @autoreleasepool {
        NSString *bid = [NSBundle mainBundle].bundleIdentifier;
        if (![bid isEqualToString:@"com.quark.browser"]) return;
        QKLoadConfig();
        dispatch_async(dispatch_get_main_queue(), ^{
            @try { QKInstall(); } @catch (NSException *e) {}
        });
    }
}
