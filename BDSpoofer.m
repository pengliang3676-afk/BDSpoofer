//
//  BDSpoofer.m
//  BDS Global Spoofer 1.9.6（roothide / dopamine，ElleKit 全局注入 deb；亦可 TrollFools 单注入）
//    - 全局共享一份虚拟身份：芒果 TV 与任意广告主 App 读取同一套设备参数，保证 CPA 归因一致。
//    - 系统 App 与白名单（微信/QQ/支付宝/百度等）完全透传，不生成身份、不安装 hook。
//    - 全局目录走 roothide jbroot 解析 + 真实可写探测；首发生成/迁移/保存用 flock 跨进程锁串行化。
//    - Dipfy 安全 SDK 专属 hook：越狱/代理/调试返回 NO，自产设备标识返回当前身份伪造值。
//  1.9.6：
//    V. 换号持久标识清理：iOS 卸载不删 Keychain，Dipfy 借此在重装后仍认出老设备/老账号。
//       「换全新身份」可挂一次性标记，下次芒果启动、在所有业务 SDK 读取前清空自身 Keychain、
//       NSUserDefaults 标识键、Foundation Cookie，以及自有容器/AppGroup 内的设备-ID 类文件，
//       并重置 Dipfy 本地 ID，使每次换号等价于一台从未装过芒果的全新设备。
//  1.8.0：
//    S. 兼容/扩展随机池合并为统一 10 款机型，不再区分随机模式；SE2 不参与随机。
//    T. 移除照片权限 Hook；相机权限继续不做 Hook，保留通讯录/日历保护。
//    U. 基础功能 6 个开关继续默认开启，一键基础随机后仍保持开启。
//  1.7.8：
//    R. 发布版本号升级；功能与 1.7.4 保持一致。
//  1.7.4：
//    Q. 反关联增强第二批：
//       - statfs/statvfs 磁盘剩余空间伪装（C 层兜底）
//       - dlopen/dlopen_preflight 反检测（越狱库路径返回 NULL）
//       - iCloud 容器隔离（URLForUbiquityContainerIdentifier 返回 nil）
//       - 通讯录/日历/照片权限返回拒绝（1.8.0 已移除照片 Hook）
//       - WebKit Cookie 过滤（过滤百度域名设备标识 Cookie，保留登录态）
//  1.7.3：
//    P. 反关联增强（独立二级页面）：
//       - WiFi SSID/BSSID 隐藏（CNCopyCurrentNetworkInfo fishhook）
//       - 本地 IP 隐藏（getifaddrs fishhook，清空 en0 地址）
//       - App Group 共享容器隔离（拦截 baidu group identifier）
//       - 剪贴板保护（UIPasteboard 读取返回空）
//       - 系统启动时间随机化（kern.boottime sysctl）
//       - CPU 参数伪装（hw.ncpu/hw.physicalcpu sysctl）
//       - 定位保护（CLLocationManager 返回拒绝/nil）
//       - 代理/VPN 检测绕过（CFNetworkCopySystemProxySettings / SCDynamicStoreCopyProxies）
//  1.7.2：
//    M. 机型随机增加兼容/扩展两种范围，默认兼容模式
//    N. IDFA 遵循真实 ATT 授权；UA 默认透传；Keychain 默认关闭
//    O. API 返回值与 Hook 统计拆分，自检支持复制确认和 TXT 分享
//  1.7.1：
//    K. 公开 API 自检增加进程内 hook 命中/透传/修改统计与最近状态
//    L. 诊断计数使用纯原子操作，C/dyld hook 内不调用 Objective-C
//  1.7.0：
//    H. 主面板精简，基础/高级功能改为独立二级页面
//    I. 基础随机与高级身份随机彻底分离
//    J. 悬浮按钮自动贴边，静置 5 秒后收成半透明把手
//  1.6.2：
//    G. 整套随机保留本机真实屏幕尺寸，避免 UIScreen hook 导致界面缩放
//  1.6.1：
//    E. 基础页面增加“一键随机整套设备参数”
//       （iPhone 8 至 iPhone 13 系列，含 SE2/SE3；iOS 15/16）
//    F. 基础功能默认开启；随机操作仅在手动点击时执行并持久保存
//  1.6.0：
//    A. iPhone 8 默认硬件参数（与 SE2 硬件一致）
//    B. _dyld_get_image_name 镜像名过滤（fishhook）
//    C. C 函数级文件检测 hook（stat/lstat/access/fopen/opendir，fishhook）
//    D. NSBundle 遍历过滤（allFrameworks/allBundles/loadedBundles）
//    C 函数 hook 全部使用 fishhook（GOT 替换），不使用 DYLD_INTERPOSE，
//    原始函数指针直接指向 libSystem 真实地址，结构上杜绝递归。
//    arm64 iOS 上 stat 已是 64 位 inode，不 hook stat64。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <Security/Security.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <WebKit/WebKit.h>
#import <dirent.h>
#import <stdio.h>
#import <unistd.h>
#import <string.h>
#import <errno.h>
#import <stdlib.h>
#import <mach/mach.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CoreLocation/CoreLocation.h>
#import <ifaddrs.h>
#import <net/if_dl.h>
#import <arpa/inet.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <dlfcn.h>
#import <Contacts/Contacts.h>
#import <EventKit/EventKit.h>
#import <fcntl.h>
#import <sys/file.h>

#pragma mark - 原子操作

#define BDS_ATOMIC_SET(var, val) __atomic_store_n(&(var), (val), __ATOMIC_RELEASE)
#define BDS_ATOMIC_GET(var) __atomic_load_n(&(var), __ATOMIC_ACQUIRE)

#pragma mark - 配置

static NSDictionary *g_config = nil;
static NSString *g_lastWipeReport = nil; // 1.9.6 最近一次持久标识清理结果（供界面展示）

// C hook 使用的全局开关（原子读写，constructor 中从配置设置）
static int g_enabledC = 0;
static int g_spoofSysctlC = 0;
static int g_bypassJailbreakC = 0;
static int g_spoofWiFiC = 0;
static int g_spoofLocalIPC = 0;
static int g_spoofProxyC = 0;
static int g_spoofBootTimeC = 0;
static int g_spoofCPUC = 0;
static int g_spoofStatfsC = 0;
static int g_spoofDlopenC = 0;

// C hook 使用的缓存伪造值（constructor 和 saveConfigValues 中更新）
static char g_hwMachine[32] = "iPhone14,6";
static char g_hwModel[32] = "D49AP";
static char g_kernOSVersion[16] = "19E258";
static char g_kernHostname[65] = "iPhone";
static char g_wifiSSID[64] = "";

// 伪造的启动时间（constructor 中初始化为当前时间减去随机 1-7 天）
static struct timeval g_fakeBootTime = {0, 0};

// 当前支持的 A11-A15 设备均为 6 个物理 CPU 核心。
static int g_fakeNcpu = 6;
static int g_fakePhysicalCPU = 6;
static int g_fakeActiveCPU = 6;

// 磁盘大小（字节），C hook 使用，constructor 和 saveConfigValues 中更新
static long long g_fakeDiskSizeBytes = 64LL * 1024 * 1024 * 1024;

static inline long long bds_disk_size_get(void) {
    return __atomic_load_n(&g_fakeDiskSizeBytes, __ATOMIC_RELAXED);
}
static inline void bds_disk_size_set(long long v) {
    __atomic_store_n(&g_fakeDiskSizeBytes, v, __ATOMIC_RELAXED);
}

static NSDictionary *BDSDefaultConfig(void) {
    static NSDictionary *defaults;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        defaults = @{
            @"configVersion": @196,
            @"enabled": @NO,
            @"spoofAdvertisingIdentifiers": @NO,
            @"spoofProcessHardware": @NO,
            @"spoofLocale": @NO,
            @"spoofCarrier": @NO,
            @"spoofScreen": @NO,
            @"spoofStorage": @NO,
            @"spoofBaiduSDK": @NO,
            @"spoofSysctl": @NO,
            @"spoofKeychain": @NO,
            @"spoofUserAgent": @NO,
            @"bypassJailbreakDetect": @NO,
            @"spoofWiFi": @NO,
            @"spoofLocalIP": @NO,
            @"spoofAppGroup": @NO,
            @"spoofPasteboard": @NO,
            @"spoofBootTime": @NO,
            @"spoofCPU": @NO,
            @"spoofLocation": @NO,
            @"spoofProxyDetection": @NO,
            @"spoofStatfs": @NO,
            @"spoofDlopen": @NO,
            @"spoofUbiquity": @NO,
            @"spoofPrivacyPermissions": @NO,
            @"spoofWebKitCookie": @NO,
            @"spoofBattery": @NO,
            @"wifiSSID": @"",
            @"bootTimeOffsetSeconds": @0,
            @"deviceProfileName": @"iPhone SE (3rd generation)",
            @"systemVersion": @"15.4.1",
            @"systemBuild": @"19E258",
            @"kernOSVersion": @"19E258",
            @"hwMachine": @"iPhone14,6",
            @"hwModel": @"D49AP",
            @"memorySize": @4096,
            @"diskSize": @64,
            @"floatingButtonSide": @"right",
            @"floatingButtonYPermille": @520,
            // 1.9.0 全局伪装（芒果 CPA）新增
            @"globalMode": @YES,              // 全局注入模式：非白名单进程一律伪装
            @"spoofDipfy": @NO,               // 芒果 Dipfy 安全 SDK 专属 hook（迁移后默认开）
            @"dipfyDeviceKey": @"",
            @"dipfyFakeUUID": @"",
            @"identityId": @"",
            @"macAddress": @"",
            // 1.9.6 换号持久标识清理
            @"wipePersistenceOnNextLaunch": @NO, // 一次性标记：下次芒果启动先清本机持久标识
            @"autoWipeOnRotate": @YES,           // 点「换全新身份」时自动挂上一次性清理
            @"lastWipeAt": @0,
            @"lastWipeReport": @"",
            // 透传白名单：com.apple. 前缀始终透传，这里是用户额外选择的 App。
            // 以 "." 或 "*" 结尾表示前缀匹配，其余为精确匹配。
            @"passthroughBundles": @[
                @"com.baidu.",
                @"com.tencent.xin",
                @"com.tencent.mqq",
                @"com.alipay."
            ]
        };
    });
    return defaults;
}

// 无法取得共享锁时，只接受已经完成迁移且关键身份字段完整的磁盘配置。
// 此检查只读，不生成字段、不执行迁移，避免不同进程在无锁状态下各自补值。
static BOOL bds_isCompleteSharedConfig(NSDictionary *config) {
    if (![config isKindOfClass:NSDictionary.class]) return NO;
    NSNumber *version = config[@"configVersion"];
    if (![version isKindOfClass:NSNumber.class] || version.integerValue < 190) return NO;
    NSArray<NSString *> *requiredStrings = @[
        @"identityId", @"idfa", @"idfv", @"dipfyDeviceKey", @"dipfyFakeUUID", @"macAddress",
        @"deviceProfileName", @"systemVersion", @"systemBuild", @"hwMachine", @"hwModel"
    ];
    for (NSString *key in requiredStrings) {
        id value = config[key];
        if (![value isKindOfClass:NSString.class] || [(NSString *)value length] == 0) return NO;
    }
    if (![config[@"globalMode"] isKindOfClass:NSNumber.class]) return NO;
    if (![config[@"passthroughBundles"] isKindOfClass:NSArray.class]) return NO;
    return YES;
}

#pragma mark - 全局共享配置路径 / 进程身份 / 白名单

// 芒果 TV 主 App bundle id（配置浮窗只在它里面显示）
#define BDS_MG_BUNDLE @"com.hunantv.imgotv"

static NSString *g_bundleID = nil;   // 当前进程 bundle id
static BOOL g_isMango = NO;          // 当前进程是否为芒果 TV 主 App


// ===== 1.9.3 全局共享存储：roothide jbroot 官方 API + 真实可写探测 + 可嵌套/带状态双锁 + 跨App登记 =====

typedef const char *(*bds_jbroot_fn_t)(const char *);
// 惰性解析一次：jbroot 函数指针 + JBRootPath 环境变量（roothide 的 jbroot 每次越狱随机命名）。
static void bds_resolveJbroot(bds_jbroot_fn_t *outFn, NSString **outEnvRoot) {
    static dispatch_once_t once;
    static bds_jbroot_fn_t sFn = NULL;
    static NSString *sEnv = nil;
    dispatch_once(&once, ^{
        sFn = (bds_jbroot_fn_t)dlsym(RTLD_DEFAULT, "jbroot");
        const char *e = getenv("JBRootPath");
        if (e && *e) sEnv = [NSString stringWithUTF8String:e];
    });
    if (outFn) *outFn = sFn;
    if (outEnvRoot) *outEnvRoot = sEnv;
}

// 全局目录候选（顺序即优先级）：roothide jbroot 官方换算优先，其次 $JBRootPath、经典 /var/jb、裸路径，去重。
static NSArray<NSString *> *bds_globalConfigCandidates(void) {
    NSArray<NSString *> *rel = @[ @"/var/mobile/Media/BDSpoofer", @"/var/mobile/Library/BDSpoofer" ];
    NSMutableArray<NSString *> *list = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    void (^add)(NSString *) = ^(NSString *p) {
        if (p.length && ![seen containsObject:p]) { [seen addObject:p]; [list addObject:p]; }
    };
    bds_jbroot_fn_t fn = NULL; NSString *envRoot = nil;
    bds_resolveJbroot(&fn, &envRoot);
    for (NSString *r in rel) {
        if (fn) {
            const char *cp = fn([r UTF8String]); // 官方用法：把越狱内绝对路径交给 jbroot() 换算
            if (cp && *cp) add([NSString stringWithUTF8String:cp]);
        }
        if (envRoot.length) add([envRoot stringByAppendingString:r]);
        add([@"/var/jb" stringByAppendingString:r]); // 经典 rootless
        add(r);                                          // 裸路径兜底
    }
    return list;
}

// 真实可写探测：建目录 + 写“进程/线程唯一”探针 + 回读比对 + 删除。
// 探针名带 pid+uuid，避免多进程/多线程并发时互相删除对方探针而误判不可写。
static BOOL bds_dirReallyWritable(NSString *dir) {
    if (!dir.length) return NO;
    NSFileManager *fm = NSFileManager.defaultManager;
    if (![fm fileExistsAtPath:dir]) {
        if (![fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil]) return NO;
    }
    NSString *probe = [dir stringByAppendingPathComponent:
        [NSString stringWithFormat:@".wprobe.%d.%@", (int)getpid(), NSUUID.UUID.UUIDString]];
    NSString *token = NSUUID.UUID.UUIDString;
    if (![token writeToFile:probe atomically:YES encoding:NSUTF8StringEncoding error:nil]) return NO;
    NSString *back = [NSString stringWithContentsOfFile:probe encoding:NSUTF8StringEncoding error:nil];
    [fm removeItemAtPath:probe error:nil];
    return [back isEqualToString:token];
}

// 选定一个“确实可写”的全局目录；都不可写返回 @""，由 configPath 回退沙盒 Documents。
static NSString *bds_globalConfigDir(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        for (NSString *dir in bds_globalConfigCandidates()) {
            if (bds_dirReallyWritable(dir)) { cached = dir; break; }
        }
        if (!cached) cached = @"";
    });
    return cached;
}

static NSString *configPath(void) {
    NSString *dir = bds_globalConfigDir();
    if (dir.length) return [dir stringByAppendingPathComponent:@"bdspoofer_config.plist"];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"bdspoofer_config.plist"];
}

// 随 dylib 同目录打包的种子配置（deb 在 DynamicLibraries，TrollFools 在 Frameworks），只读兜底。
static NSString *bds_bundledSeedPath(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            const char *img = _dyld_get_image_name(i);
            if (!img) continue;
            NSString *p = [NSString stringWithUTF8String:img];
            NSString *base = p.lastPathComponent.lowercaseString;
            if ([base containsString:@"bdsspoofer"] || [base containsString:@"bdsglobal"]) {
                NSString *sib = [[p stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"bdspoofer_config.plist"];
                if ([NSFileManager.defaultManager fileExistsAtPath:sib]) { cached = sib; return; }
            }
        }
        cached = [[NSBundle mainBundle] pathForResource:@"bdspoofer_config" ofType:@"plist"];
    });
    return cached;
}

// 双临界区：进程内 NSRecursiveLock 保证线程互斥；每次独立 fd + flock 保证跨进程互斥。
static NSRecursiveLock *bds_csLock(void) {
    static NSRecursiveLock *lock = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSRecursiveLock new]; });
    return lock;
}
static int bds_csFD = -1;      // 最外层持有的跨进程锁 fd
static int bds_csDepth = 0;    // 同线程嵌套深度
static volatile int g_csProcLockOK = 0;    // 最近一次是否真正拿到跨进程 flock
static volatile int g_csLockEverFailed = 0; // 粘性：本进程是否曾拿不到跨进程锁（防止后续成功掩盖初始化失败）

// flock 带 EINTR 重试。
static BOOL bds_flockLoop(int fd, int op) {
    int rc;
    do { rc = flock(fd, op); } while (rc != 0 && errno == EINTR);
    return rc == 0;
}
// 进入临界区：进程内递归锁（线程互斥、同线程可嵌套）+ 仅最外层申请一次跨进程 flock。
// 返回是否拿到跨进程锁；拿不到时调用方必须以磁盘最新值为准，不能假定已互斥。
static BOOL bds_beginCriticalSection(void) {
    [bds_csLock() lock];
    bds_csDepth++;
    if (bds_csDepth == 1) {
        bds_csFD = -1; g_csProcLockOK = 0;
        NSString *dir = bds_globalConfigDir();
        if (dir.length) {
            NSString *lockPath = [dir stringByAppendingPathComponent:@"config.lock"];
            // 阻塞 flock 偶发瞬时失败时重试 3 次（每次间隔 20ms），仍失败才记粘性失败。
            for (int attempt = 0; attempt < 3 && bds_csFD < 0; attempt++) {
                int fd = open([lockPath fileSystemRepresentation], O_CREAT | O_RDWR, 0666);
                if (fd >= 0) {
                    if (bds_flockLoop(fd, LOCK_EX)) { bds_csFD = fd; g_csProcLockOK = 1; }
                    else { close(fd); usleep(20000); }
                } else { usleep(20000); }
            }
            if (bds_csFD < 0) g_csLockEverFailed = 1;
        } else {
            g_csLockEverFailed = 1; // 没有共享目录，天然无法跨进程互斥
        }
    }
    return bds_csFD >= 0;
}
static void bds_endCriticalSection(void) {
    if (bds_csDepth > 0) {
        bds_csDepth--;
        if (bds_csDepth == 0 && bds_csFD >= 0) {
            bds_flockLoop(bds_csFD, LOCK_UN);
            close(bds_csFD);
            bds_csFD = -1;
        }
    }
    [bds_csLock() unlock];
}

// 单条白名单规则匹配：以 "." 或 "*" 结尾为前缀匹配，否则精确匹配。
static BOOL bds_ruleMatchesBundle(NSString *bundleID, NSString *rule) {
    if (![bundleID isKindOfClass:NSString.class] || ![rule isKindOfClass:NSString.class]) return NO;
    if (rule.length == 0) return NO;
    if ([rule hasSuffix:@"*"]) {
        NSString *prefix = [rule substringToIndex:rule.length - 1];
        return prefix.length ? [bundleID hasPrefix:prefix] : NO;
    }
    if ([rule hasSuffix:@"."]) return [bundleID hasPrefix:rule];
    return [bundleID isEqualToString:rule];
}

// 用显式规则集判定透传（constructor 早期 g_config 尚未加载时也能用）。
// 注意：系统 App 与用户白名单“无条件”透传，不受 globalMode 影响，任何情况下都不 hook。
static BOOL bds_passthroughWithRules(NSString *bundleID, id rules) {
    if (![bundleID isKindOfClass:NSString.class] || bundleID.length == 0) return NO;
    if ([bundleID hasPrefix:@"com.apple."]) return YES;
    if (![rules isKindOfClass:[NSArray class]]) {
        rules = BDSDefaultConfig()[@"passthroughBundles"];
    }
    for (NSString *rule in (NSArray *)rules) {
        if (bds_ruleMatchesBundle(bundleID, rule)) return YES;
    }
    return NO;
}

// 正式加载配置后使用 g_config 中的规则判定。
static BOOL bds_isPassthroughBundle(NSString *bundleID) {
    return bds_passthroughWithRules(bundleID, g_config[@"passthroughBundles"]);
}

// 早期透传只读：在候选路径中找“已存在且可读”的全局配置，绝不建目录、绝不写探针，保证白名单零写入。
// 候选顺序与正式可写解析一致；稳态下写入方(Mango)落在首个可写目录，读取方也在该目录最先命中。
static NSString *bds_existingGlobalConfigReadOnly(void) {
    NSFileManager *fm = NSFileManager.defaultManager;
    BOOL isDir = NO;
    for (NSString *dir in bds_globalConfigCandidates()) {
        // 与正式写入方相同优先级：目录必须“已存在且可写”（只判断，绝不创建/写探针），
        // 避免读到前面候选里的只读旧配置、而写入落在后面候选导致的分叉。
        if (![fm fileExistsAtPath:dir isDirectory:&isDir] || !isDir) continue;
        if (![fm isWritableFileAtPath:dir]) continue;
        NSString *f = [dir stringByAppendingPathComponent:@"bdspoofer_config.plist"];
        if ([fm isReadableFileAtPath:f]) return f;
    }
    return nil;
}
static NSDictionary *bds_readOnlyGlobalConfig(void) {
    NSString *p = bds_existingGlobalConfigReadOnly();
    NSDictionary *d = p ? [NSDictionary dictionaryWithContentsOfFile:p] : nil;
    return [d isKindOfClass:[NSDictionary class]] ? d : BDSDefaultConfig();
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

static BOOL BDSHasEnabledCHookFeature(void) {
    return cfgBool(@"spoofSysctl", NO) ||
           cfgBool(@"spoofKeychain", NO) ||
           cfgBool(@"bypassJailbreakDetect", NO) ||
           cfgBool(@"spoofWiFi", NO) ||
           cfgBool(@"spoofLocalIP", NO) ||
           cfgBool(@"spoofBootTime", NO) ||
           cfgBool(@"spoofCPU", NO) ||
           cfgBool(@"spoofProxyDetection", NO) ||
           cfgBool(@"spoofStatfs", NO) ||
           cfgBool(@"spoofDlopen", NO);
}

static void bds_update_c_cache(void) {
    NSString *v;
    v = cfgStr(@"hwMachine", @"iPhone14,6");
    snprintf(g_hwMachine, sizeof(g_hwMachine), "%s", v.UTF8String);
    v = cfgStr(@"hwModel", @"D49AP");
    snprintf(g_hwModel, sizeof(g_hwModel), "%s", v.UTF8String);
    v = cfgStr(@"kernOSVersion", @"19E258");
    snprintf(g_kernOSVersion, sizeof(g_kernOSVersion), "%s", v.UTF8String);
    v = cfgStr(@"kernHostname", @"iPhone");
    snprintf(g_kernHostname, sizeof(g_kernHostname), "%s", v.UTF8String);
    v = cfgStr(@"wifiSSID", @"");
    const char *wifiUTF8 = v.UTF8String;
    size_t wifiLength = wifiUTF8 ? strlen(wifiUTF8) : 0;
    if (!wifiUTF8 || wifiLength >= sizeof(g_wifiSSID)) {
        g_wifiSSID[0] = '\0';
    } else {
        memcpy(g_wifiSSID, wifiUTF8, wifiLength + 1);
    }
    bds_disk_size_set((long long)cfgInt(@"diskSize", 64) * 1024LL * 1024LL * 1024LL);
}

static void loadConfig() {
    NSString *p1 = configPath();
    BOOL needsProcessLock = bds_globalConfigDir().length > 0;
    BOOL bdsGotLock = bds_beginCriticalSection();
    @try {
    // 锁内重新读取磁盘：另一进程若已抢先生成，直接采用同一身份，杜绝并发首启各自随机。
    NSString *bdsSeed = bds_bundledSeedPath();
    NSString *bdsExisting = [[NSFileManager defaultManager] fileExistsAtPath:p1] ? p1 : bdsSeed;
    NSDictionary *loaded = bdsExisting ? [NSDictionary dictionaryWithContentsOfFile:bdsExisting] : nil;
    NSMutableDictionary *merged = [BDSDefaultConfig() mutableCopy];
    if (loaded) [merged addEntriesFromDictionary:loaded];

    // 共享目录存在但 flock 失败：禁止迁移和写盘。只采用完整、已迁移的磁盘配置；
    // 磁盘缺失或残缺时保持安全默认值，避免无锁生成身份或采用 configVersion 高但缺键的配置。
    if (needsProcessLock && !bdsGotLock) {
        NSDictionary *diskOnly = [NSDictionary dictionaryWithContentsOfFile:p1];
        if (bds_isCompleteSharedConfig(diskOnly)) {
            [merged removeAllObjects];
            [merged addEntriesFromDictionary:BDSDefaultConfig()];
            [merged addEntriesFromDictionary:diskOnly];
        } else {
            [merged removeAllObjects];
            [merged addEntriesFromDictionary:BDSDefaultConfig()];
        }
        g_config = [merged copy];
        bds_update_c_cache();
        return;
    }

    NSInteger ver = [loaded[@"configVersion"] integerValue];
    // 当前 1.9.x 配置若自报 190 但关键字段不完整，按 1.8.1 基线重新执行 1.9.0 补齐迁移。
    // 仅处理已知版本 190，避免擅自降级未来更高版本的配置。
    if (ver == 190 && !bds_isCompleteSharedConfig(loaded)) ver = 181;
    if (ver < 150) {
        [merged addEntriesFromDictionary:@{
            @"configVersion": @150,
            @"enabled": @YES,
            @"spoofBaiduSDK": @YES,
            @"spoofSysctl": @NO,
            @"spoofKeychain": @YES,
            @"spoofUserAgent": @YES,
            @"bypassJailbreakDetect": @YES
        }];
    }
    if (ver < 160) {
        [merged addEntriesFromDictionary:@{
            @"configVersion": @160,
            @"spoofSysctl": @YES,
            @"systemVersion": @"15.7.1",
            @"systemBuild": @"19H117",
            @"hwMachine": @"iPhone10,1",
            @"hwModel": @"D20AP",
            @"kernOSVersion": @"19H117",
            @"screenWidth": @375,
            @"screenHeight": @667,
            @"screenScale": @2,
            @"memorySize": @2048,
            @"diskSize": @64
        }];
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 161) {
        // 1.6.1 只迁移基础功能开关；高级功能保持 1.6.0 的已有状态。
        [merged addEntriesFromDictionary:@{
            @"configVersion": @161,
            @"enabled": @YES,
            @"spoofAdvertisingIdentifiers": @YES,
            @"spoofProcessHardware": @YES,
            @"spoofLocale": @YES,
            @"spoofCarrier": @YES,
            @"spoofScreen": @NO,
            @"spoofStorage": @YES
        }];
        if (!loaded[@"nativeScreenWidth"]) merged[@"nativeScreenWidth"] = @750;
        if (!loaded[@"nativeScreenHeight"]) merged[@"nativeScreenHeight"] = @1334;
        if (!loaded[@"deviceProfileName"]) merged[@"deviceProfileName"] = @"iPhone 8";
        // 修正旧默认值中 15.7.1 与 15.7.3 Build 混用的问题，不覆盖用户自定义组合。
        if ([merged[@"systemVersion"] isEqualToString:@"15.7.1"] &&
            [merged[@"systemBuild"] isEqualToString:@"19H307"]) {
            merged[@"systemBuild"] = @"19H117";
            if ([merged[@"kernOSVersion"] isEqualToString:@"19H307"]) {
                merged[@"kernOSVersion"] = @"19H117";
            }
        }
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 162) {
        // UIScreen 会直接影响真实界面布局；升级后默认关闭并保留本机屏幕。
        merged[@"configVersion"] = @162;
        merged[@"spoofScreen"] = @NO;
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 170) {
        merged[@"configVersion"] = @170;
        if (!loaded[@"floatingButtonSide"]) merged[@"floatingButtonSide"] = @"right";
        if (!loaded[@"floatingButtonYPermille"]) merged[@"floatingButtonYPermille"] = @520;
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 171) {
        // 1.7.1 仅增加内存中的诊断计数，不改变用户现有功能和参数。
        merged[@"configVersion"] = @171;
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 172) {
        // 1.7.2 迁移到一致性优先的默认值；保留其他现有参数。
        merged[@"configVersion"] = @172;
        merged[@"deviceRandomMode"] = @"compatible";
        merged[@"spoofKeychain"] = @NO;
        merged[@"spoofUserAgent"] = @NO;
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 173) {
        // 1.7.3 新功能默认开启；只补齐旧配置缺失的键，
        // 不覆盖用户已经明确保存的开关选择。
        merged[@"configVersion"] = @173;
        NSArray<NSString *> *newSwitches = @[
            @"spoofWiFi", @"spoofLocalIP", @"spoofAppGroup", @"spoofPasteboard",
            @"spoofBootTime", @"spoofCPU", @"spoofLocation", @"spoofProxyDetection"
        ];
        for (NSString *key in newSwitches) {
            if (!loaded[key]) merged[key] = @YES;
        }
        if (!loaded[@"wifiSSID"]) merged[@"wifiSSID"] = @"";
        if (!loaded[@"bootTimeOffsetSeconds"]) merged[@"bootTimeOffsetSeconds"] = @0;
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 178) {
        // 1.7.8 版本基线：包含 1.7.4 反关联增强第二批的默认开关
        merged[@"configVersion"] = @178;
        NSArray<NSString *> *newSwitches = @[
            @"spoofStatfs", @"spoofDlopen", @"spoofUbiquity",
            @"spoofPrivacyPermissions", @"spoofWebKitCookie", @"spoofBattery"
        ];
        for (NSString *key in newSwitches) {
            if (!loaded[key]) merged[key] = @YES;
        }
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 180) {
        // 1.8.0 合并机型随机池；旧的 compatible/extended 选择不再使用。
        merged[@"configVersion"] = @180;
        [merged removeObjectForKey:@"deviceRandomMode"];
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 181) {
        // 1.8.1：每个 App/Crane 数据容器首次升级时关闭基础和高级功能。
        // 已保存参数保持不变；基础随机只负责开启常规项，风险测试项继续手动控制。
        [merged addEntriesFromDictionary:@{
            @"configVersion": @181,
            @"enabled": @NO,
            @"spoofAdvertisingIdentifiers": @NO,
            @"spoofProcessHardware": @NO,
            @"spoofLocale": @NO,
            @"spoofCarrier": @NO,
            @"spoofScreen": @NO,
            @"spoofStorage": @NO,
            @"spoofBaiduSDK": @NO,
            @"spoofSysctl": @NO,
            @"spoofKeychain": @NO,
            @"spoofUserAgent": @NO,
            @"bypassJailbreakDetect": @NO,
            @"spoofWiFi": @NO,
            @"spoofLocalIP": @NO,
            @"spoofAppGroup": @NO,
            @"spoofPasteboard": @NO,
            @"spoofBootTime": @NO,
            @"spoofCPU": @NO,
            @"spoofLocation": @NO,
            @"spoofProxyDetection": @NO,
            @"spoofStatfs": @NO,
            @"spoofDlopen": @NO,
            @"spoofUbiquity": @NO,
            @"spoofPrivacyPermissions": @NO,
            @"spoofWebKitCookie": @NO,
            @"spoofBattery": @NO
        }];
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 190) {
        // 1.9.0 全局伪装基线（芒果 CPA）：
        // 全新全局配置首次生成时所有伪装开关默认开启；旧配置已保存的选择不覆盖。
        merged[@"configVersion"] = @190;
        merged[@"globalMode"] = @YES;
        merged[@"spoofDipfy"] = @YES;
        NSArray<NSString *> *allOn = @[
            @"enabled", @"spoofAdvertisingIdentifiers", @"spoofProcessHardware", @"spoofLocale",
            @"spoofCarrier", @"spoofStorage", @"spoofBaiduSDK", @"spoofSysctl", @"spoofKeychain",
            @"spoofUserAgent", @"bypassJailbreakDetect", @"spoofWiFi", @"spoofLocalIP",
            @"spoofAppGroup", @"spoofPasteboard", @"spoofBootTime", @"spoofCPU", @"spoofLocation",
            @"spoofProxyDetection", @"spoofStatfs", @"spoofDlopen", @"spoofUbiquity",
            @"spoofPrivacyPermissions", @"spoofWebKitCookie", @"spoofBattery"
        ];
        for (NSString *k in allOn) {
            if (!loaded[k]) merged[k] = @YES;
        }
        // 屏幕保持真机物理尺寸，避免 UIScreen hook 导致界面缩放。
        if (!loaded[@"spoofScreen"]) merged[@"spoofScreen"] = @NO;
        if (!loaded[@"passthroughBundles"]) {
            merged[@"passthroughBundles"] = BDSDefaultConfig()[@"passthroughBundles"];
        }
        NSString *(^bdsHex)(NSUInteger) = ^(NSUInteger n) {
            return [[[NSUUID.UUID.UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""]
                     substringToIndex:n] uppercaseString];
        };
        if (![merged[@"identityId"] isKindOfClass:NSString.class] || [merged[@"identityId"] length] == 0)
            merged[@"identityId"] = [bdsHex(12) lowercaseString];
        if (![merged[@"dipfyDeviceKey"] isKindOfClass:NSString.class] || [merged[@"dipfyDeviceKey"] length] == 0)
            merged[@"dipfyDeviceKey"] = bdsHex(32);
        if (![merged[@"dipfyFakeUUID"] isKindOfClass:NSString.class] || [merged[@"dipfyFakeUUID"] length] == 0)
            merged[@"dipfyFakeUUID"] = NSUUID.UUID.UUIDString.uppercaseString;
        if (![merged[@"idfa"] isKindOfClass:NSString.class] || [merged[@"idfa"] length] == 0)
            merged[@"idfa"] = NSUUID.UUID.UUIDString.uppercaseString;
        if (![merged[@"idfv"] isKindOfClass:NSString.class] || [merged[@"idfv"] length] == 0)
            merged[@"idfv"] = NSUUID.UUID.UUIDString.uppercaseString;
        if (![merged[@"macAddress"] isKindOfClass:NSString.class] || [merged[@"macAddress"] length] == 0) {
            merged[@"macAddress"] = [NSString stringWithFormat:@"%02X:%02X:%02X:%02X:%02X:%02X",
                (unsigned)arc4random_uniform(256), (unsigned)arc4random_uniform(256),
                (unsigned)arc4random_uniform(256), (unsigned)arc4random_uniform(256),
                (unsigned)arc4random_uniform(256), (unsigned)arc4random_uniform(256)];
        }
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 196) {
        // 1.9.6 换号持久标识清理：补齐新键，默认换身份即挂一次性清理。
        merged[@"configVersion"] = @196;
        if (!loaded[@"autoWipeOnRotate"]) merged[@"autoWipeOnRotate"] = @YES;
        if (!loaded[@"wipePersistenceOnNextLaunch"]) merged[@"wipePersistenceOnNextLaunch"] = @NO;
        if (!loaded[@"lastWipeAt"]) merged[@"lastWipeAt"] = @0;
        if (!loaded[@"lastWipeReport"]) merged[@"lastWipeReport"] = @"";
        [merged writeToFile:p1 atomically:YES];
    }
    g_config = [merged copy];
    bds_update_c_cache();
    } @finally { bds_endCriticalSection(); }
}

static BOOL saveConfigValues(NSDictionary *values) {
    if (!values.count) return NO;
    NSString *p = configPath();
    BOOL needsProcessLock = bds_globalConfigDir().length > 0;
    // 双临界区内“读磁盘最新(读不到则用内存完整配置兜底，绝不从空字典写残缺) → 叠加 → 写回 → 同步内存”。
    BOOL bdsGotLock = bds_beginCriticalSection();
    BOOL saved = NO;
    @try {
    if (needsProcessLock && !bdsGotLock) {
        // 共享配置禁止无锁覆盖；调用方收到 NO 后可提示用户重试。
        saved = NO;
    } else {
    NSDictionary *disk = [NSDictionary dictionaryWithContentsOfFile:p];
    // 只有完整磁盘配置才能作为合并基底；磁盘残缺时使用完整内存配置。
    // 两者都不完整则拒绝写入，避免把少量 values 持久化成新的残缺 plist。
    NSDictionary *base = bds_isCompleteSharedConfig(disk) ? disk
                       : (bds_isCompleteSharedConfig(g_config) ? g_config : nil);
    if (base) {
        NSMutableDictionary *next = [base mutableCopy];
        // 只叠加本次要改的键；不用旧 g_config 整体覆盖正常的磁盘最新值。
        [next addEntriesFromDictionary:values];
        saved = [next writeToFile:p atomically:YES];
        if (saved) {
        // g_config 与 C 缓存必须在临界区内更新，避免两线程交错时较早的保存最后把内存回退成旧值。
        g_config = [next copy];
        bds_update_c_cache();
        // C 层 Hook 属于高级功能，不能被基础总开关 enabled 一并关闭。
        BDS_ATOMIC_SET(g_enabledC, BDSHasEnabledCHookFeature() ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofSysctlC, cfgBool(@"spoofSysctl", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_bypassJailbreakC, cfgBool(@"bypassJailbreakDetect", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofWiFiC, cfgBool(@"spoofWiFi", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofLocalIPC, cfgBool(@"spoofLocalIP", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofProxyC, cfgBool(@"spoofProxyDetection", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofBootTimeC, cfgBool(@"spoofBootTime", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofCPUC, cfgBool(@"spoofCPU", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofStatfsC, cfgBool(@"spoofStatfs", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofDlopenC, cfgBool(@"spoofDlopen", NO) ? 1 : 0);
        }
    }
    }
    } @finally { bds_endCriticalSection(); }
    return saved;
}

#pragma mark - 1.7.1 只读诊断计数

typedef NS_ENUM(int, BDSDiagState) {
    BDSDiagStateNever = 0,
    BDSDiagStatePassed = 1,
    BDSDiagStateChanged = 2,
    BDSDiagStateBlocked = 3
};

typedef struct {
    volatile uint64_t hits;
    volatile uint64_t passed;
    volatile uint64_t changed;
    volatile uint64_t blocked;
    volatile int lastState;
} BDSDiagCounter;

static BDSDiagCounter g_diagUIDevice;
static BDSDiagCounter g_diagIDFV;
static BDSDiagCounter g_diagAdvertising;
static BDSDiagCounter g_diagProcess;
static BDSDiagCounter g_diagLocaleCarrier;
static BDSDiagCounter g_diagScreenStorage;
static BDSDiagCounter g_diagBaiduSDK;
static BDSDiagCounter g_diagSysctl;
static BDSDiagCounter g_diagKeychain;
static BDSDiagCounter g_diagUserAgent;
static BDSDiagCounter g_diagDyld;
static BDSDiagCounter g_diagCFiles;
static BDSDiagCounter g_diagObjCJailbreak;
static BDSDiagCounter g_diagBundles;
static BDSDiagCounter g_diagWiFi;
static BDSDiagCounter g_diagLocalIP;
static BDSDiagCounter g_diagAppGroup;
static BDSDiagCounter g_diagPasteboard;
static BDSDiagCounter g_diagBootTime;
static BDSDiagCounter g_diagCPU;
static BDSDiagCounter g_diagLocation;
static BDSDiagCounter g_diagProxy;
static BDSDiagCounter g_diagStatfs;
static BDSDiagCounter g_diagDlopen;
static BDSDiagCounter g_diagUbiquity;
static BDSDiagCounter g_diagPrivacy;
static BDSDiagCounter g_diagWebKitCookie;
static BDSDiagCounter g_diagBattery;

#define BDS_DIAG_RECORD(counter, state) do { \
    __atomic_fetch_add(&(counter).hits, 1, __ATOMIC_RELAXED); \
    if ((state) == BDSDiagStatePassed) { \
        __atomic_fetch_add(&(counter).passed, 1, __ATOMIC_RELAXED); \
    } else if ((state) == BDSDiagStateBlocked) { \
        __atomic_fetch_add(&(counter).blocked, 1, __ATOMIC_RELAXED); \
    } else { \
        __atomic_fetch_add(&(counter).changed, 1, __ATOMIC_RELAXED); \
    } \
    __atomic_store_n(&(counter).lastState, (int)(state), __ATOMIC_RELAXED); \
} while (0)

static uint64_t bds_diag_load64(volatile uint64_t *value) {
    return __atomic_load_n(value, __ATOMIC_RELAXED);
}

static int bds_diag_load_state(volatile int *value) {
    return __atomic_load_n(value, __ATOMIC_RELAXED);
}

static void bds_diag_reset_counter(BDSDiagCounter *counter) {
    __atomic_store_n(&counter->hits, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&counter->passed, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&counter->changed, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&counter->blocked, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&counter->lastState, BDSDiagStateNever, __ATOMIC_RELAXED);
}

static void bds_diag_reset_all(void) {
    BDSDiagCounter *counters[] = {
        &g_diagUIDevice, &g_diagIDFV, &g_diagAdvertising, &g_diagProcess,
        &g_diagLocaleCarrier, &g_diagScreenStorage, &g_diagBaiduSDK,
        &g_diagSysctl, &g_diagKeychain, &g_diagUserAgent, &g_diagDyld,
        &g_diagCFiles, &g_diagObjCJailbreak, &g_diagBundles,
        &g_diagWiFi, &g_diagLocalIP, &g_diagAppGroup, &g_diagPasteboard,
        &g_diagBootTime, &g_diagCPU, &g_diagLocation, &g_diagProxy,
        &g_diagStatfs, &g_diagDlopen, &g_diagUbiquity, &g_diagPrivacy,
        &g_diagWebKitCookie,
        &g_diagBattery
    };
    for (size_t i = 0; i < sizeof(counters) / sizeof(counters[0]); i++) {
        bds_diag_reset_counter(counters[i]);
    }
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

#pragma mark - fishhook（内嵌，GOT 符号重绑定）
// fishhook 通过修改各 image 的 __la_symbol_ptr / __nl_symbol_ptr 中的指针来 hook C 函数。
// 原始地址保存在 rebinding.replaced 中，直接指向 libSystem 真实实现，
// 调用原始函数不经过 GOT，因此结构上不可能出现 DYLD_INTERPOSE + dlsym 的递归问题。

// 架构类型定义（标准 fishhook 的 __LP64__ 类型块）
#ifdef __LP64__
typedef struct mach_header_64 bds_mach_header_t;
typedef struct segment_command_64 bds_segment_command_t;
typedef struct section_64 bds_section_t;
typedef struct nlist_64 bds_nlist_t;
#define BDS_LC_SEGMENT LC_SEGMENT_64
#else
typedef struct mach_header bds_mach_header_t;
typedef struct segment_command bds_segment_command_t;
typedef struct section bds_section_t;
typedef struct nlist bds_nlist_t;
#define BDS_LC_SEGMENT LC_SEGMENT
#endif

// SEG_DATA_CONST 在旧版 SDK 中未定义（官方 fishhook 同样做此兼容）
#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif

struct bds_rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct bds_rebindings_entry {
    struct bds_rebinding *rebindings;
    size_t rebindings_nel;
    struct bds_rebindings_entry *next;
};

static struct bds_rebindings_entry *bds_rebindings_head = NULL;

static int bds_prepend_rebindings(struct bds_rebindings_entry **head,
                                  struct bds_rebinding rebindings[],
                                  size_t nel) {
    struct bds_rebindings_entry *new_entry =
        (struct bds_rebindings_entry *)malloc(sizeof(struct bds_rebindings_entry));
    if (!new_entry) return -1;
    new_entry->rebindings =
        (struct bds_rebinding *)malloc(sizeof(struct bds_rebinding) * nel);
    if (!new_entry->rebindings) { free(new_entry); return -1; }
    memcpy(new_entry->rebindings, rebindings, sizeof(struct bds_rebinding) * nel);
    new_entry->rebindings_nel = nel;
    new_entry->next = *head;
    *head = new_entry;
    return 0;
}

static void bds_perform_rebinding_with_section(struct bds_rebindings_entry *rebindings,
                                               bds_section_t *section,
                                               intptr_t slide,
                                               bds_nlist_t *symtab,
                                               char *strtab,
                                               uint32_t *indirect_symtab,
                                               uint32_t nindirectsyms) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    uint32_t pointer_count = (uint32_t)(section->size / sizeof(void *));

    // 越界保护：reserved1 + 指针数不能超过间接符号表大小
    if (section->reserved1 >= nindirectsyms ||
        pointer_count > nindirectsyms - section->reserved1) {
        return;
    }

    int protected_region = 0;  // 延迟 vm_protect：找到匹配符号后才解除写保护

    for (uint i = 0; i < pointer_count; i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        if (!symbol_name[0] || !symbol_name[1]) continue;
        struct bds_rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    // 延迟到真正需要写入时才解除该 GOT 区域的写保护
                    if (!protected_region) {
                        kern_return_t vr = vm_protect(mach_task_self(),
                            (vm_address_t)indirect_symbol_bindings,
                            (vm_size_t)section->size, NO,
                            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        if (vr != KERN_SUCCESS) return;  // 写保护解除失败，跳过整个节
                        protected_region = 1;
                    }
                    if (cur->rebindings[j].replaced != NULL &&
                        indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    goto bds_symbol_loop;
                }
            }
            cur = cur->next;
        }
    bds_symbol_loop:;
    }
}

static void bds_rebind_symbols_for_image(struct bds_rebindings_entry *rebindings,
                                         const struct mach_header *header,
                                         intptr_t slide) {
    if (header->magic != MH_MAGIC_64 && header->magic != MH_MAGIC) return;

    bds_segment_command_t *cur_seg_cmd;
    bds_segment_command_t *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(bds_mach_header_t);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (bds_segment_command_t *)cur;
        if (cur_seg_cmd->cmd == BDS_LC_SEGMENT) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment) return;
    if (dysymtab_cmd->nindirectsyms == 0) return;

    uintptr_t linkedit_base =
        (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    bds_nlist_t *symtab = (bds_nlist_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab =
        (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(bds_mach_header_t);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (bds_segment_command_t *)cur;
        if (cur_seg_cmd->cmd == BDS_LC_SEGMENT) {
            // 只扫描 __DATA 和 __DATA_CONST（官方 fishhook 同样如此）。
            // 不扫描 __AUTH/__AUTH_CONST：arm64e 上这些段的 GOT 指针带 PAC 签名，
            // 直接写入未签名指针会在调用时触发认证失败崩溃。
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
                strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
                continue;
            }
            for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
                bds_section_t *sect =
                    (bds_section_t *)(cur + sizeof(bds_segment_command_t)) + j;
                uint8_t sect_type = sect->flags & SECTION_TYPE;
                if (sect_type == S_LAZY_SYMBOL_POINTERS ||
                    sect_type == S_NON_LAZY_SYMBOL_POINTERS) {
                    bds_perform_rebinding_with_section(rebindings, sect, slide,
                                                       symtab, strtab, indirect_symtab,
                                                       dysymtab_cmd->nindirectsyms);
                }
            }
        }
    }
}

static void bds_rebind_symbols_for_image_cb(const struct mach_header *mh, intptr_t slide) {
    bds_rebind_symbols_for_image(bds_rebindings_head, mh, slide);
}

static int bds_rebind_symbols(struct bds_rebinding rebindings[], size_t nel) {
    int retval = bds_prepend_rebindings(&bds_rebindings_head, rebindings, nel);
    if (retval < 0) return retval;
    if (bds_rebindings_head->next == NULL) {
        // 第一次调用：注册 dyld 回调，回调会立即对所有已加载 image 执行 rebind
        _dyld_register_func_for_add_image(bds_rebind_symbols_for_image_cb);
    } else {
        // 后续调用：手动对已加载 image 执行 rebind
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            bds_rebind_symbols_for_image(bds_rebindings_head,
                                         _dyld_get_image_header(i),
                                         _dyld_get_image_vmaddr_slide(i));
        }
    }
    return retval;
}

#pragma mark - 统一越狱路径表（C 数组）

static const char *bds_jailbreak_path_strings[] = {
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Library/MobileSubstrate",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/sbin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/usr/bin/sshd",
    "/usr/bin/cycript",
    "/usr/lib/libsubstrate.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libellekit.dylib",
    "/usr/lib/TweakInject",
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/ssh",
    "/var/jb",
    "/var/jb/Library",
    "/var/jb/basebin",
    "/var/jb/usr/lib/TweakInject",
    "/.bootstrapped_electra",
    "/.cydia_no_stash",
    "/.installed_unc0ver",
    "/jb",
    "/var/LIY",
    "/var/Memory.me",
    "/var/checkra1n.dmg",
    NULL
};

static int bds_c_is_jailbreak_path(const char *path) {
    if (!path) return 0;
    for (int i = 0; bds_jailbreak_path_strings[i]; i++) {
        const char *p = bds_jailbreak_path_strings[i];
        size_t len = strlen(p);
        if (strcmp(path, p) == 0) return 1;
        if (strncmp(path, p, len) == 0 && path[len] == '/') return 1;
    }
    return 0;
}

#pragma mark - UIDevice Hook

static IMP orig_systemVersion = NULL;
static NSString *new_systemVersion(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagUIDevice, BDSDiagStateChanged);
    return cfgStr(@"systemVersion", @"15.4.1");
}

static IMP orig_model = NULL;
static NSString *new_model(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagUIDevice, BDSDiagStateChanged);
    return cfgStr(@"deviceModel", @"iPhone");
}

static IMP orig_localizedModel = NULL;
static NSString *new_localizedModel(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagUIDevice, BDSDiagStateChanged);
    return cfgStr(@"marketingModel", @"iPhone");
}

static IMP orig_name = NULL;
static NSString *new_name(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagUIDevice, BDSDiagStateChanged);
    return cfgStr(@"deviceName", @"iPhone");
}

static IMP orig_systemName = NULL;
static NSString *new_systemName(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagUIDevice, BDSDiagStateChanged);
    return @"iOS";
}

#pragma mark - 电池电量伪装

static volatile float g_fakeBatteryLevel = -1.0f;
static dispatch_once_t g_batteryOnce;
static IMP orig_batteryLevel = NULL;
static float new_batteryLevel(id self, SEL _cmd) {
    if (!cfgBool(@"spoofBattery", NO)) {
        typedef float (*BatteryLevelIMP)(id, SEL);
        if (orig_batteryLevel) return ((BatteryLevelIMP)orig_batteryLevel)(self, _cmd);
        return -1.0f;
    }
    BDS_DIAG_RECORD(g_diagBattery, BDSDiagStateChanged);
    dispatch_once(&g_batteryOnce, ^{
        g_fakeBatteryLevel = 0.30f + (float)(arc4random_uniform(56)) / 100.0f;
    });
    return g_fakeBatteryLevel;
}

static IMP orig_batteryState = NULL;
static NSInteger new_batteryState(id self, SEL _cmd) {
    if (!cfgBool(@"spoofBattery", NO)) {
        typedef NSInteger (*BatteryStateIMP)(id, SEL);
        if (orig_batteryState) return ((BatteryStateIMP)orig_batteryState)(self, _cmd);
        return 0;
    }
    BDS_DIAG_RECORD(g_diagBattery, BDSDiagStateChanged);
    return 1; // UIDeviceBatteryStateUnplugged
}

static IMP orig_identifierForVendor = NULL;
static NSUUID *new_identifierForVendor(id self, SEL _cmd) {
    NSString *uuid = cfgStr(@"idfv", @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
    NSUUID *value = [[NSUUID alloc] initWithUUIDString:uuid];
    if (value) {
        BDS_DIAG_RECORD(g_diagIDFV, BDSDiagStateChanged);
        return value;
    }
    BDS_DIAG_RECORD(g_diagIDFV, BDSDiagStatePassed);
    if (orig_identifierForVendor) {
        return ((NSUUID *(*)(id, SEL))orig_identifierForVendor)(self, _cmd);
    }
    return nil;
}

#pragma mark - ASIdentifierManager Hook

static IMP orig_advertisingIdentifier = NULL;

static NSInteger bds_realTrackingAuthorizationStatus(void) {
    Class cls = objc_getClass("ATTrackingManager");
    SEL sel = NSSelectorFromString(@"trackingAuthorizationStatus");
    Method method = cls ? class_getClassMethod(cls, sel) : NULL;
    if (!method) return -1;
    IMP imp = method_getImplementation(method);
    return imp ? ((NSInteger (*)(id, SEL))imp)(cls, sel) : -1;
}

static BOOL bds_realAdvertisingTrackingEnabled(id manager) {
    NSInteger status = bds_realTrackingAuthorizationStatus();
    if (status >= 0) return status == 3; // ATTrackingManagerAuthorizationStatusAuthorized
    SEL sel = @selector(isAdvertisingTrackingEnabled);
    Method method = class_getInstanceMethod([manager class], sel);
    IMP imp = method ? method_getImplementation(method) : NULL;
    return imp ? ((BOOL (*)(id, SEL))imp)(manager, sel) : NO;
}

static NSUUID *new_advertisingIdentifier(id self, SEL _cmd) {
    NSUUID *original = orig_advertisingIdentifier
        ? ((NSUUID *(*)(id, SEL))orig_advertisingIdentifier)(self, _cmd) : nil;
    NSUUID *value = nil;
    if (bds_realAdvertisingTrackingEnabled(self)) {
        NSString *uuid = cfgStr(@"idfa", @"FEDCBA98-7654-3210-FEDC-BA9876543210");
        value = [[NSUUID alloc] initWithUUIDString:uuid] ?: original;
    } else {
        value = [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
    }
    BOOL changed = original ? ![value isEqual:original] : value != nil;
    BDS_DIAG_RECORD(g_diagAdvertising, changed ? BDSDiagStateChanged : BDSDiagStatePassed);
    return value;
}

// ATT 和“广告跟踪已开启”保持系统真实状态，不再 hook。

#pragma mark - NSProcessInfo Hook

static IMP orig_operatingSystemVersionString = NULL;
static NSString *new_operatingSystemVersionString(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagProcess, BDSDiagStateChanged);
    NSString *v = cfgStr(@"systemVersion", @"15.4.1");
    NSString *b = cfgStr(@"systemBuild", @"19E258");
    return [NSString stringWithFormat:@"Version %@ (Build %@)", v, b];
}

static IMP orig_operatingSystemVersion = NULL;
static NSOperatingSystemVersion new_operatingSystemVersion(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagProcess, BDSDiagStateChanged);
    NSOperatingSystemVersion v = {15, 7, 1};
    NSString *s = cfgStr(@"systemVersion", @"15.4.1");
    NSArray *p = [s componentsSeparatedByString:@"."];
    if (p.count >= 1) v.majorVersion = [p[0] integerValue];
    if (p.count >= 2) v.minorVersion = [p[1] integerValue];
    if (p.count >= 3) v.patchVersion = [p[2] integerValue];
    return v;
}

static IMP orig_hostName = NULL;
static NSString *new_hostName(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagProcess, BDSDiagStateChanged);
    return cfgStr(@"kernHostname", @"iPhone");
}

static IMP orig_physicalMemory = NULL;
static unsigned long long new_physicalMemory(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagProcess, BDSDiagStateChanged);
    return (unsigned long long)cfgInt(@"memorySize", 4096) * 1024 * 1024;
}

#pragma mark - NSLocale Hook

static IMP orig_localeIdentifier = NULL;
static NSString *new_localeIdentifier(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagLocaleCarrier, BDSDiagStateChanged);
    return cfgStr(@"localeIdentifier", @"zh_CN");
}

#pragma mark - CTTelephonyNetworkInfo / CTCarrier Hook

static IMP orig_subscriberCellularProvider = NULL;
static CTCarrier *new_subscriberCellularProvider(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagLocaleCarrier, BDSDiagStateChanged);
    CTCarrier *fake = [[CTCarrier alloc] init];
    return fake;
}

static IMP orig_serviceSubscriberCellularProviders = NULL;
static NSDictionary *new_serviceSubscriberCellularProviders(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagLocaleCarrier, BDSDiagStateChanged);
    CTCarrier *fake = [[CTCarrier alloc] init];
    return @{@"0000000100000001": fake};
}

static IMP orig_carrierName = NULL;
static NSString *new_carrierName(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagLocaleCarrier, BDSDiagStateChanged);
    return cfgStr(@"carrierName", @"中国移动");
}

static IMP orig_mobileCountryCode = NULL;
static NSString *new_mobileCountryCode(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagLocaleCarrier, BDSDiagStateChanged);
    return cfgStr(@"mcc", @"460");
}

static IMP orig_mobileNetworkCode = NULL;
static NSString *new_mobileNetworkCode(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagLocaleCarrier, BDSDiagStateChanged);
    return cfgStr(@"mnc", @"00");
}

static IMP orig_isoCountryCode = NULL;
static NSString *new_isoCountryCode(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagLocaleCarrier, BDSDiagStateChanged);
    return cfgStr(@"isoCountryCode", @"cn");
}

static IMP orig_allowsVOIP = NULL;
static BOOL new_allowsVOIP(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagLocaleCarrier, BDSDiagStateChanged);
    return YES;
}

#pragma mark - UIScreen Hook

static IMP orig_bounds = NULL;
static CGRect new_bounds(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagScreenStorage, BDSDiagStateChanged);
    CGFloat w = cfgInt(@"screenWidth", 375);
    CGFloat h = cfgInt(@"screenHeight", 667);
    return CGRectMake(0, 0, w, h);
}

static IMP orig_nativeBounds = NULL;
static CGRect new_nativeBounds(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagScreenStorage, BDSDiagStateChanged);
    CGFloat scale = (CGFloat)cfgInt(@"screenScale", 2);
    CGFloat w = (CGFloat)cfgInt(@"nativeScreenWidth",
                                cfgInt(@"screenWidth", 375) * scale);
    CGFloat h = (CGFloat)cfgInt(@"nativeScreenHeight",
                                cfgInt(@"screenHeight", 667) * scale);
    return CGRectMake(0, 0, w, h);
}

static IMP orig_scale = NULL;
static CGFloat new_scale(id self, SEL _cmd) {
    BDS_DIAG_RECORD(g_diagScreenStorage, BDSDiagStateChanged);
    return (CGFloat)cfgInt(@"screenScale", 2);
}

#pragma mark - NSFileManager Hook（磁盘大小）

static IMP orig_attributesOfFileSystemForPath = NULL;
static NSDictionary *new_attributesOfFileSystemForPath(id self, SEL _cmd, id path, NSError **error) {
    typedef NSDictionary *(*FileSystemAttributesIMP)(id, SEL, NSString *, NSError **);
    NSDictionary *orig = orig_attributesOfFileSystemForPath
        ? ((FileSystemAttributesIMP)orig_attributesOfFileSystemForPath)(self, _cmd, path, error)
        : nil;
    if (!orig) {
        BDS_DIAG_RECORD(g_diagScreenStorage, BDSDiagStatePassed);
        return orig;
    }
    BDS_DIAG_RECORD(g_diagScreenStorage, BDSDiagStateChanged);
    NSMutableDictionary *m = [orig mutableCopy];
    long long diskSize = cfgInt(@"diskSize", 64) * 1024LL * 1024LL * 1024LL;
    m[NSFileSystemSize] = @(diskSize);
    m[NSFileSystemFreeSize] = @(diskSize / 2);
    return m;
}

#pragma mark - 百度 SDK Hook

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

    if (!cfgBool(@"spoofBaiduSDK", NO)) {
        BDS_DIAG_RECORD(g_diagBaiduSDK, BDSDiagStatePassed);
        if (origValue) {
            IMP orig = [origValue pointerValue];
            return ((NSString *(*)(id, SEL))orig)(self, _cmd);
        }
        return nil;
    }

    if (origValue) {
        IMP orig = [origValue pointerValue];
        id result = ((id (*)(id, SEL))orig)(self, _cmd);
        if ([result isKindOfClass:[NSString class]]) {
            BDS_DIAG_RECORD(g_diagBaiduSDK, BDSDiagStateChanged);
            return bds_fake_value_for_cmd(_cmd);
        }
        BDS_DIAG_RECORD(g_diagBaiduSDK, BDSDiagStatePassed);
        return result;
    }
    BDS_DIAG_RECORD(g_diagBaiduSDK, BDSDiagStateChanged);
    return bds_fake_value_for_cmd(_cmd);
}

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

    if ([g_baiduHookedKeys containsObject:key]) {
        [g_baiduLock unlock];
        return;
    }

    Method m = isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m || !bds_isSafeSyncMethod(m)) {
        [g_baiduLock unlock];
        return;
    }

    Class targetCls = isClassMethod ? object_getClass(cls) : cls;
    IMP oldImp = class_replaceMethod(targetCls, sel, (IMP)new_baidu_string_sync,
                                     method_getTypeEncoding(m));
    if (!oldImp) {
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

static void bds_dyld_add_image_cb(const struct mach_header *mh, intptr_t vmaddr_slide) {
    (void)mh; (void)vmaddr_slide;
    bds_scanBaiduSDKClasses();
}

static void installBaiduSDKHooks(void) {
    bds_scanBaiduSDKClasses();
    _dyld_register_func_for_add_image(bds_dyld_add_image_cb);
}

#pragma mark - Dipfy（芒果安全 SDK）专属 Hook
// 只做两类、且都做签名校验，避免返回类型不符导致崩溃：
//  1) 安全检测布尔值（越狱/代理/USB）-> 一律 NO
//  2) Dipfy 自产、不经过系统 API 的设备标识字符串 -> 返回当前身份的稳定伪造值
// 机型/系统/内存等 DipfyCDevice 只是转调系统 API 的方法，已被底层 UIDevice/NSProcessInfo/sysctl hook 覆盖，不重复 hook。

static NSRecursiveLock *g_dipfyLock = nil;
static NSMutableDictionary<NSString *, NSValue *> *g_dipfyOrigImps = nil;
static NSMutableSet<NSString *> *g_dipfyHooked = nil;
static volatile uint64_t g_dipfyBoolHits = 0;
static volatile uint64_t g_dipfyStrHits = 0;

typedef NS_ENUM(int, BDSDipfyKind) {
    BDSDipfyBoolNoArg = 0,   // 无参 BOOL，返回 NO
    BDSDipfyBoolOneArg,      // 单参 BOOL，返回 NO
    BDSDipfyString           // 无参 NSString，返回伪造标识
};

static NSString *bds_dipfy_string_for_cmd(SEL _cmd) {
    NSString *s = NSStringFromSelector(_cmd).lowercaseString;
    if ([s containsString:@"devicename"]) return cfgStr(@"deviceName", @"iPhone");
    if ([s containsString:@"mac"]) return cfgStr(@"macAddress", @"02:00:00:00:00:00");
    if ([s containsString:@"idfv"] || [s containsString:@"identifierforvendor"])
        return cfgStr(@"idfv", @"");
    if ([s containsString:@"fakeuuid"] || [s containsString:@"uuid"] ||
        [s containsString:@"flowidentifier"])
        return cfgStr(@"dipfyFakeUUID", @"");
    if ([s containsString:@"devicekey"] || [s containsString:@"imei"] ||
        [s containsString:@"serial"] || [s containsString:@"deviceid"])
        return cfgStr(@"dipfyDeviceKey", @"");
    return nil;
}

static BOOL bds_dipfy_enabled(void) {
    return cfgBool(@"spoofDipfy", NO);
}

static BOOL new_dipfy_bool_noarg(id self, SEL _cmd) {
    __atomic_add_fetch(&g_dipfyBoolHits, 1, __ATOMIC_RELAXED);
    NSString *isC = object_isClass(self) ? @"C" : @"I";
    NSString *cls = object_isClass(self) ? NSStringFromClass(self) : NSStringFromClass([self class]);
    NSString *key = [NSString stringWithFormat:@"%@.%@.%@.B0", cls, NSStringFromSelector(_cmd), isC];
    NSValue *ov = nil;
    [g_dipfyLock lock]; ov = g_dipfyOrigImps[key]; [g_dipfyLock unlock];
    if (!bds_dipfy_enabled()) {
        if (ov) return ((BOOL (*)(id, SEL))[ov pointerValue])(self, _cmd);
        return NO;
    }
    return NO; // 越狱/代理等安全检测一律“未发现”
}

static BOOL new_dipfy_bool_onearg(id self, SEL _cmd, id arg) {
    __atomic_add_fetch(&g_dipfyBoolHits, 1, __ATOMIC_RELAXED);
    NSString *isC = object_isClass(self) ? @"C" : @"I";
    NSString *cls = object_isClass(self) ? NSStringFromClass(self) : NSStringFromClass([self class]);
    NSString *key = [NSString stringWithFormat:@"%@.%@.%@.B1", cls, NSStringFromSelector(_cmd), isC];
    NSValue *ov = nil;
    [g_dipfyLock lock]; ov = g_dipfyOrigImps[key]; [g_dipfyLock unlock];
    if (!bds_dipfy_enabled()) {
        if (ov) return ((BOOL (*)(id, SEL, id))[ov pointerValue])(self, _cmd, arg);
        return NO;
    }
    return NO; // isConnUsb: 一律“未连接调试”
}

static NSString *new_dipfy_string(id self, SEL _cmd) {
    __atomic_add_fetch(&g_dipfyStrHits, 1, __ATOMIC_RELAXED);
    NSString *isC = object_isClass(self) ? @"C" : @"I";
    NSString *cls = object_isClass(self) ? NSStringFromClass(self) : NSStringFromClass([self class]);
    NSString *key = [NSString stringWithFormat:@"%@.%@.%@.S", cls, NSStringFromSelector(_cmd), isC];
    NSValue *ov = nil;
    [g_dipfyLock lock]; ov = g_dipfyOrigImps[key]; [g_dipfyLock unlock];
    IMP orig = ov ? [ov pointerValue] : NULL;
    if (!bds_dipfy_enabled()) {
        if (orig) return ((NSString *(*)(id, SEL))orig)(self, _cmd);
        return nil;
    }
    // 先取原值，确认确实是字符串才替换，类型不符时原样返回，杜绝 ABI 崩溃。
    id original = orig ? ((id (*)(id, SEL))orig)(self, _cmd) : nil;
    if (original && ![original isKindOfClass:NSString.class]) return original;
    NSString *fake = bds_dipfy_string_for_cmd(_cmd);
    if (fake.length) return fake;
    return original;
}

static void bds_dipfy_try_method(Class cls, SEL sel, BDSDipfyKind kind, BOOL isClassMethod) {
    if (!cls) return;
    Method m = isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m) return;

    char ret[16] = {0};
    method_getReturnType(m, ret, sizeof(ret));
    unsigned nargs = method_getNumberOfArguments(m);
    BOOL sigOK = NO;
    IMP replacement = NULL;
    NSString *suffix = nil;
    switch (kind) {
        case BDSDipfyBoolNoArg:
            sigOK = (nargs == 2 && ret[0] == 'B');
            replacement = (IMP)new_dipfy_bool_noarg;
            suffix = @".B0";
            break;
        case BDSDipfyBoolOneArg: {
            // 替换函数把第三个参数当 id；必须校验其类型编码确为对象(@/@?)，否则标量/结构体会 ABI 不匹配崩溃。
            char argt[16] = {0};
            method_getArgumentType(m, 2, argt, sizeof(argt));
            sigOK = (nargs == 3 && ret[0] == 'B' && argt[0] == '@');
            replacement = (IMP)new_dipfy_bool_onearg;
            suffix = @".B1";
            break;
        }
        case BDSDipfyString:
            sigOK = (nargs == 2 && ret[0] == '@');
            replacement = (IMP)new_dipfy_string;
            suffix = @".S";
            break;
    }
    if (!sigOK || !replacement) return;

    NSString *className = NSStringFromClass(cls);
    NSString *tag = isClassMethod ? @"C" : @"I";
    NSString *hookKey = [NSString stringWithFormat:@"%@.%@.%@%@", className, NSStringFromSelector(sel), tag, suffix];

    [g_dipfyLock lock];
    if ([g_dipfyHooked containsObject:hookKey]) {
        [g_dipfyLock unlock];
        return;
    }
    Class targetCls = isClassMethod ? object_getClass(cls) : cls;
    IMP oldImp = class_replaceMethod(targetCls, sel, replacement, method_getTypeEncoding(m));
    if (!oldImp) oldImp = method_getImplementation(m);
    [g_dipfyOrigImps setObject:[NSValue valueWithPointer:oldImp] forKey:hookKey];
    [g_dipfyHooked addObject:hookKey];
    [g_dipfyLock unlock];
}

static void bds_dipfy_scan(void) {
    if (!g_dipfyLock) {
        g_dipfyLock = [[NSRecursiveLock alloc] init];
        g_dipfyOrigImps = [NSMutableDictionary dictionary];
        g_dipfyHooked = [NSMutableSet set];
    }
    NSArray<NSString *> *classes = @[
        @"DipfyCDevice", @"DipfyDevice", @"DipfyCInfo", @"DipfyCSecurity"
    ];
    NSArray<NSString *> *boolNoArg = @[
        @"hasJailBroken", @"hasJailbroken", @"isJailbroken", @"hasProxy", @"isProxy",
        @"isDebug", @"isSimulator"
    ];
    NSArray<NSString *> *boolOneArg = @[@"isConnUsb:"];
    NSArray<NSString *> *strings = @[
        @"deviceKey", @"deviceKeyNew", @"local_deviceKey",
        @"getFakeUUID", @"loadFakeUUID", @"fakeUUID", @"uuid", @"UUID",
        @"flowIdentifier", @"idfv", @"identifierForVendor", @"macAddress",
        @"sql_deviceid", @"sql_idfv", @"sql_IMEI", @"sql_serialId", @"sql_deviceName"
    ];
    for (NSString *className in classes) {
        Class cls = objc_getClass(className.UTF8String);
        if (!cls) continue;
        for (NSString *s in boolNoArg) {
            SEL sel = NSSelectorFromString(s);
            bds_dipfy_try_method(cls, sel, BDSDipfyBoolNoArg, YES);
            bds_dipfy_try_method(cls, sel, BDSDipfyBoolNoArg, NO);
        }
        for (NSString *s in boolOneArg) {
            SEL sel = NSSelectorFromString(s);
            bds_dipfy_try_method(cls, sel, BDSDipfyBoolOneArg, YES);
            bds_dipfy_try_method(cls, sel, BDSDipfyBoolOneArg, NO);
        }
        for (NSString *s in strings) {
            SEL sel = NSSelectorFromString(s);
            bds_dipfy_try_method(cls, sel, BDSDipfyString, YES);
            bds_dipfy_try_method(cls, sel, BDSDipfyString, NO);
        }
    }
}

static void bds_dipfy_add_image_cb(const struct mach_header *mh, intptr_t slide) {
    (void)mh; (void)slide;
    bds_dipfy_scan();
}

static void installDipfyHooks(void) {
    bds_dipfy_scan();
    _dyld_register_func_for_add_image(bds_dipfy_add_image_cb);
}

#pragma mark - sysctlbyname Hook（fishhook，纯 C）

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);

static int bds_my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                                void *newp, size_t newlen) {
    // 异常参数或写入操作直接透传
    if (!name || (oldp && !oldlenp) || newp) {
        BDS_DIAG_RECORD(g_diagSysctl, BDSDiagStatePassed);
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    if (!BDS_ATOMIC_GET(g_enabledC)) {
        BDS_DIAG_RECORD(g_diagSysctl, BDSDiagStatePassed);
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    // 原有 sysctl 字符串伪装受 spoofSysctl 控制；启动时间和 CPU 使用各自独立开关。
    const char *fakeStr = NULL;
    if (BDS_ATOMIC_GET(g_spoofSysctlC)) {
        if (strcmp(name, "hw.machine") == 0) {
            fakeStr = g_hwMachine;
        } else if (strcmp(name, "hw.model") == 0) {
            fakeStr = g_hwModel;
        } else if (strcmp(name, "kern.osversion") == 0) {
            fakeStr = g_kernOSVersion;
        } else if (strcmp(name, "kern.hostname") == 0) {
            fakeStr = g_kernHostname;
        }
    }

    if (fakeStr) {
        BDS_DIAG_RECORD(g_diagSysctl, BDSDiagStateChanged);
        size_t fakeLen = strlen(fakeStr) + 1;
        if (oldp == NULL) {
            if (oldlenp) *oldlenp = fakeLen;
            return 0;
        }
        if (*oldlenp < fakeLen) {
            *oldlenp = fakeLen;
            errno = ENOMEM;
            return -1;
        }
        memcpy(oldp, fakeStr, fakeLen);
        *oldlenp = fakeLen;
        return 0;
    }

    // kern.boottime（struct timeval，16 字节）
    if (BDS_ATOMIC_GET(g_spoofBootTimeC) && strcmp(name, "kern.boottime") == 0) {
        BDS_DIAG_RECORD(g_diagBootTime, BDSDiagStateChanged);
        size_t fakeLen = sizeof(struct timeval);
        if (oldp == NULL) {
            if (oldlenp) *oldlenp = fakeLen;
            return 0;
        }
        if (*oldlenp < fakeLen) {
            *oldlenp = fakeLen;
            errno = ENOMEM;
            return -1;
        }
        *(struct timeval *)oldp = g_fakeBootTime;
        *oldlenp = fakeLen;
        return 0;
    }

    // CPU 参数（int，4 字节）
    if (BDS_ATOMIC_GET(g_spoofCPUC)) {
        int fakeInt = 0;
        int isCPUKey = 0;
        if (strcmp(name, "hw.ncpu") == 0) {
            fakeInt = g_fakeNcpu; isCPUKey = 1;
        } else if (strcmp(name, "hw.activecpu") == 0) {
            fakeInt = g_fakeActiveCPU; isCPUKey = 1;
        } else if (strcmp(name, "hw.physicalcpu") == 0) {
            fakeInt = g_fakePhysicalCPU; isCPUKey = 1;
        }
        if (isCPUKey) {
            BDS_DIAG_RECORD(g_diagCPU, BDSDiagStateChanged);
            size_t fakeLen = sizeof(int);
            if (oldp == NULL) {
                if (oldlenp) *oldlenp = fakeLen;
                return 0;
            }
            if (*oldlenp < fakeLen) {
                *oldlenp = fakeLen;
                errno = ENOMEM;
                return -1;
            }
            *(int *)oldp = fakeInt;
            *oldlenp = fakeLen;
            return 0;
        }
    }

    BDS_DIAG_RECORD(g_diagSysctl, BDSDiagStatePassed);
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

#pragma mark - Keychain Hook（fishhook）

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);

static BOOL bds_keychainValueContainsBaidu(id value) {
    if (![value isKindOfClass:NSString.class]) return NO;
    return [(NSString *)value rangeOfString:@"baidu"
                                    options:NSCaseInsensitiveSearch].location != NSNotFound;
}

static OSStatus bds_my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    // Keychain 是高级功能，不能再依赖基础总开关 enabled。
    if (!g_config || !cfgBool(@"spoofKeychain", NO) || !query) {
        BDS_DIAG_RECORD(g_diagKeychain, BDSDiagStatePassed);
        return orig_SecItemCopyMatching(query, result);
    }

    @autoreleasepool {
        NSDictionary *dictionary = (__bridge NSDictionary *)query;
        NSArray *keys = @[
            (__bridge id)kSecAttrAccessGroup,
            (__bridge id)kSecAttrService,
            (__bridge id)kSecAttrAccount,
            (__bridge id)kSecAttrDescription,
            (__bridge id)kSecAttrLabel,
            @"agrp"
        ];
        for (id key in keys) {
            if (bds_keychainValueContainsBaidu(dictionary[key])) {
                BDS_DIAG_RECORD(g_diagKeychain, BDSDiagStateBlocked);
                if (result) *result = NULL;
                return errSecItemNotFound;
            }
        }
    }

    BDS_DIAG_RECORD(g_diagKeychain, BDSDiagStatePassed);
    return orig_SecItemCopyMatching(query, result);
}

#pragma mark - User-Agent Hook

static IMP orig_wk_customUserAgent = NULL;
static NSString *new_wk_customUserAgent(id self, SEL _cmd) {
    typedef NSString *(*UserAgentGetterIMP)(id, SEL);
    NSString *original = orig_wk_customUserAgent
        ? ((UserAgentGetterIMP)orig_wk_customUserAgent)(self, _cmd) : nil;
    NSString *custom = cfgStr(@"userAgent", @"");
    if (custom.length > 0) {
        BDS_DIAG_RECORD(g_diagUserAgent, BDSDiagStateChanged);
        return custom;
    }
    BDS_DIAG_RECORD(g_diagUserAgent, BDSDiagStatePassed);
    return original;
}

static IMP orig_nsmurl_setValue = NULL;
static void new_nsmurl_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    BOOL changed = NO;
    if (field && value &&
        [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame &&
        cfgBool(@"spoofUserAgent", NO)) {
        NSString *custom = cfgStr(@"userAgent", @"");
        if (custom.length > 0) {
            value = custom;
            changed = YES;
        }
    }
    BDS_DIAG_RECORD(g_diagUserAgent, changed ? BDSDiagStateChanged : BDSDiagStatePassed);
    typedef void (*SetValueIMP)(id, SEL, NSString *, NSString *);
    if (orig_nsmurl_setValue) ((SetValueIMP)orig_nsmurl_setValue)(self, _cmd, value, field);
}

static IMP orig_nsmurl_addValue = NULL;
static void new_nsmurl_addValue(id self, SEL _cmd, NSString *value, NSString *field) {
    BOOL changed = NO;
    if (field && value &&
        [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame &&
        cfgBool(@"spoofUserAgent", NO)) {
        NSString *custom = cfgStr(@"userAgent", @"");
        if (custom.length > 0) {
            value = custom;
            changed = YES;
        }
    }
    BDS_DIAG_RECORD(g_diagUserAgent, changed ? BDSDiagStateChanged : BDSDiagStatePassed);
    typedef void (*AddValueIMP)(id, SEL, NSString *, NSString *);
    if (orig_nsmurl_addValue) ((AddValueIMP)orig_nsmurl_addValue)(self, _cmd, value, field);
}

#pragma mark - B: dyld 镜像名过滤（fishhook，纯 C）

static const char *(*orig_dyld_get_image_name)(uint32_t);

static const char *bds_fake_image_names[] = {
    "/System/Library/Frameworks/Foundation.framework/Foundation",
    "/System/Library/Frameworks/UIKit.framework/UIKit",
    "/usr/lib/libobjc.A.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
    "/usr/lib/system/libsystem_kernel.dylib",
    "/usr/lib/system/libsystem_c.dylib",
    "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
    "/usr/lib/libc++.1.dylib"
};
#define BDS_FAKE_IMAGE_COUNT (sizeof(bds_fake_image_names) / sizeof(bds_fake_image_names[0]))

static int bds_c_should_hide_image(const char *name) {
    if (!name) return 0;
    static const char *needles[] = {
        "MGspoofer", "BDSpoofer", "TrollFools", "TrollStore", "dopamine", "Dopamine",
        "ellekit", "ElleKit", "libhooker", "substrate", "Substrate",
        "CydiaSubstrate", "TweakInject", "/var/jb/", "roothide", "RootHide",
        "Choicy", "A-Bypass", "Shadow", "Liberty", "UnSub",
        NULL
    };
    for (int i = 0; needles[i]; i++) {
        if (strstr(name, needles[i])) return 1;
    }
    return 0;
}

static const char *bds_my_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name(image_index);
    if (!name) {
        BDS_DIAG_RECORD(g_diagDyld, BDSDiagStatePassed);
        return name;
    }
    if (!BDS_ATOMIC_GET(g_enabledC) || !BDS_ATOMIC_GET(g_bypassJailbreakC)) {
        BDS_DIAG_RECORD(g_diagDyld, BDSDiagStatePassed);
        return name;
    }
    if (bds_c_should_hide_image(name)) {
        BDS_DIAG_RECORD(g_diagDyld, BDSDiagStateChanged);
        return bds_fake_image_names[image_index % BDS_FAKE_IMAGE_COUNT];
    }
    BDS_DIAG_RECORD(g_diagDyld, BDSDiagStatePassed);
    return name;
}

#pragma mark - C: C 函数级文件检测 hook（fishhook）
// arm64 iOS 上 struct stat 已使用 64 位 inode（__DARWIN_ONLY_64_BIT_INO_T=1），
// stat64/struct stat64 不公开，因此不 hook stat64。

static int (*orig_stat)(const char *, struct stat *);
static int (*orig_lstat)(const char *, struct stat *);
static int (*orig_access)(const char *, int);
static FILE *(*orig_fopen)(const char *, const char *);
static DIR *(*orig_opendir)(const char *);

static int bds_my_stat(const char *path, struct stat *buf) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStateBlocked);
        errno = ENOENT;
        return -1;
    }
    BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStatePassed);
    return orig_stat(path, buf);
}

static int bds_my_lstat(const char *path, struct stat *buf) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStateBlocked);
        errno = ENOENT;
        return -1;
    }
    BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStatePassed);
    return orig_lstat(path, buf);
}

static int bds_my_access(const char *path, int mode) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStateBlocked);
        errno = ENOENT;
        return -1;
    }
    BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStatePassed);
    return orig_access(path, mode);
}

static FILE *bds_my_fopen(const char *path, const char *mode) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStateBlocked);
        errno = ENOENT;
        return NULL;
    }
    BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStatePassed);
    return orig_fopen(path, mode);
}

static DIR *bds_my_opendir(const char *path) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStateBlocked);
        errno = ENOENT;
        return NULL;
    }
    BDS_DIAG_RECORD(g_diagCFiles, BDSDiagStatePassed);
    return orig_opendir(path);
}

#pragma mark - 越狱检测绕过（ObjC 层）

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
    return bds_c_is_jailbreak_path(path.UTF8String) ? YES : NO;
}

static BOOL bds_isSuspiciousBundlePath(NSString *path) {
    if (!path) return NO;
    if (bds_isJailbreakPath(path)) return YES;
    NSString *lower = path.lowercaseString;
    NSArray *needles = @[@"mgspoofer", @"bdspoofer", @"trollfools", @"trollstore", @"dopamine",
                         @"ellekit", @"libhooker", @"substrate", @"tweakinject",
                         @"roothide", @"/var/jb/"];
    for (NSString *n in needles) {
        if ([lower containsString:n]) return YES;
    }
    return NO;
}

static IMP orig_fileExistsAtPath = NULL;
static BOOL new_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (cfgBool(@"bypassJailbreakDetect", NO) && bds_isJailbreakPath(path)) {
        BDS_DIAG_RECORD(g_diagObjCJailbreak, BDSDiagStateBlocked);
        return NO;
    }
    BDS_DIAG_RECORD(g_diagObjCJailbreak, BDSDiagStatePassed);
    typedef BOOL (*ExistsIMP)(id, SEL, NSString *);
    if (orig_fileExistsAtPath) return ((ExistsIMP)orig_fileExistsAtPath)(self, _cmd, path);
    return NO;
}

static IMP orig_fileExistsAtPathIsDir = NULL;
static BOOL new_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDirectory) {
    if (cfgBool(@"bypassJailbreakDetect", NO) && bds_isJailbreakPath(path)) {
        BDS_DIAG_RECORD(g_diagObjCJailbreak, BDSDiagStateBlocked);
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    BDS_DIAG_RECORD(g_diagObjCJailbreak, BDSDiagStatePassed);
    typedef BOOL (*ExistsDirIMP)(id, SEL, NSString *, BOOL *);
    if (orig_fileExistsAtPathIsDir) return ((ExistsDirIMP)orig_fileExistsAtPathIsDir)(self, _cmd, path, isDirectory);
    return NO;
}

static IMP orig_canOpenURL = NULL;
static BOOL new_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (cfgBool(@"bypassJailbreakDetect", NO)) {
        NSString *scheme = url.scheme.lowercaseString;
        if (scheme && [bds_jailbreakSchemes() containsObject:scheme]) {
            BDS_DIAG_RECORD(g_diagObjCJailbreak, BDSDiagStateBlocked);
            return NO;
        }
    }
    BDS_DIAG_RECORD(g_diagObjCJailbreak, BDSDiagStatePassed);
    typedef BOOL (*CanOpenIMP)(id, SEL, NSURL *);
    if (orig_canOpenURL) return ((CanOpenIMP)orig_canOpenURL)(self, _cmd, url);
    return NO;
}

#pragma mark - D: NSBundle 遍历过滤

static IMP orig_allFrameworks = NULL;
static NSArray *new_allFrameworks(id self, SEL _cmd) {
    typedef NSArray *(*AllFrameworksIMP)(id, SEL);
    NSArray *orig = orig_allFrameworks ? ((AllFrameworksIMP)orig_allFrameworks)(self, _cmd) : @[];
    if (!cfgBool(@"bypassJailbreakDetect", NO)) {
        BDS_DIAG_RECORD(g_diagBundles, BDSDiagStatePassed);
        return orig;
    }
    NSMutableArray *filtered = [NSMutableArray array];
    for (NSBundle *bundle in orig) {
        if (![bundle isKindOfClass:[NSBundle class]]) { [filtered addObject:bundle]; continue; }
        if (!bds_isSuspiciousBundlePath(bundle.bundlePath)) {
            [filtered addObject:bundle];
        }
    }
    BDS_DIAG_RECORD(g_diagBundles, filtered.count == orig.count ? BDSDiagStatePassed : BDSDiagStateChanged);
    return filtered;
}

static IMP orig_allBundles = NULL;
static NSArray *new_allBundles(id self, SEL _cmd) {
    typedef NSArray *(*AllBundlesIMP)(id, SEL);
    NSArray *orig = orig_allBundles ? ((AllBundlesIMP)orig_allBundles)(self, _cmd) : @[];
    if (!cfgBool(@"bypassJailbreakDetect", NO)) {
        BDS_DIAG_RECORD(g_diagBundles, BDSDiagStatePassed);
        return orig;
    }
    NSMutableArray *filtered = [NSMutableArray array];
    for (NSBundle *bundle in orig) {
        if (![bundle isKindOfClass:[NSBundle class]]) { [filtered addObject:bundle]; continue; }
        if (!bds_isSuspiciousBundlePath(bundle.bundlePath)) {
            [filtered addObject:bundle];
        }
    }
    BDS_DIAG_RECORD(g_diagBundles, filtered.count == orig.count ? BDSDiagStatePassed : BDSDiagStateChanged);
    return filtered;
}

static IMP orig_loadedBundles = NULL;
static NSArray *new_loadedBundles(id self, SEL _cmd) {
    typedef NSArray *(*LoadedBundlesIMP)(id, SEL);
    NSArray *orig = orig_loadedBundles ? ((LoadedBundlesIMP)orig_loadedBundles)(self, _cmd) : @[];
    if (!cfgBool(@"bypassJailbreakDetect", NO)) {
        BDS_DIAG_RECORD(g_diagBundles, BDSDiagStatePassed);
        return orig;
    }
    NSMutableArray *filtered = [NSMutableArray array];
    for (NSBundle *bundle in orig) {
        if (![bundle isKindOfClass:[NSBundle class]]) { [filtered addObject:bundle]; continue; }
        if (!bds_isSuspiciousBundlePath(bundle.bundlePath)) {
            [filtered addObject:bundle];
        }
    }
    BDS_DIAG_RECORD(g_diagBundles, filtered.count == orig.count ? BDSDiagStatePassed : BDSDiagStateChanged);
    return filtered;
}

#pragma mark - P3: App Group 共享容器隔离

static IMP orig_containerURL = NULL;
static NSURL *new_containerURL(id self, SEL _cmd, NSString *groupIdentifier) {
    if (cfgBool(@"spoofAppGroup", NO) && groupIdentifier &&
        [groupIdentifier rangeOfString:@"baidu" options:NSCaseInsensitiveSearch].location != NSNotFound) {
        BDS_DIAG_RECORD(g_diagAppGroup, BDSDiagStateBlocked);
        return nil;
    }
    BDS_DIAG_RECORD(g_diagAppGroup, BDSDiagStatePassed);
    typedef NSURL *(*ContainerURLIMP)(id, SEL, NSString *);
    if (orig_containerURL) return ((ContainerURLIMP)orig_containerURL)(self, _cmd, groupIdentifier);
    return nil;
}

#pragma mark - P4: 剪贴板保护

static BOOL bds_shouldBlockPasteboardRead(id pasteboard) {
    if (!cfgBool(@"spoofPasteboard", NO)) return NO;
    UIPasteboard *general = [UIPasteboard generalPasteboard];
    if (pasteboard != general) return NO;
    // 前台读取通常来自用户主动粘贴；只阻止 App 非活动状态下读取通用剪贴板。
    return UIApplication.sharedApplication.applicationState != UIApplicationStateActive;
}

static IMP orig_pb_string = NULL;
static NSString *new_pb_string(id self, SEL _cmd) {
    if (bds_shouldBlockPasteboardRead(self)) {
        BDS_DIAG_RECORD(g_diagPasteboard, BDSDiagStateBlocked);
        return @"";
    }
    BDS_DIAG_RECORD(g_diagPasteboard, BDSDiagStatePassed);
    typedef NSString *(*PBStringIMP)(id, SEL);
    if (orig_pb_string) return ((PBStringIMP)orig_pb_string)(self, _cmd);
    return @"";
}

static IMP orig_pb_strings = NULL;
static NSArray *new_pb_strings(id self, SEL _cmd) {
    if (bds_shouldBlockPasteboardRead(self)) {
        BDS_DIAG_RECORD(g_diagPasteboard, BDSDiagStateBlocked);
        return @[];
    }
    BDS_DIAG_RECORD(g_diagPasteboard, BDSDiagStatePassed);
    typedef NSArray *(*PBStringsIMP)(id, SEL);
    if (orig_pb_strings) return ((PBStringsIMP)orig_pb_strings)(self, _cmd);
    return @[];
}

static IMP orig_pb_URL = NULL;
static NSURL *new_pb_URL(id self, SEL _cmd) {
    if (bds_shouldBlockPasteboardRead(self)) {
        BDS_DIAG_RECORD(g_diagPasteboard, BDSDiagStateBlocked);
        return nil;
    }
    BDS_DIAG_RECORD(g_diagPasteboard, BDSDiagStatePassed);
    typedef NSURL *(*PBURLIMP)(id, SEL);
    if (orig_pb_URL) return ((PBURLIMP)orig_pb_URL)(self, _cmd);
    return nil;
}

static IMP orig_pb_items = NULL;
static NSArray *new_pb_items(id self, SEL _cmd) {
    if (bds_shouldBlockPasteboardRead(self)) {
        BDS_DIAG_RECORD(g_diagPasteboard, BDSDiagStateBlocked);
        return @[];
    }
    BDS_DIAG_RECORD(g_diagPasteboard, BDSDiagStatePassed);
    typedef NSArray *(*PBItemsIMP)(id, SEL);
    if (orig_pb_items) return ((PBItemsIMP)orig_pb_items)(self, _cmd);
    return @[];
}

#pragma mark - P7: 定位保护

static IMP orig_clm_locationServicesEnabled_class = NULL;
static BOOL new_clm_locationServicesEnabled_class(id self, SEL _cmd) {
    if (cfgBool(@"spoofLocation", NO)) {
        BDS_DIAG_RECORD(g_diagLocation, BDSDiagStateChanged);
        return NO;
    }
    BDS_DIAG_RECORD(g_diagLocation, BDSDiagStatePassed);
    typedef BOOL (*CLMBoolIMP)(id, SEL);
    if (orig_clm_locationServicesEnabled_class) return ((CLMBoolIMP)orig_clm_locationServicesEnabled_class)(self, _cmd);
    return NO;
}

static IMP orig_clm_authorizationStatus_class = NULL;
static NSInteger new_clm_authorizationStatus_class(id self, SEL _cmd) {
    if (cfgBool(@"spoofLocation", NO)) {
        BDS_DIAG_RECORD(g_diagLocation, BDSDiagStateChanged);
        return kCLAuthorizationStatusDenied;
    }
    BDS_DIAG_RECORD(g_diagLocation, BDSDiagStatePassed);
    typedef NSInteger (*CLMIntIMP)(id, SEL);
    if (orig_clm_authorizationStatus_class) return ((CLMIntIMP)orig_clm_authorizationStatus_class)(self, _cmd);
    return kCLAuthorizationStatusNotDetermined;
}

static IMP orig_clm_authorizationStatus_instance = NULL;
static NSInteger new_clm_authorizationStatus_instance(id self, SEL _cmd) {
    if (cfgBool(@"spoofLocation", NO)) {
        BDS_DIAG_RECORD(g_diagLocation, BDSDiagStateChanged);
        return kCLAuthorizationStatusDenied;
    }
    BDS_DIAG_RECORD(g_diagLocation, BDSDiagStatePassed);
    typedef NSInteger (*CLMIntIMP)(id, SEL);
    if (orig_clm_authorizationStatus_instance) {
        return ((CLMIntIMP)orig_clm_authorizationStatus_instance)(self, _cmd);
    }
    return kCLAuthorizationStatusNotDetermined;
}

static IMP orig_clm_location = NULL;
static CLLocation *new_clm_location(id self, SEL _cmd) {
    if (cfgBool(@"spoofLocation", NO)) {
        BDS_DIAG_RECORD(g_diagLocation, BDSDiagStateChanged);
        return nil;
    }
    BDS_DIAG_RECORD(g_diagLocation, BDSDiagStatePassed);
    typedef CLLocation *(*CLMLocIMP)(id, SEL);
    if (orig_clm_location) return ((CLMLocIMP)orig_clm_location)(self, _cmd);
    return nil;
}

#pragma mark - Q3: iCloud 容器隔离

static IMP orig_ubiquityContainerURL = NULL;
static NSURL *new_ubiquityContainerURL(id self, SEL _cmd, NSString *containerID) {
    if (cfgBool(@"spoofUbiquity", NO)) {
        // 只拦截默认容器（nil）和百度相关 containerID，不影响系统其他 iCloud 功能
        BOOL shouldBlock = (containerID == nil) ||
            ([containerID rangeOfString:@"baidu" options:NSCaseInsensitiveSearch].location != NSNotFound);
        if (shouldBlock) {
            BDS_DIAG_RECORD(g_diagUbiquity, BDSDiagStateBlocked);
            return nil;
        }
    }
    BDS_DIAG_RECORD(g_diagUbiquity, BDSDiagStatePassed);
    typedef NSURL *(*UbiquityIMP)(id, SEL, NSString *);
    if (orig_ubiquityContainerURL) return ((UbiquityIMP)orig_ubiquityContainerURL)(self, _cmd, containerID);
    return nil;
}

#pragma mark - Q4: 通讯录/日历权限返回拒绝

static IMP orig_cn_authorizationStatus = NULL;
static NSInteger new_cn_authorizationStatus(id self, SEL _cmd, NSInteger entityType) {
    if (cfgBool(@"spoofPrivacyPermissions", NO)) {
        BDS_DIAG_RECORD(g_diagPrivacy, BDSDiagStateChanged);
        return 2; // CNAuthorizationStatusDenied
    }
    BDS_DIAG_RECORD(g_diagPrivacy, BDSDiagStatePassed);
    typedef NSInteger (*CNAuthIMP)(id, SEL, NSInteger);
    if (orig_cn_authorizationStatus) return ((CNAuthIMP)orig_cn_authorizationStatus)(self, _cmd, entityType);
    return 2;
}

static IMP orig_ek_authorizationStatus = NULL;
static NSInteger new_ek_authorizationStatus(id self, SEL _cmd, NSInteger entityType) {
    if (cfgBool(@"spoofPrivacyPermissions", NO)) {
        BDS_DIAG_RECORD(g_diagPrivacy, BDSDiagStateChanged);
        return 2; // EKAuthorizationStatusDenied
    }
    BDS_DIAG_RECORD(g_diagPrivacy, BDSDiagStatePassed);
    typedef NSInteger (*EKAuthIMP)(id, SEL, NSInteger);
    if (orig_ek_authorizationStatus) return ((EKAuthIMP)orig_ek_authorizationStatus)(self, _cmd, entityType);
    return 2;
}

static IMP orig_cn_requestAccess = NULL;
static void new_cn_requestAccess(id self, SEL _cmd, NSInteger entityType, void (^completionHandler)(BOOL, NSError *)) {
    if (cfgBool(@"spoofPrivacyPermissions", NO)) {
        BDS_DIAG_RECORD(g_diagPrivacy, BDSDiagStateBlocked);
        // 异步回调，与系统原始行为一致
        if (completionHandler) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                completionHandler(NO, nil);
            });
        }
        return;
    }
    BDS_DIAG_RECORD(g_diagPrivacy, BDSDiagStatePassed);
    typedef void (*CNRequestIMP)(id, SEL, NSInteger, void (^)(BOOL, NSError *));
    if (orig_cn_requestAccess) ((CNRequestIMP)orig_cn_requestAccess)(self, _cmd, entityType, completionHandler);
}

static IMP orig_ek_requestAccess = NULL;
static void new_ek_requestAccess(id self, SEL _cmd, NSInteger entityType, void (^completionHandler)(BOOL, NSError *)) {
    if (cfgBool(@"spoofPrivacyPermissions", NO)) {
        BDS_DIAG_RECORD(g_diagPrivacy, BDSDiagStateBlocked);
        if (completionHandler) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                completionHandler(NO, nil);
            });
        }
        return;
    }
    BDS_DIAG_RECORD(g_diagPrivacy, BDSDiagStatePassed);
    typedef void (*EKRequestIMP)(id, SEL, NSInteger, void (^)(BOOL, NSError *));
    if (orig_ek_requestAccess) ((EKRequestIMP)orig_ek_requestAccess)(self, _cmd, entityType, completionHandler);
}

#pragma mark - Q5: WebKit Cookie 过滤
// 覆盖范围说明：
// getAllCookies: — 拦截 App 主动读取 Cookie
// requestHeaderFieldsWithCookies: — 拦截 NSURLSession/NSURLRequest 生成 Cookie 头
// cookiesWithResponseHeaderFields:forURL: — 拦截响应中的 Set-Cookie 写入
// 注意：WebKit 网络进程内部的 Cookie 管理可能不完全经过上述公开 API，
// 此 Hook 不能保证 100% 阻断所有网络层 Cookie 传输。

static IMP orig_wk_getAllCookies = NULL;
static IMP orig_cookieRequestHeaders = NULL;
static IMP orig_cookieSetCookies = NULL;

static BOOL bds_shouldBlockCookie(NSHTTPCookie *cookie) {
    if (!cookie) return NO;
    NSString *domain = cookie.domain.lowercaseString ?: @"";
    // 精确匹配百度域名后缀，避免 containsString 误拦截
    BOOL isBaidu = NO;
    NSArray *baiduSuffixes = @[
        @".baidu.com", @".bdstatic.com", @".bdimg.com",
        @".hao123.com", @".nuomi.com", @".baidubcs.com",
        @".baidupcs.com", @".mbd.baidu.com"
    ];
    for (NSString *suffix in baiduSuffixes) {
        if ([domain hasSuffix:suffix] || [domain isEqualToString:[suffix substringFromIndex:1]]) {
            isBaidu = YES;
            break;
        }
    }
    if (!isBaidu) return NO;
    NSString *name = cookie.name ?: @"";
    if ([name caseInsensitiveCompare:@"BDUSS"] == NSOrderedSame ||
        [name caseInsensitiveCompare:@"STOKEN"] == NSOrderedSame) {
        return NO;
    }
    static NSSet<NSString *> *blockedNames = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        blockedNames = [NSSet setWithArray:@[
            @"BAIDUID", @"BAIDUID_BFESS", @"cuid", @"cuid_galaxy2",
            @"BAIDU_DEVICE_ID", @"device_id", @"utdid", @"UTDID",
            @"bd_deviceid", @"BD_DEVICEID", @"__yjs_duid", @"__yjsv5_",
            @"PSTM", @"BDSVRTM"
        ]];
    });
    for (NSString *blockedName in blockedNames) {
        if ([name caseInsensitiveCompare:blockedName] == NSOrderedSame ||
            [name rangeOfString:blockedName options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

static void new_wk_getAllCookies(id self, SEL _cmd, void (^completionHandler)(NSArray<NSHTTPCookie *> *)) {
    typedef void (*WKGetAllCookiesIMP)(id, SEL, void (^)(NSArray<NSHTTPCookie *> *));
    if (!cfgBool(@"spoofWebKitCookie", NO)) {
        BDS_DIAG_RECORD(g_diagWebKitCookie, BDSDiagStatePassed);
        if (orig_wk_getAllCookies) {
            ((WKGetAllCookiesIMP)orig_wk_getAllCookies)(self, _cmd, completionHandler);
        } else if (completionHandler) {
            completionHandler(@[]);
        }
        return;
    }
    void (^wrappedHandler)(NSArray<NSHTTPCookie *> *) = ^(NSArray<NSHTTPCookie *> *cookies) {
        NSMutableArray<NSHTTPCookie *> *filtered = [NSMutableArray array];
        for (NSHTTPCookie *cookie in cookies) {
            if (!bds_shouldBlockCookie(cookie)) [filtered addObject:cookie];
        }
        if (filtered.count != cookies.count) {
            BDS_DIAG_RECORD(g_diagWebKitCookie, BDSDiagStateChanged);
        } else {
            BDS_DIAG_RECORD(g_diagWebKitCookie, BDSDiagStatePassed);
        }
        if (completionHandler) completionHandler(filtered);
    };
    if (orig_wk_getAllCookies) {
        ((WKGetAllCookiesIMP)orig_wk_getAllCookies)(self, _cmd, wrappedHandler);
    } else if (completionHandler) {
        completionHandler(@[]);
    }
}

static NSDictionary *new_cookieRequestHeaders(id self, SEL _cmd, NSArray<NSHTTPCookie *> *cookies) {
    typedef NSDictionary *(*CookieHeadersIMP)(id, SEL, NSArray *);
    if (!cfgBool(@"spoofWebKitCookie", NO)) {
        BDS_DIAG_RECORD(g_diagWebKitCookie, BDSDiagStatePassed);
        if (orig_cookieRequestHeaders) return ((CookieHeadersIMP)orig_cookieRequestHeaders)(self, _cmd, cookies);
        return @{};
    }
    NSMutableArray<NSHTTPCookie *> *filtered = [NSMutableArray array];
    for (NSHTTPCookie *cookie in cookies) {
        if (!bds_shouldBlockCookie(cookie)) [filtered addObject:cookie];
    }
    if (filtered.count != cookies.count) {
        BDS_DIAG_RECORD(g_diagWebKitCookie, BDSDiagStateChanged);
    } else {
        BDS_DIAG_RECORD(g_diagWebKitCookie, BDSDiagStatePassed);
    }
    if (orig_cookieRequestHeaders) return ((CookieHeadersIMP)orig_cookieRequestHeaders)(self, _cmd, filtered);
    return @{};
}

static NSArray<NSHTTPCookie *> *new_cookieSetCookies(id self, SEL _cmd, NSDictionary *headerFields, NSURL *URL) {
    typedef NSArray *(*CookieSetIMP)(id, SEL, NSDictionary *, NSURL *);
    NSArray<NSHTTPCookie *> *original = orig_cookieSetCookies
        ? ((CookieSetIMP)orig_cookieSetCookies)(self, _cmd, headerFields, URL)
        : @[];
    if (!cfgBool(@"spoofWebKitCookie", NO)) {
        BDS_DIAG_RECORD(g_diagWebKitCookie, BDSDiagStatePassed);
        return original;
    }
    NSMutableArray<NSHTTPCookie *> *filtered = [NSMutableArray array];
    for (NSHTTPCookie *cookie in original) {
        if (!bds_shouldBlockCookie(cookie)) [filtered addObject:cookie];
    }
    if (filtered.count != original.count) {
        BDS_DIAG_RECORD(g_diagWebKitCookie, BDSDiagStateChanged);
    } else {
        BDS_DIAG_RECORD(g_diagWebKitCookie, BDSDiagStatePassed);
    }
    return filtered;
}

#pragma mark - P1: WiFi SSID/BSSID Hook（fishhook）

static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef);

static CFDictionaryRef bds_my_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    if (!BDS_ATOMIC_GET(g_enabledC) || !BDS_ATOMIC_GET(g_spoofWiFiC)) {
        BDS_DIAG_RECORD(g_diagWiFi, BDSDiagStatePassed);
        return orig_CNCopyCurrentNetworkInfo(interfaceName);
    }
    if (g_wifiSSID[0] != '\0') {
        // 返回伪造的 SSID
        NSString *ssid = [[NSString alloc] initWithBytes:g_wifiSSID
                                                  length:strlen(g_wifiSSID)
                                                encoding:NSUTF8StringEncoding];
        if (!ssid) {
            BDS_DIAG_RECORD(g_diagWiFi, BDSDiagStateBlocked);
            return NULL;
        }
        NSData *ssidData = [ssid dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *fake = @{
            (__bridge NSString *)kCNNetworkInfoKeySSID: ssid,
            (__bridge NSString *)kCNNetworkInfoKeyBSSID: @"00:00:00:00:00:00",
            (__bridge NSString *)kCNNetworkInfoKeySSIDData: ssidData
        };
        BDS_DIAG_RECORD(g_diagWiFi, BDSDiagStateChanged);
        return CFRetain((__bridge CFDictionaryRef)fake);
    }
    // 返回 NULL 表示无法获取 WiFi 信息（相当于没有连接 WiFi 或无权限）
    BDS_DIAG_RECORD(g_diagWiFi, BDSDiagStateBlocked);
    return NULL;
}

#pragma mark - P2: 本地 IP Hook（fishhook）

static int (*orig_getifaddrs)(struct ifaddrs **);

static int bds_my_getifaddrs(struct ifaddrs **ifap) {
    int result = orig_getifaddrs(ifap);
    if (result != 0 || !ifap || !*ifap) {
        BDS_DIAG_RECORD(g_diagLocalIP, BDSDiagStatePassed);
        return result;
    }
    if (!BDS_ATOMIC_GET(g_enabledC) || !BDS_ATOMIC_GET(g_spoofLocalIPC)) {
        BDS_DIAG_RECORD(g_diagLocalIP, BDSDiagStatePassed);
        return result;
    }
    // 不返回 0.0.0.0/零掩码这种互相矛盾的数据；把 en0 的 IP 地址项标记为未指定。
    // 调用方仍可按原约定 freeifaddrs() 释放完整链表。
    int modified = 0;
    for (struct ifaddrs *ifa = *ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, "en0") != 0) continue;
        sa_family_t family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            modified = 1;
            ifa->ifa_addr->sa_family = AF_UNSPEC;
            if (ifa->ifa_netmask) ifa->ifa_netmask->sa_family = AF_UNSPEC;
            if (ifa->ifa_dstaddr) ifa->ifa_dstaddr->sa_family = AF_UNSPEC;
        }
    }
    BDS_DIAG_RECORD(g_diagLocalIP, modified ? BDSDiagStateChanged : BDSDiagStatePassed);
    return result;
}

#pragma mark - P8: 代理/VPN 检测绕过（fishhook）

static CFDictionaryRef (*orig_CFNetworkCopySystemProxySettings)(void);
static CFDictionaryRef (*orig_SCDynamicStoreCopyProxies)(SCDynamicStoreRef);

static CFDictionaryRef bds_my_CFNetworkCopySystemProxySettings(void) {
    if (!BDS_ATOMIC_GET(g_enabledC) || !BDS_ATOMIC_GET(g_spoofProxyC)) {
        BDS_DIAG_RECORD(g_diagProxy, BDSDiagStatePassed);
        return orig_CFNetworkCopySystemProxySettings();
    }
    BDS_DIAG_RECORD(g_diagProxy, BDSDiagStateChanged);
    // 返回空字典，表示没有代理
    return CFDictionaryCreate(NULL, NULL, NULL, 0,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

static CFDictionaryRef bds_my_SCDynamicStoreCopyProxies(SCDynamicStoreRef store) {
    if (!BDS_ATOMIC_GET(g_enabledC) || !BDS_ATOMIC_GET(g_spoofProxyC)) {
        BDS_DIAG_RECORD(g_diagProxy, BDSDiagStatePassed);
        return orig_SCDynamicStoreCopyProxies(store);
    }
    BDS_DIAG_RECORD(g_diagProxy, BDSDiagStateChanged);
    return CFDictionaryCreate(NULL, NULL, NULL, 0,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

#pragma mark - Q1: statfs/statvfs 磁盘剩余空间 Hook（fishhook）

static int (*orig_statfs)(const char *, struct statfs *);
static int (*orig_statvfs)(const char *, struct statvfs *);

static int bds_my_statfs(const char *path, struct statfs *buf) {
    int result = orig_statfs(path, buf);
    if (result != 0 || !buf) {
        BDS_DIAG_RECORD(g_diagStatfs, BDSDiagStatePassed);
        return result;
    }
    if (!BDS_ATOMIC_GET(g_enabledC) || !BDS_ATOMIC_GET(g_spoofStatfsC)) {
        BDS_DIAG_RECORD(g_diagStatfs, BDSDiagStatePassed);
        return result;
    }
    BDS_DIAG_RECORD(g_diagStatfs, BDSDiagStateChanged);
    long long diskSize = bds_disk_size_get();
    long long fakeFree = diskSize / 2;
    if (buf->f_bsize > 0) {
        buf->f_blocks = (uint64_t)(diskSize / buf->f_bsize);
        buf->f_bfree = (uint64_t)(fakeFree / buf->f_bsize);
        buf->f_bavail = (uint64_t)(fakeFree / buf->f_bsize);
    }
    return result;
}

static int bds_my_statvfs(const char *path, struct statvfs *buf) {
    int result = orig_statvfs(path, buf);
    if (result != 0 || !buf) {
        BDS_DIAG_RECORD(g_diagStatfs, BDSDiagStatePassed);
        return result;
    }
    if (!BDS_ATOMIC_GET(g_enabledC) || !BDS_ATOMIC_GET(g_spoofStatfsC)) {
        BDS_DIAG_RECORD(g_diagStatfs, BDSDiagStatePassed);
        return result;
    }
    BDS_DIAG_RECORD(g_diagStatfs, BDSDiagStateChanged);
    unsigned long long diskSize = (unsigned long long)bds_disk_size_get();
    unsigned long long fakeFree = diskSize / 2;
    unsigned long frsize = buf->f_frsize > 0 ? buf->f_frsize : buf->f_bsize;
    if (frsize > 0) {
        buf->f_blocks = (fsblkcnt_t)(diskSize / frsize);
        buf->f_bfree = (fsblkcnt_t)(fakeFree / frsize);
        buf->f_bavail = (fsblkcnt_t)(fakeFree / frsize);
    }
    return result;
}

#pragma mark - Q2: dlopen 反检测（fishhook）

static void *(*orig_dlopen)(const char *, int);
static int (*orig_dlopen_preflight)(const char *);

static BOOL bds_is_suspicious_dlopen_path(const char *path) {
    if (!path) return NO;
    static const char *badPaths[] = {
        "/var/jb", "/Library/MobileSubstrate", "/bootstrap",
        "/usr/lib/TweakInject", "/.jailbreak", "/.cydia",
        "/jb/", "/electra", "/chimera", "/odyssey",
        "/var/containers/Bundle/trollstore", "/TrollFools",
        NULL
    };
    for (int i = 0; badPaths[i]; i++) {
        if (strstr(path, badPaths[i])) return YES;
    }
    return NO;
}

static void *bds_my_dlopen(const char *path, int mode) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_spoofDlopenC) &&
        bds_is_suspicious_dlopen_path(path)) {
        BDS_DIAG_RECORD(g_diagDlopen, BDSDiagStateBlocked);
        // 让系统加载一个不存在的路径，自然设置 dlerror 并返回 NULL
        return orig_dlopen("/.bds_blocked_nonexistent", mode);
    }
    BDS_DIAG_RECORD(g_diagDlopen, BDSDiagStatePassed);
    return orig_dlopen(path, mode);
}

static int bds_my_dlopen_preflight(const char *path) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_spoofDlopenC) &&
        bds_is_suspicious_dlopen_path(path)) {
        BDS_DIAG_RECORD(g_diagDlopen, BDSDiagStateBlocked);
        if (orig_dlopen_preflight) return orig_dlopen_preflight("/.bds_blocked_nonexistent");
        return 0;
    }
    BDS_DIAG_RECORD(g_diagDlopen, BDSDiagStatePassed);
    if (orig_dlopen_preflight) return orig_dlopen_preflight(path);
    return 0;
}

#pragma mark - C 函数 hook 安装（fishhook）

static void installCHooks(void) {
    struct bds_rebinding rebindings[] = {
        {"sysctlbyname", (void *)bds_my_sysctlbyname, (void **)&orig_sysctlbyname},
        {"SecItemCopyMatching", (void *)bds_my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"_dyld_get_image_name", (void *)bds_my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"stat", (void *)bds_my_stat, (void **)&orig_stat},
        {"lstat", (void *)bds_my_lstat, (void **)&orig_lstat},
        {"access", (void *)bds_my_access, (void **)&orig_access},
        {"fopen", (void *)bds_my_fopen, (void **)&orig_fopen},
        {"opendir", (void *)bds_my_opendir, (void **)&orig_opendir},
        {"CNCopyCurrentNetworkInfo", (void *)bds_my_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo},
        {"getifaddrs", (void *)bds_my_getifaddrs, (void **)&orig_getifaddrs},
        {"CFNetworkCopySystemProxySettings", (void *)bds_my_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings},
        {"SCDynamicStoreCopyProxies", (void *)bds_my_SCDynamicStoreCopyProxies, (void **)&orig_SCDynamicStoreCopyProxies},
        {"statfs", (void *)bds_my_statfs, (void **)&orig_statfs},
        {"statvfs", (void *)bds_my_statvfs, (void **)&orig_statvfs},
        {"dlopen", (void *)bds_my_dlopen, (void **)&orig_dlopen},
        {"dlopen_preflight", (void *)bds_my_dlopen_preflight, (void **)&orig_dlopen_preflight},
    };
    bds_rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
}

#pragma mark - 悬浮配置入口

static const void *BDSButtonKey = &BDSButtonKey;
static const CGFloat BDSButtonFullSize = 42.0;
static const CGFloat BDSButtonCollapsedWidth = 18.0;
static const CGFloat BDSButtonCollapsedVisibleWidth = 10.0;
static const NSTimeInterval BDSButtonCollapseDelay = 2.0;

// 1.9.6 换号持久标识清理（实现在 constructor 之前；此处前置声明供界面方法调用）。
static NSString *bds_wipeMangoPersistence(BOOL *outSuccess);

@interface BDSUIController : NSObject
@property (nonatomic, assign) NSUInteger floatingButtonGeneration;
+ (instancetype)shared;
- (void)attachButton;
- (void)openPanel;
- (void)editSystemVersion;
- (void)editDeviceName;
- (void)editIdentifiers;
- (void)randomizeBasicProfile;
- (void)randomizeAdvancedProfile;
- (void)rotateGlobalIdentity;
- (void)showPassthroughWhitelist;
- (void)showPresenceLedger;
- (void)showOptionalSwitches;
- (void)showOptionalEditors;
- (void)showAdvancedSwitches;
- (void)showAdvancedEditors;
- (void)showAntiAssociation;
- (void)wipePersistenceNow;
- (void)showRiskTestSwitches;
- (void)editWiFiSSID;
- (void)editProcessHardware;
- (void)editLocaleCarrier;
- (void)editScreenStorage;
- (void)showSelfTest;
- (void)showPublicAPITest;
- (void)showHookDiagnostics;
- (void)copyDiagnosticText:(NSString *)text;
- (void)shareDiagnosticText:(NSString *)text;
- (void)presentMessage:(NSString *)message title:(NSString *)title;
- (void)showRestartNotice:(BOOL)saved;
- (void)scheduleButtonCollapse:(UIButton *)button;
- (void)expandButton:(UIButton *)button animated:(BOOL)animated;
- (void)collapseButton:(UIButton *)button;
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

static NSString *BDSDiagStateText(int state) {
    switch (state) {
        case BDSDiagStatePassed: return @"透传原值";
        case BDSDiagStateChanged: return @"返回修改值";
        case BDSDiagStateBlocked: return @"已拦截";
        default: return @"未调用";
    }
}

static void BDSAppendDiagLine(NSMutableString *text, NSString *name, BDSDiagCounter *counter) {
    uint64_t hits = bds_diag_load64(&counter->hits);
    uint64_t passed = bds_diag_load64(&counter->passed);
    uint64_t changed = bds_diag_load64(&counter->changed);
    uint64_t blocked = bds_diag_load64(&counter->blocked);
    int state = bds_diag_load_state(&counter->lastState);
    [text appendFormat:@"\n%@：读取 %llu 次 / 返回原值 %llu 次 / 返回修改值 %llu 次 / 拦截 %llu 次 / 最近：%@",
        name, (unsigned long long)hits, (unsigned long long)passed,
        (unsigned long long)changed, (unsigned long long)blocked, BDSDiagStateText(state)];
}

static NSString *BDSRandomHex32(BOOL uppercase) {
    NSString *value = [[NSUUID.UUID.UUIDString
        stringByReplacingOccurrencesOfString:@"-" withString:@""] substringToIndex:32];
    return uppercase ? value.uppercaseString : value.lowercaseString;
}

static NSDictionary *BDSRandomIdentityValues(void) {
    return @{
        @"idfa": NSUUID.UUID.UUIDString.uppercaseString,
        @"idfv": NSUUID.UUID.UUIDString.uppercaseString,
        @"deviceID": NSUUID.UUID.UUIDString.uppercaseString,
        @"cuid": BDSRandomHex32(YES),
        @"utdid": BDSRandomHex32(NO)
    };
}

static NSArray<NSDictionary *> *BDSDeviceProfiles(void) {
    static NSArray<NSDictionary *> *profiles;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        profiles = @[
            @{@"name": @"iPhone 8", @"machine": @"iPhone10,1", @"model": @"D20AP",
              @"width": @375, @"height": @667, @"nativeWidth": @750, @"nativeHeight": @1334,
              @"scale": @2, @"memory": @2048, @"disks": @[@64, @256]},
            @{@"name": @"iPhone 8 Plus", @"machine": @"iPhone10,2", @"model": @"D21AP",
              @"width": @414, @"height": @736, @"nativeWidth": @1080, @"nativeHeight": @1920,
              @"scale": @3, @"memory": @3072, @"disks": @[@64, @256]},
            @{@"name": @"iPhone X", @"machine": @"iPhone10,3", @"model": @"D22AP",
              @"width": @375, @"height": @812, @"nativeWidth": @1125, @"nativeHeight": @2436,
              @"scale": @3, @"memory": @3072, @"disks": @[@64, @256]},
            @{@"name": @"iPhone XR", @"machine": @"iPhone11,8", @"model": @"N841AP",
              @"width": @414, @"height": @896, @"nativeWidth": @828, @"nativeHeight": @1792,
              @"scale": @2, @"memory": @3072, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone XS", @"machine": @"iPhone11,2", @"model": @"D321AP",
              @"width": @375, @"height": @812, @"nativeWidth": @1125, @"nativeHeight": @2436,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @256, @512]},
            @{@"name": @"iPhone XS Max", @"machine": @"iPhone11,6", @"model": @"D331pAP",
              @"width": @414, @"height": @896, @"nativeWidth": @1242, @"nativeHeight": @2688,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @256, @512]},
            @{@"name": @"iPhone 11", @"machine": @"iPhone12,1", @"model": @"N104AP",
              @"width": @414, @"height": @896, @"nativeWidth": @828, @"nativeHeight": @1792,
              @"scale": @2, @"memory": @4096, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone 11 Pro", @"machine": @"iPhone12,3", @"model": @"D421AP",
              @"width": @375, @"height": @812, @"nativeWidth": @1125, @"nativeHeight": @2436,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @256, @512]},
            @{@"name": @"iPhone 11 Pro Max", @"machine": @"iPhone12,5", @"model": @"D431AP",
              @"width": @414, @"height": @896, @"nativeWidth": @1242, @"nativeHeight": @2688,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @256, @512]},
            @{@"name": @"iPhone SE (2nd generation)", @"machine": @"iPhone12,8", @"model": @"D79AP",
              @"width": @375, @"height": @667, @"nativeWidth": @750, @"nativeHeight": @1334,
              @"scale": @2, @"memory": @3072, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone 12 mini", @"machine": @"iPhone13,1", @"model": @"D52gAP",
              @"width": @375, @"height": @812, @"nativeWidth": @1080, @"nativeHeight": @2340,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone 12", @"machine": @"iPhone13,2", @"model": @"D53gAP",
              @"width": @390, @"height": @844, @"nativeWidth": @1170, @"nativeHeight": @2532,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone 12 Pro", @"machine": @"iPhone13,3", @"model": @"D53pAP",
              @"width": @390, @"height": @844, @"nativeWidth": @1170, @"nativeHeight": @2532,
              @"scale": @3, @"memory": @6144, @"disks": @[@128, @256, @512]},
            @{@"name": @"iPhone 12 Pro Max", @"machine": @"iPhone13,4", @"model": @"D54pAP",
              @"width": @428, @"height": @926, @"nativeWidth": @1284, @"nativeHeight": @2778,
              @"scale": @3, @"memory": @6144, @"disks": @[@128, @256, @512]},
            @{@"name": @"iPhone 13 mini", @"machine": @"iPhone14,4", @"model": @"D16AP",
              @"width": @375, @"height": @812, @"nativeWidth": @1080, @"nativeHeight": @2340,
              @"scale": @3, @"memory": @4096, @"disks": @[@128, @256, @512]},
            @{@"name": @"iPhone 13", @"machine": @"iPhone14,5", @"model": @"D17AP",
              @"width": @390, @"height": @844, @"nativeWidth": @1170, @"nativeHeight": @2532,
              @"scale": @3, @"memory": @4096, @"disks": @[@128, @256, @512]},
            @{@"name": @"iPhone 13 Pro", @"machine": @"iPhone14,2", @"model": @"D63AP",
              @"width": @390, @"height": @844, @"nativeWidth": @1170, @"nativeHeight": @2532,
              @"scale": @3, @"memory": @6144, @"disks": @[@128, @256, @512, @1024]},
            @{@"name": @"iPhone 13 Pro Max", @"machine": @"iPhone14,3", @"model": @"D64AP",
              @"width": @428, @"height": @926, @"nativeWidth": @1284, @"nativeHeight": @2778,
              @"scale": @3, @"memory": @6144, @"disks": @[@128, @256, @512, @1024]},
            @{@"name": @"iPhone SE (3rd generation)", @"machine": @"iPhone14,6", @"model": @"D49AP",
              @"width": @375, @"height": @667, @"nativeWidth": @750, @"nativeHeight": @1334,
              @"scale": @2, @"memory": @4096, @"disks": @[@64, @128, @256]}
        ];
    });
    return profiles;
}

static NSString *BDSDeviceRangeName(void) {
    return @"统一随机（10款，不含 SE2）";
}

static NSArray<NSDictionary *> *BDSUnifiedDeviceProfiles(void) {
    // 1.8.0 统一机型池：SE2 保留在资料表中供旧配置读取，但不参与一键随机。
    NSSet<NSString *> *machines = [NSSet setWithArray:@[
        @"iPhone10,1", // iPhone 8
        @"iPhone10,3", // iPhone X
        @"iPhone11,8", // iPhone XR
        @"iPhone11,2", // iPhone XS
        @"iPhone12,1", // iPhone 11
        @"iPhone12,3", // iPhone 11 Pro
        @"iPhone13,1", // iPhone 12 mini
        @"iPhone13,2", // iPhone 12
        @"iPhone14,4", // iPhone 13 mini
        @"iPhone14,6"  // iPhone SE3
    ]];
    NSMutableArray<NSDictionary *> *filtered = [NSMutableArray array];
    for (NSDictionary *profile in BDSDeviceProfiles()) {
        if ([machines containsObject:profile[@"machine"]]) [filtered addObject:profile];
    }
    return filtered;
}

static NSArray<NSDictionary *> *BDSSystemProfiles(void) {
    static NSArray<NSDictionary *> *profiles;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        profiles = @[
            @{@"version": @"15.4.1", @"build": @"19E258"},
            @{@"version": @"15.5", @"build": @"19F77"},
            @{@"version": @"15.6", @"build": @"19G71"},
            @{@"version": @"15.6.1", @"build": @"19G82"},
            @{@"version": @"15.7", @"build": @"19H12"},
            @{@"version": @"16.0", @"build": @"20A362"},
            @{@"version": @"16.1.2", @"build": @"20B110"},
            @{@"version": @"16.3.1", @"build": @"20D67"},
            @{@"version": @"16.5.1", @"build": @"20F75"},
            @{@"version": @"16.7", @"build": @"20H19"},
            @{@"version": @"17.0", @"build": @"21A329"},
            @{@"version": @"17.2.1", @"build": @"21C66"},
            @{@"version": @"17.3.1", @"build": @"21D61"},
            @{@"version": @"17.4.1", @"build": @"21E236"},
            @{@"version": @"17.5", @"build": @"21F79"},
            @{@"version": @"18.0", @"build": @"22A3354"},
            @{@"version": @"18.1.1", @"build": @"22B91"},
            @{@"version": @"18.2.1", @"build": @"22C161"},
            @{@"version": @"18.3.1", @"build": @"22D72"},
            @{@"version": @"18.5", @"build": @"22F76"}
        ];
    });
    return profiles;
}

static NSInteger BDSMaxRandomOSMajorForMachine(NSString *machine) {
    // iPhone 8 / 8 Plus / X (iPhone10,*) officially stop at iOS 16.
    // Every other model currently present in BDSDeviceProfiles supports iOS 18.
    return [machine hasPrefix:@"iPhone10,"] ? 16 : 18;
}

static NSArray<NSDictionary *> *BDSSystemProfilesForDevice(NSDictionary *device) {
    NSString *machine = [device[@"machine"] isKindOfClass:[NSString class]] ? device[@"machine"] : @"";
    NSInteger maxMajor = BDSMaxRandomOSMajorForMachine(machine);
    NSMutableArray<NSDictionary *> *compatible = [NSMutableArray array];
    for (NSDictionary *profile in BDSSystemProfiles()) {
        NSString *version = [profile[@"version"] isKindOfClass:[NSString class]] ? profile[@"version"] : @"";
        if (version.integerValue <= maxMajor) [compatible addObject:profile];
    }
    // Defensive fallback: a malformed/unknown profile must not make randomization crash.
    return compatible.count ? compatible : BDSSystemProfiles();
}

static NSDictionary *BDSRandomSystemProfileForDevice(NSDictionary *device) {
    NSArray<NSDictionary *> *compatible = BDSSystemProfilesForDevice(device);
    NSMutableDictionary<NSNumber *, NSMutableArray<NSDictionary *> *> *byMajor = [NSMutableDictionary dictionary];
    for (NSDictionary *profile in compatible) {
        NSString *version = [profile[@"version"] isKindOfClass:[NSString class]] ? profile[@"version"] : @"";
        NSNumber *major = @(version.integerValue);
        if (!byMajor[major]) byMajor[major] = [NSMutableArray array];
        [byMajor[major] addObject:profile];
    }
    NSArray<NSNumber *> *majors = [[byMajor allKeys] sortedArrayUsingSelector:@selector(compare:)];
    if (!majors.count) return BDSSystemProfiles().firstObject;
    NSNumber *major = majors[arc4random_uniform((uint32_t)majors.count)];
    NSArray<NSDictionary *> *versions = byMajor[major];
    return versions[arc4random_uniform((uint32_t)versions.count)];
}

static NSDictionary *BDSRandomBasicProfileValues(void) {
    NSArray<NSDictionary *> *allDevices = BDSUnifiedDeviceProfiles();
    NSString *currentMachine = cfgStr(@"hwMachine", @"");
    NSMutableArray<NSDictionary *> *candidates = [NSMutableArray array];
    for (NSDictionary *profile in allDevices) {
        if (![profile[@"machine"] isEqualToString:currentMachine]) [candidates addObject:profile];
    }
    if (!candidates.count) [candidates addObjectsFromArray:allDevices];
    NSDictionary *device = candidates[arc4random_uniform((uint32_t)candidates.count)];
    NSDictionary *system = BDSRandomSystemProfileForDevice(device);
    NSArray<NSNumber *> *disks = device[@"disks"];
    NSNumber *disk = disks[arc4random_uniform((uint32_t)disks.count)];

    NSMutableDictionary *values = [NSMutableDictionary dictionary];
    NSString *deviceSuffix = [BDSRandomHex32(YES) substringToIndex:6];
    NSString *deviceName = [@"iPhone-" stringByAppendingString:deviceSuffix];
    values[@"enabled"] = @YES;
    values[@"spoofAdvertisingIdentifiers"] = @YES;
    values[@"spoofProcessHardware"] = @YES;
    values[@"spoofLocale"] = @YES;
    values[@"spoofCarrier"] = @YES;
    // 保持本机真实屏幕，避免随机到大屏机型后界面被放大或缩小。
    values[@"spoofScreen"] = @NO;
    values[@"spoofStorage"] = @YES;
    // 常规高级功能随基础随机一起开启；高级身份值本身不在这里重新生成。
    values[@"spoofBaiduSDK"] = @YES;
    values[@"spoofSysctl"] = @YES;
    values[@"bypassJailbreakDetect"] = @YES;
    values[@"spoofWiFi"] = @YES;
    values[@"spoofLocalIP"] = @YES;
    values[@"spoofPasteboard"] = @YES;
    values[@"spoofBootTime"] = @YES;
    values[@"spoofCPU"] = @YES;
    values[@"spoofLocation"] = @YES;
    values[@"spoofProxyDetection"] = @YES;
    values[@"spoofStatfs"] = @YES;
    values[@"spoofDlopen"] = @YES;
    values[@"spoofUbiquity"] = @YES;
    values[@"spoofPrivacyPermissions"] = @YES;
    values[@"spoofBattery"] = @YES;
    // 兼容风险测试 4 项不在这里修改：Keychain、User-Agent、App Group、WebKit Cookie。
    values[@"deviceProfileName"] = device[@"name"];
    values[@"deviceModel"] = @"iPhone";
    values[@"marketingModel"] = @"iPhone";
    values[@"systemVersion"] = system[@"version"];
    values[@"systemBuild"] = system[@"build"];
    values[@"kernOSVersion"] = system[@"build"];
    values[@"hwMachine"] = device[@"machine"];
    values[@"hwModel"] = device[@"model"];
    values[@"memorySize"] = device[@"memory"];
    values[@"diskSize"] = disk;
    values[@"deviceName"] = deviceName;
    values[@"kernHostname"] = deviceName;
    return values;
}

static NSString *BDSRandomMACAddr(void) {
    return [NSString stringWithFormat:@"%02X:%02X:%02X:%02X:%02X:%02X",
        (unsigned)arc4random_uniform(256), (unsigned)arc4random_uniform(256),
        (unsigned)arc4random_uniform(256), (unsigned)arc4random_uniform(256),
        (unsigned)arc4random_uniform(256), (unsigned)arc4random_uniform(256)];
}

// 一键换全新身份：机型/系统/硬件自洽，所有设备/广告/Dipfy 标识全部重新随机，
// 并打开全部伪装开关（屏幕保持真机物理尺寸）。写入全局共享配置，芒果与广告主 App 共用。
static NSDictionary *BDSFullNewIdentityValues(void) {
    NSArray<NSDictionary *> *devs = BDSUnifiedDeviceProfiles();
    NSDictionary *device = devs[arc4random_uniform((uint32_t)devs.count)];
    NSDictionary *system = BDSRandomSystemProfileForDevice(device);
    NSArray<NSNumber *> *disks = device[@"disks"];
    NSNumber *disk = disks[arc4random_uniform((uint32_t)disks.count)];
    NSString *deviceName = [@"iPhone-" stringByAppendingString:[BDSRandomHex32(YES) substringToIndex:6]];

    NSMutableDictionary *v = [NSMutableDictionary dictionary];
    v[@"identityId"] = [[BDSRandomHex32(NO) substringToIndex:12] copy];
    v[@"identityCreatedAt"] = @((long long)NSDate.date.timeIntervalSince1970);
    v[@"deviceProfileName"] = device[@"name"];
    v[@"deviceModel"] = @"iPhone";
    v[@"marketingModel"] = @"iPhone";
    v[@"systemVersion"] = system[@"version"];
    v[@"systemBuild"] = system[@"build"];
    v[@"kernOSVersion"] = system[@"build"];
    v[@"hwMachine"] = device[@"machine"];
    v[@"hwModel"] = device[@"model"];
    v[@"memorySize"] = device[@"memory"];
    v[@"diskSize"] = disk;
    v[@"deviceName"] = deviceName;
    v[@"kernHostname"] = deviceName;
    // 设备 / 广告 / 百度 / Dipfy 标识全部换新
    v[@"idfa"] = NSUUID.UUID.UUIDString.uppercaseString;
    v[@"idfv"] = NSUUID.UUID.UUIDString.uppercaseString;
    v[@"deviceID"] = NSUUID.UUID.UUIDString.uppercaseString;
    v[@"cuid"] = BDSRandomHex32(YES);
    v[@"utdid"] = BDSRandomHex32(NO);
    v[@"dipfyDeviceKey"] = BDSRandomHex32(YES);
    v[@"dipfyFakeUUID"] = NSUUID.UUID.UUIDString.uppercaseString;
    v[@"macAddress"] = BDSRandomMACAddr();
    v[@"bootTimeOffsetSeconds"] = @(86400 + (NSInteger)arc4random_uniform(7 * 86400));
    // 全部伪装开关打开；屏幕保持真机，避免界面缩放。
    NSArray<NSString *> *turnOn = @[
        @"enabled", @"spoofAdvertisingIdentifiers", @"spoofProcessHardware", @"spoofLocale",
        @"spoofCarrier", @"spoofStorage", @"spoofBaiduSDK", @"spoofSysctl", @"spoofKeychain",
        @"spoofUserAgent", @"bypassJailbreakDetect", @"spoofWiFi", @"spoofLocalIP",
        @"spoofAppGroup", @"spoofPasteboard", @"spoofBootTime", @"spoofCPU", @"spoofLocation",
        @"spoofProxyDetection", @"spoofStatfs", @"spoofDlopen", @"spoofUbiquity",
        @"spoofPrivacyPermissions", @"spoofWebKitCookie", @"spoofBattery", @"spoofDipfy"
    ];
    for (NSString *k in turnOn) v[k] = @YES;
    v[@"spoofScreen"] = @NO;
    return v;
}

static NSString *BDSConfigSummary(void) {
    NSString *bdsDir = bds_globalConfigDir();
    NSString *storage;
    if (bdsDir.length) {
        NSString *cf = [bdsDir stringByAppendingPathComponent:@"bdspoofer_config.plist"];
        NSDictionary *attr = [[NSFileManager defaultManager] attributesOfItemAtPath:cf error:nil];
        unsigned long long sz = [attr fileSize];
        NSString *lock = g_csLockEverFailed ? @"跨进程锁:曾失败(并发首启有风险)"
                          : (g_csProcLockOK ? @"跨进程锁:可用" : @"跨进程锁:本次未取得");
        if (attr && sz > 0) {
            storage = [NSString stringWithFormat:@"全局共享·已落盘(%lluB)\n文件:%@\n%@\n(仅证明本进程;跨App一致性请用[各App身份核对])", sz, cf, lock];
        } else {
            storage = [NSString stringWithFormat:@"⚠️目录可写但配置未落盘\n文件:%@\n%@", cf, lock];
        }
    } else {
        storage = @"⚠️沙盒Documents(各App身份会不一致)";
    }
    return [NSString stringWithFormat:
        @"状态：%@\n身份ID：%@\n设备：%@\n系统：iOS %@ (%@)\n存储：%@\n进程：%@%@",
        cfgBool(@"enabled", NO) ? @"已开启（全局伪装）" : @"已关闭",
        cfgStr(@"identityId", @"(未生成)"),
        cfgStr(@"deviceProfileName", @"iPhone SE (3rd generation)"),
        cfgStr(@"systemVersion", @"15.4.1"),
        cfgStr(@"systemBuild", @"19E258"),
        storage,
        g_bundleID ?: @"-",
        g_isMango ? @"（芒果主App，可改配置）" : @"（广告主App，静默伪装）"];
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
            BOOL leftSide = [cfgStr(@"floatingButtonSide", @"right") isEqualToString:@"left"];
            CGFloat containerWidth = CGRectGetWidth(window.bounds);
            CGFloat containerHeight = CGRectGetHeight(window.bounds);
            CGFloat centerY = containerHeight * ((CGFloat)cfgInt(@"floatingButtonYPermille", 520) / 1000.0);
            centerY = MIN(MAX(centerY, BDSButtonFullSize / 2.0 + 44.0),
                          containerHeight - BDSButtonFullSize / 2.0 - 20.0);
            CGFloat x = leftSide ? 4.0 : containerWidth - BDSButtonFullSize - 4.0;
            button = [UIButton buttonWithType:UIButtonTypeSystem];
            button.frame = CGRectMake(x, centerY - BDSButtonFullSize / 2.0,
                                      BDSButtonFullSize, BDSButtonFullSize);
            button.autoresizingMask = (leftSide ? UIViewAutoresizingFlexibleRightMargin : UIViewAutoresizingFlexibleLeftMargin) |
                                      UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleBottomMargin;
            button.backgroundColor = [UIColor colorWithRed:0.92 green:0.12 blue:0.14 alpha:0.90];
            button.layer.cornerRadius = BDSButtonFullSize / 2.0;
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
            [self scheduleButtonCollapse:button];
        }
        [window bringSubviewToFront:button];
    });
}

- (void)buttonTapped:(UIButton *)button {
    self.floatingButtonGeneration++;
    [self openPanel];
    [self scheduleButtonCollapse:button];
}

- (void)scheduleButtonCollapse:(UIButton *)button {
    NSUInteger generation = ++self.floatingButtonGeneration;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(BDSButtonCollapseDelay * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (generation != self.floatingButtonGeneration || !button.superview) return;
        [self collapseButton:button];
    });
}

- (void)expandButton:(UIButton *)button animated:(BOOL)animated {
    UIView *container = button.superview;
    if (!container) return;
    self.floatingButtonGeneration++;
    BOOL leftSide = CGRectGetMidX(button.frame) < CGRectGetWidth(container.bounds) / 2.0;
    CGFloat centerY = CGRectGetMidY(button.frame);
    CGRect target = CGRectMake(leftSide ? 4.0 : CGRectGetWidth(container.bounds) - BDSButtonFullSize - 4.0,
                               centerY - BDSButtonFullSize / 2.0,
                               BDSButtonFullSize, BDSButtonFullSize);
    void (^changes)(void) = ^{
        button.frame = target;
        button.backgroundColor = [UIColor colorWithRed:0.92 green:0.12 blue:0.14 alpha:0.90];
        button.layer.cornerRadius = BDSButtonFullSize / 2.0;
        button.layer.borderWidth = 1.0;
        [button setTitle:@"隐" forState:UIControlStateNormal];
        button.titleLabel.font = [UIFont boldSystemFontOfSize:17.0];
    };
    if (animated) [UIView animateWithDuration:0.18 animations:changes]; else changes();
}

- (void)collapseButton:(UIButton *)button {
    UIView *container = button.superview;
    if (!container) return;
    BOOL leftSide = CGRectGetMidX(button.frame) < CGRectGetWidth(container.bounds) / 2.0;
    CGFloat centerY = CGRectGetMidY(button.frame);
    CGFloat hiddenWidth = BDSButtonCollapsedWidth - BDSButtonCollapsedVisibleWidth;
    CGRect target = CGRectMake(leftSide ? -hiddenWidth : CGRectGetWidth(container.bounds) - BDSButtonCollapsedVisibleWidth,
                               centerY - BDSButtonFullSize / 2.0,
                               BDSButtonCollapsedWidth, BDSButtonFullSize);
    [UIView animateWithDuration:0.22 animations:^{
        button.frame = target;
        button.backgroundColor = [UIColor colorWithRed:0.92 green:0.12 blue:0.14 alpha:1.00];
        button.layer.cornerRadius = BDSButtonCollapsedWidth / 2.0;
        button.layer.borderWidth = 0.0;
        [button setTitle:(leftSide ? @"›" : @"‹") forState:UIControlStateNormal];
        button.titleLabel.font = [UIFont boldSystemFontOfSize:16.0];
    }];
}

- (void)buttonPanned:(UIPanGestureRecognizer *)gesture {
    UIButton *button = (UIButton *)gesture.view;
    UIView *container = button.superview;
    if (!button || !container) return;
    if (gesture.state == UIGestureRecognizerStateBegan) {
        [self expandButton:button animated:YES];
        [gesture setTranslation:CGPointZero inView:container];
        return;
    }
    CGPoint translation = [gesture translationInView:container];
    CGPoint center = CGPointMake(button.center.x + translation.x, button.center.y + translation.y);
    CGFloat half = CGRectGetWidth(button.bounds) / 2.0;
    center.x = MIN(MAX(center.x, half + 2.0), CGRectGetWidth(container.bounds) - half - 2.0);
    center.y = MIN(MAX(center.y, half + 44.0), CGRectGetHeight(container.bounds) - half - 20.0);
    button.center = center;
    [gesture setTranslation:CGPointZero inView:container];
    if (gesture.state == UIGestureRecognizerStateEnded ||
        gesture.state == UIGestureRecognizerStateCancelled ||
        gesture.state == UIGestureRecognizerStateFailed) {
        BOOL leftSide = button.center.x < CGRectGetWidth(container.bounds) / 2.0;
        CGFloat targetX = leftSide ? 4.0 : CGRectGetWidth(container.bounds) - BDSButtonFullSize - 4.0;
        CGRect target = CGRectMake(targetX, button.center.y - BDSButtonFullSize / 2.0,
                                   BDSButtonFullSize, BDSButtonFullSize);
        button.autoresizingMask = (leftSide ? UIViewAutoresizingFlexibleRightMargin : UIViewAutoresizingFlexibleLeftMargin) |
                                  UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleBottomMargin;
        NSInteger yPermille = (NSInteger)(((button.center.y / CGRectGetHeight(container.bounds)) * 1000.0) + 0.5);
        saveConfigValues(@{@"floatingButtonSide": leftSide ? @"left" : @"right",
                           @"floatingButtonYPermille": @(yPermille)});
        [UIView animateWithDuration:0.20 animations:^{ button.frame = target; } completion:^(BOOL finished) {
            (void)finished;
            [self scheduleButtonCollapse:button];
        }];
    }
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
    [self presentMessage:(saved ? @"配置已写入。请彻底关闭芒果 TV 后重新打开。" : @"配置写入失败，请检查 App Documents 目录权限。")
                    title:(saved ? @"保存成功" : @"保存失败")];
}

- (void)openPanel {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"BDS Global 1.9.6"
                                                                   message:BDSConfigSummary()
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"换全新身份（全局）" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self rotateGlobalIdentity];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"一键随机整套基础参数" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self randomizeBasicProfile];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"一键随机整套高级参数" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self randomizeAdvancedProfile];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"基础功能设置  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showOptionalSwitches];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"高级功能设置  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showAdvancedSwitches];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"反关联增强  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showAntiAssociation];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"透传白名单管理  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showPassthroughWhitelist];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"各App身份核对  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showPresenceLedger];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"诊断与自检  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
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
            @"spoofKeychain": @NO,
            @"spoofUserAgent": @NO,
            @"bypassJailbreakDetect": @NO,
            @"spoofWiFi": @NO,
            @"spoofLocalIP": @NO,
            @"spoofAppGroup": @NO,
            @"spoofPasteboard": @NO,
            @"spoofBootTime": @NO,
            @"spoofCPU": @NO,
            @"spoofLocation": @NO,
            @"spoofProxyDetection": @NO,
            @"spoofStatfs": @NO,
            @"spoofDlopen": @NO,
            @"spoofUbiquity": @NO,
            @"spoofPrivacyPermissions": @NO,
            @"spoofWebKitCookie": @NO,
            @"spoofBattery": @NO
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
        field.placeholder = @"例如 15.7.1";
        field.text = cfgStr(@"systemVersion", @"15.4.1");
        field.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"例如 19H117";
        field.text = cfgStr(@"systemBuild", @"19E258");
        field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *version = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *build = [alert.textFields[1].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].uppercaseString;
        NSRange match = [version rangeOfString:@"^[0-9]+\\.[0-9]+(\\.[0-9]+)?$" options:NSRegularExpressionSearch];
        if (match.location == NSNotFound || !build.length || build.length > 16) {
            [self presentMessage:@"请输入有效版本号和 Build，例如 15.7.1 / 19H117。" title:@"格式错误"];
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

- (void)randomizeBasicProfile {
    NSDictionary *values = BDSRandomBasicProfileValues();
    BOOL saved = saveConfigValues(values);
    if (!saved) {
        [self presentMessage:@"配置文件写入失败，基础参数没有更换。" title:@"保存失败"];
        return;
    }
    NSString *message = [NSString stringWithFormat:
        @"已随机并保存基础参数；基础功能和常规高级功能已开启。\n"
         "高级身份参数没有改动；兼容风险测试 4 项保持原状态。\n"
         "请彻底关闭 App 后重新打开。\n\n"
         "随机范围：%@\n机型：%@\n系统：%@ (%@)\n"
         "内存：%@ MB\n磁盘：%@ GB\n设备名称：%@",
        BDSDeviceRangeName(), values[@"deviceProfileName"], values[@"systemVersion"], values[@"systemBuild"],
        values[@"memorySize"], values[@"diskSize"], values[@"deviceName"]];
    [self presentMessage:message title:@"基础参数已更换"];
}

- (void)randomizeAdvancedProfile {
    NSDictionary *values = BDSRandomIdentityValues();
    BOOL saved = saveConfigValues(values);
    if (!saved) {
        [self presentMessage:@"配置文件写入失败，高级参数没有更换。" title:@"保存失败"];
        return;
    }
    BOOL idfaHit = bds_diag_load64(&g_diagAdvertising.hits) > 0;
    BOOL idfvHit = bds_diag_load64(&g_diagIDFV.hits) > 0;
    BOOL baiduHit = bds_diag_load64(&g_diagBaiduSDK.hits) > 0;
    NSInteger attStatus = bds_realTrackingAuthorizationStatus();
    NSString *attText = attStatus == 3 ? @"已授权" :
                        attStatus == 2 ? @"已拒绝" :
                        attStatus == 1 ? @"受限制" :
                        attStatus == 0 ? @"未决定" : @"不可用";
    NSString *message = [NSString stringWithFormat:
        @"已随机并保存高级参数；基础参数没有改动。\n"
         "请彻底关闭 App 后重新打开，再通过诊断确认新值被读取。\n\n"
         "ATT：%@\n"
         "IDFA：已保存；运行时%@（未授权时固定返回全零）\n"
         "IDFV：已保存；运行时%@\n"
         "CUID/UTDID/DeviceID：已保存；百度SDK运行时%@\n\n"
         "本进程命中只表示接口被调用过，不代表本次新值已上传。",
        attText, idfaHit ? @"已命中" : @"未命中",
        idfvHit ? @"已命中" : @"未命中",
        baiduHit ? @"已命中" : @"未命中"];
    [self presentMessage:message title:@"高级参数已更换"];
}

- (void)rotateGlobalIdentity {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    NSString *current = [NSString stringWithFormat:@"当前身份：%@\n机型：%@ / iOS %@",
                         cfgStr(@"identityId", @"(无)"),
                         cfgStr(@"deviceProfileName", @"-"),
                         cfgStr(@"systemVersion", @"-")];
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"换全新身份（全局）"
                         message:[current stringByAppendingString:
                            @"\n\n将重新随机机型/系统/IDFA/IDFV/Dipfy 等全套身份并写入全局配置，芒果与所有广告主 App 共用同一套。\n\n换号配套三步：①给芒果新建 Crane 干净容器；②卸载上一批广告主 App；③换 IP（飞行重拨/切流量卡/换节点）。"]
                  preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"确认换新身份" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        (void)action;
        NSMutableDictionary *values = [BDSFullNewIdentityValues() mutableCopy];
        // 1.9.6 默认在下次启动先清空 Keychain / 本地 Dipfy 等持久标识，避免重装仍被认成老设备。
        if (cfgBool(@"autoWipeOnRotate", YES)) values[@"wipePersistenceOnNextLaunch"] = @YES;
        BOOL saved = saveConfigValues(values);
        if (!saved) {
            [self presentMessage:@"全局配置写入失败，请检查 /var/jb 全局目录是否可写。" title:@"保存失败"];
            return;
        }
        // 换身份代次：清空上一代各 App 登记，避免浮窗长期显示旧“不一致”。
        NSString *bdsPDir = bds_globalConfigDir();
        if (bdsPDir.length) {
            [[NSFileManager defaultManager] removeItemAtPath:
                [bdsPDir stringByAppendingPathComponent:@"presence.plist"] error:nil];
        }
        NSString *wipeHint = cfgBool(@"autoWipeOnRotate", YES)
            ? @"\n\n已挂「持久标识清理」：彻底关闭芒果再打开时，会自动清空 Keychain/本地Dipfy（等于全新安装）。"
            : @"";
        NSString *msg = [NSString stringWithFormat:
            @"新身份已写入全局配置：\n身份ID：%@\n机型：%@\niOS：%@ (%@)\n\n"
             "请按顺序操作：\n1. 给芒果新建 Crane 干净容器，再登录 B 账号\n2. 卸载上一批广告主 App\n3. 切换 IP（飞行重拨/切流量卡/换代理节点）\n4. 彻底关闭并重启芒果（重启时自动清理持久标识）%@",
            values[@"identityId"], values[@"deviceProfileName"],
            values[@"systemVersion"], values[@"systemBuild"], wipeHint];
        [self presentMessage:msg title:@"新身份已生成"];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)showPassthroughWhitelist {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    NSArray<NSString *> *rules = g_config[@"passthroughBundles"];
    if (![rules isKindOfClass:[NSArray class]]) rules = BDSDefaultConfig()[@"passthroughBundles"];
    NSString *msg = [NSString stringWithFormat:
        @"以下 App 读取真机信息、完全不伪装；com.apple. 系统 App 始终透传。当前 %lu 条，点条目删除，重启后生效。",
        (unsigned long)rules.count];
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"透传白名单"
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    for (NSString *rule in rules) {
        [sheet addAction:[UIAlertAction actionWithTitle:[@"删除：" stringByAppendingString:rule]
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            (void)action;
            NSMutableArray *next = [rules mutableCopy];
            [next removeObject:rule];
            [self showRestartNotice:saveConfigValues(@{@"passthroughBundles": next})];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"添加白名单（精确或前缀.）"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        (void)action;
        UIAlertController *inAlert = [UIAlertController
            alertControllerWithTitle:@"添加透传 App"
                             message:@"填 bundle id：精确匹配直接写，如 com.tencent.xin；以 . 结尾做前缀，如 com.alipay."
                      preferredStyle:UIAlertControllerStyleAlert];
        [inAlert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.placeholder = @"com.xxx.app";
            field.autocapitalizationType = UITextAutocapitalizationTypeNone;
            field.autocorrectionType = UITextAutocorrectionTypeNo;
        }];
        [inAlert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
        [inAlert addAction:[UIAlertAction actionWithTitle:@"添加" style:UIAlertActionStyleDefault handler:^(UIAlertAction *b) {
            (void)b;
            NSString *v = [inAlert.textFields.firstObject.text
                stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            if (!v.length) return;
            NSMutableArray *next = [rules mutableCopy];
            if (![next containsObject:v]) [next addObject:v];
            [self showRestartNotice:saveConfigValues(@{@"passthroughBundles": next})];
        }]];
        [presenter presentViewController:inAlert animated:YES completion:nil];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self openPanel]; });
    }]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showPresenceLedger {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    NSString *dir = bds_globalConfigDir();
    NSString *pf = dir.length ? [dir stringByAppendingPathComponent:@"presence.plist"] : nil;
    NSDictionary *ledger = pf ? [NSDictionary dictionaryWithContentsOfFile:pf] : nil;
    NSString *curId = cfgStr(@"identityId", @"-");
    NSString *curIDFV = cfgStr(@"idfv", @"-");
    NSString *curModel = cfgStr(@"deviceProfileName", @"-");
    NSString *curSys = cfgStr(@"systemVersion", @"-");
    NSMutableString *msg = [NSMutableString string];
    if (!dir.length) {
        [msg appendString:@"⚠️当前为沙盒回退，没有共享登记文件，无法跨App核对。"];
    } else if (![ledger isKindOfClass:NSDictionary.class] || ledger.count == 0) {
        [msg appendFormat:@"暂无登记记录。\n文件：%@\n请先冷启动芒果和各广告主App后再打开。", pf];
    } else {
        [msg appendFormat:@"芒果当前身份：%@\nIDFV:%@\n机型:%@ iOS%@\n逐项核对(身份四要素+运行值)：",
                          curId, curIDFV, curModel, curSys];
        NSArray *sorted = [ledger.allKeys sortedArrayUsingSelector:@selector(compare:)];
        for (NSString *k in sorted) {
            NSDictionary *e = ledger[k];
            if (![e isKindOfClass:NSDictionary.class]) continue;
            NSString *eId=[e objectForKey:@"identityId"]?:@"-", *eIDFV=[e objectForKey:@"idfv"]?:@"-";
            NSString *eModel=[e objectForKey:@"model"]?:@"-", *eSys=[e objectForKey:@"sys"]?:@"-";
            BOOL sameAll = [eId isEqualToString:curId] && [eIDFV isEqualToString:curIDFV]
                        && [eModel isEqualToString:curModel] && [eSys isEqualToString:curSys];
            NSString *gen = [eId isEqualToString:curId] ? @"" : @"\n  ⚠旧身份代次(换身份前残留,可忽略)";
            NSString *rtIDFV=[e objectForKey:@"rtIDFV"]?:@"-", *rtSys=[e objectForKey:@"rtSys"]?:@"-";
            BOOL idfvHookInstalled = [[e objectForKey:@"rtIDFVHookInstalled"] boolValue];
            BOOL sysHookInstalled = [[e objectForKey:@"rtSysHookInstalled"] boolValue];
            NSString *idfvState = idfvHookInstalled
                ? ([rtIDFV isEqualToString:eIDFV] ? @"Hook已安装·匹配" : @"⚠Hook已安装·不匹配")
                : @"Hook未启用";
            NSString *sysState = sysHookInstalled
                ? ([rtSys isEqualToString:eSys] ? @"Hook已安装·匹配" : @"⚠Hook已安装·不匹配")
                : @"Hook未启用";
            [msg appendFormat:@"\n————\n%@  %@%@\n  容器:%@ 锁:%@\n  配置 IDFV:%@ iOS:%@\n  运行 IDFV:%@ (%@)\n  运行 iOS:%@ (%@)\n  %@",
                [e objectForKey:@"bundle"]?:k, sameAll?@"✓四要素一致":@"✗不一致", gen,
                [e objectForKey:@"containerTag"]?:@"-", [e objectForKey:@"lock"]?:@"-",
                eIDFV, eSys, rtIDFV, idfvState, rtSys, sysState,
                [e objectForKey:@"time"]?:@""];
        }
    }
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"各App身份核对（共享登记）"
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"复制" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        (void)a;
        [UIPasteboard generalPasteboard].string = msg;
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *a) {
        (void)a;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self openPanel]; });
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)showOptionalSwitches {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"基础功能设置"
                                                                   message:@"屏幕始终保持本机真实尺寸，不在这里显示。修改后重启生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"key": @"enabled", @"name": @"基础功能总开关"},
        @{@"key": @"spoofAdvertisingIdentifiers", @"name": @"广告标识符"},
        @{@"key": @"spoofProcessHardware", @"name": @"主机名与内存"},
        @{@"key": @"spoofLocale", @"name": @"语言地区"},
        @{@"key": @"spoofCarrier", @"name": @"运营商"},
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
    [sheet addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self openPanel]; });
    }]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showOptionalEditors {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"编辑基础参数"
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
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"高级功能设置"
                                                                   message:@"高级功能初始全部关闭；点击基础随机后自动开启常规项目。兼容风险项目在独立页面手动测试。修改后重启生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"key": @"spoofBaiduSDK", @"name": @"高级身份（IDFV/CUID/UTDID/DeviceID）"},
        @{@"key": @"spoofSysctl", @"name": @"sysctlbyname（hw.machine 等）"},
        @{@"key": @"bypassJailbreakDetect", @"name": @"越狱检测绕过（含镜像名/C函数/NSBundle）"}
    ];
    for (NSDictionary *item in items) {
        NSString *key = item[@"key"];
        NSString *title = [NSString stringWithFormat:@"%@：%@", item[@"name"], BDSOnOff(cfgBool(key, NO))];
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            [self showRestartNotice:saveConfigValues(@{key: @(!cfgBool(key, NO))})];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"兼容风险测试（4项）  ›"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self showRiskTestSwitches]; });
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"编辑高级参数  ›"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self showAdvancedEditors];
        });
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self openPanel]; });
    }]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showRiskTestSwitches {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"兼容风险测试"
                                                                   message:@"这 4 项可能影响登录、共享数据或网络请求。支持逐项切换，也可一键开启/关闭；修改后请彻底重启芒果 TV。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"key": @"spoofKeychain", @"name": @"Keychain 拦截"},
        @{@"key": @"spoofAppGroup", @"name": @"App Group 隔离"},
        @{@"key": @"spoofWebKitCookie", @"name": @"WebKit Cookie 过滤"},
        @{@"key": @"spoofUserAgent", @"name": @"User-Agent 自定义（空值透传）"}
    ];
    for (NSDictionary *item in items) {
        NSString *key = item[@"key"];
        NSString *title = [NSString stringWithFormat:@"%@：%@", item[@"name"], BDSOnOff(cfgBool(key, NO))];
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            [self showRestartNotice:saveConfigValues(@{key: @(!cfgBool(key, NO))})];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"一键开启本页 4 项"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *action) {
        (void)action;
        [self showRestartNotice:saveConfigValues(@{
            @"spoofKeychain": @YES,
            @"spoofAppGroup": @YES,
            @"spoofWebKitCookie": @YES,
            @"spoofUserAgent": @YES
        })];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"一键关闭本页 4 项"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        (void)action;
        [self showRestartNotice:saveConfigValues(@{
            @"spoofKeychain": @NO,
            @"spoofAppGroup": @NO,
            @"spoofWebKitCookie": @NO,
            @"spoofUserAgent": @NO
        })];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self showAdvancedSwitches]; });
    }]];
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
        @{@"key": @"hwMachine", @"default": @"iPhone14,6", @"placeholder": @"hw.machine，例如 iPhone14,6"},
        @{@"key": @"hwModel", @"default": @"D49AP", @"placeholder": @"hw.model，例如 D49AP"},
        @{@"key": @"kernOSVersion", @"default": @"19E258", @"placeholder": @"kern.osversion，例如 19E258"}
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
                                                                   message:@"留空时完整透传百度原始 User-Agent；只有明确填写时才替换。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"userAgent", @"");
        field.placeholder = @"留空透传原始值";
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

- (void)showAntiAssociation {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"反关联增强"
                                                                   message:@"以下常规项目初始关闭，点击基础随机后自动开启。兼容风险项目已集中到独立测试页面。修改后重启生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"key": @"spoofWiFi", @"name": @"WiFi SSID/BSSID 隐藏"},
        @{@"key": @"spoofLocalIP", @"name": @"本地 IP 隐藏（实验）"},
        @{@"key": @"spoofPasteboard", @"name": @"剪贴板保护"},
        @{@"key": @"spoofBootTime", @"name": @"系统启动时间随机化"},
        @{@"key": @"spoofCPU", @"name": @"CPU 参数伪装"},
        @{@"key": @"spoofLocation", @"name": @"定位保护"},
        @{@"key": @"spoofProxyDetection", @"name": @"代理设置隐藏（可能影响网络）"},
        @{@"key": @"spoofStatfs", @"name": @"磁盘剩余空间伪装（C层）"},
        @{@"key": @"spoofDlopen", @"name": @"dlopen 反检测"},
        @{@"key": @"spoofUbiquity", @"name": @"iCloud 容器隔离"},
        @{@"key": @"spoofPrivacyPermissions", @"name": @"通讯录/日历权限拒绝"},
        @{@"key": @"spoofBattery", @"name": @"电池电量伪装"},
        @{@"key": @"autoWipeOnRotate", @"name": @"换身份时清空Keychain/本地ID"}
    ];
    for (NSDictionary *item in items) {
        NSString *key = item[@"key"];
        NSString *title = [NSString stringWithFormat:@"%@：%@", item[@"name"], BDSOnOff(cfgBool(key, NO))];
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            [self showRestartNotice:saveConfigValues(@{key: @(!cfgBool(key, NO))})];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:
        [NSString stringWithFormat:@"下次启动清空持久标识：%@", BDSOnOff(cfgBool(@"wipePersistenceOnNextLaunch", NO))]
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        (void)action;
        BOOL next = !cfgBool(@"wipePersistenceOnNextLaunch", NO);
        [self showRestartNotice:saveConfigValues(@{@"wipePersistenceOnNextLaunch": @(next)})];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"立即清空本机持久标识（现在执行）"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *action) {
        (void)action;
        [self wipePersistenceNow];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"编辑伪造 WiFi SSID"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self editWiFiSSID]; });
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self openPanel]; });
    }]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

// 立即执行一次持久标识清理（不杀进程，便于当场验证）；换号正式流程仍建议用「换全新身份」后重启。
- (void)wipePersistenceNow {
    BOOL complete = NO;
    NSString *report = bds_wipeMangoPersistence(&complete);
    saveConfigValues(@{@"lastWipeAt": @((long long)NSDate.date.timeIntervalSince1970),
                       @"lastWipeReport": report ?: @"",
                       // 运行中的 SDK 可能把内存缓存重新落盘；下一次冷启动必须再做最终清理。
                       @"wipePersistenceOnNextLaunch": @YES});
    [self presentMessage:[NSString stringWithFormat:
        @"已执行第一遍清理：%@\n\n已保留下次启动清理标记。请立即彻底关闭芒果再重开；只有冷启动清理成功后标记才会自动复位。%@",
        report, complete ? @"" : @"\n本次存在未完成项，下次启动会继续重试。"]
                    title:@"持久标识清理"];
}

- (void)editWiFiSSID {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"伪造 WiFi SSID"
                                                                   message:@"留空时返回 NULL（相当于获取不到 WiFi 信息）；填写后返回伪造的 SSID 和全零 BSSID。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"wifiSSID", @"");
        field.placeholder = @"留空 = 隐藏 WiFi 信息";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *ssid = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSUInteger byteLength = [ssid lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        if (byteLength > 32) {
            [self presentMessage:@"WiFi SSID 最多 32 个 UTF-8 字节；中文和 emoji 通常会占多个字节。"
                            title:@"SSID 过长"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"wifiSSID": ssid ?: @""})];
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
        field.text = [NSString stringWithFormat:@"%ld", (long)cfgInt(@"memorySize", 4096)];
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
        @{@"key": @"screenWidth", @"default": @375, @"placeholder": @"逻辑宽度"},
        @{@"key": @"screenHeight", @"default": @667, @"placeholder": @"逻辑高度"},
        @{@"key": @"screenScale", @"default": @2, @"placeholder": @"缩放倍数"},
        @{@"key": @"diskSize", @"default": @64, @"placeholder": @"磁盘 GB"}
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
            @"nativeScreenWidth": @(width * scale),
            @"nativeScreenHeight": @(height * scale),
            @"screenScale": @(scale), @"diskSize": @(disk)
        })];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)copyDiagnosticText:(NSString *)text {
    UIPasteboard.generalPasteboard.string = text ?: @"";
    [self presentMessage:@"结果已经写入系统剪贴板。" title:@"复制成功"];
}

- (void)shareDiagnosticText:(NSString *)text {
    NSString *fileName = [NSString stringWithFormat:@"MGspoofer1.0.0_diagnostics_%lld.txt",
        (long long)NSDate.date.timeIntervalSince1970];
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:fileName];
    NSError *error = nil;
    BOOL saved = [text writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (!saved) {
        [self presentMessage:(error.localizedDescription ?: @"TXT 文件生成失败。") title:@"导出失败"];
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.30 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *presenter = BDSTopController();
        if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
        UIActivityViewController *share = [[UIActivityViewController alloc]
            initWithActivityItems:@[[NSURL fileURLWithPath:path]] applicationActivities:nil];
        if (share.popoverPresentationController) {
            share.popoverPresentationController.sourceView = presenter.view;
            share.popoverPresentationController.sourceRect = CGRectMake(
                CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
        }
        [presenter presentViewController:share animated:YES completion:nil];
    });
}

- (void)showSelfTest {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"诊断与自检"
                                                                   message:@"API 返回值与 Hook 命中统计已分开显示。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    [sheet addAction:[UIAlertAction actionWithTitle:@"公开 API 返回值  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self showPublicAPITest]; });
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Hook 命中统计  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self showHookDiagnostics]; });
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"开始新诊断（清零统计）" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        bds_diag_reset_all();
        [self presentMessage:@"统计已清零。现在正常操作芒果 TV；出现问题后再打开“Hook 命中统计”。"
                        title:@"诊断已开始"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self openPanel]; });
    }]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(
            CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showHookDiagnostics {
    NSMutableString *message = [NSMutableString stringWithString:
        @"范围：芒果 TV 当前进程；不代表这些值已经上传到服务器。\n"
         "读取表示 App 调用了对应 API；返回状态表示插件交给 App 的结果类型。\n"
         "统计从 App 启动或上次清零开始。"];
    BDSAppendDiagLine(message, @"UIDevice", &g_diagUIDevice);
    BDSAppendDiagLine(message, @"IDFV", &g_diagIDFV);
    BDSAppendDiagLine(message, @"IDFA", &g_diagAdvertising);
    BDSAppendDiagLine(message, @"NSProcessInfo", &g_diagProcess);
    BDSAppendDiagLine(message, @"语言 / 运营商", &g_diagLocaleCarrier);
    BDSAppendDiagLine(message, @"屏幕 / 磁盘", &g_diagScreenStorage);
    BDSAppendDiagLine(message, @"百度 SDK 标识", &g_diagBaiduSDK);
    BDSAppendDiagLine(message, @"sysctlbyname", &g_diagSysctl);
    BDSAppendDiagLine(message, @"Keychain", &g_diagKeychain);
    BDSAppendDiagLine(message, @"User-Agent", &g_diagUserAgent);
    BDSAppendDiagLine(message, @"dyld 镜像名", &g_diagDyld);
    BDSAppendDiagLine(message, @"C 文件查询", &g_diagCFiles);
    BDSAppendDiagLine(message, @"ObjC 文件 / URL", &g_diagObjCJailbreak);
    BDSAppendDiagLine(message, @"NSBundle 遍历", &g_diagBundles);
    [message appendString:@"\n\n--- 反关联增强统计 ---"];
    BDSAppendDiagLine(message, @"WiFi SSID/BSSID", &g_diagWiFi);
    BDSAppendDiagLine(message, @"本地 IP", &g_diagLocalIP);
    BDSAppendDiagLine(message, @"App Group", &g_diagAppGroup);
    BDSAppendDiagLine(message, @"剪贴板", &g_diagPasteboard);
    BDSAppendDiagLine(message, @"启动时间", &g_diagBootTime);
    BDSAppendDiagLine(message, @"CPU 参数", &g_diagCPU);
    BDSAppendDiagLine(message, @"定位", &g_diagLocation);
    BDSAppendDiagLine(message, @"代理设置", &g_diagProxy);
    BDSAppendDiagLine(message, @"磁盘剩余空间", &g_diagStatfs);
    BDSAppendDiagLine(message, @"dlopen 反检测", &g_diagDlopen);
    BDSAppendDiagLine(message, @"iCloud 容器", &g_diagUbiquity);
    BDSAppendDiagLine(message, @"隐私权限", &g_diagPrivacy);
    BDSAppendDiagLine(message, @"WebKit Cookie", &g_diagWebKitCookie);
    BDSAppendDiagLine(message, @"电池电量", &g_diagBattery);

    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Hook 命中统计"
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"复制结果" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self copyDiagnosticText:message];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"分享 TXT" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self shareDiagnosticText:message];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self showSelfTest]; });
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)showPublicAPITest {
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
    ASIdentifierManager *adManager = ASIdentifierManager.sharedManager;
    NSString *currentIDFA = adManager.advertisingIdentifier.UUIDString ?: @"nil";
    NSUUID *realAdUUID = orig_advertisingIdentifier
        ? ((UUIDGetterIMP)orig_advertisingIdentifier)(adManager, @selector(advertisingIdentifier))
        : adManager.advertisingIdentifier;
    NSString *realIDFA = realAdUUID.UUIDString ?: @"nil";
    NSInteger attStatus = bds_realTrackingAuthorizationStatus();
    NSString *attText = attStatus == 3 ? @"已授权" :
                        attStatus == 2 ? @"已拒绝" :
                        attStatus == 1 ? @"受限制" :
                        attStatus == 0 ? @"未决定" : @"不可用";
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
         @"IDFA / ATT\n原始 %@\n配置 %@\n当前 %@\nATT %@\n\n"
         @"NSProcessInfo\n原始 %@\n当前 %@\n\n"
         @"内存(MB)\n原始 %llu\n配置 %ld\n当前 %llu\n\n"
         @"屏幕(points / scale)\n原始 %.0fx%.0f / %.2f\n配置 %ldx%ld / %ld\n当前 %.0fx%.0f / %.2f",
        cfgBool(@"enabled", NO) ? @"基础功能已开启" : @"基础功能已关闭",
        realVersion, cfgStr(@"systemVersion", @"15.4.1"), cfgStr(@"systemBuild", @"19E258"), currentVersion,
        realName, cfgStr(@"deviceName", @"iPhone"), currentName,
        realIDFV, cfgStr(@"idfv", @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890"), currentIDFV,
        realIDFA, cfgStr(@"idfa", @"FEDCBA98-7654-3210-FEDC-BA9876543210"), currentIDFA, attText,
        realProcess, currentProcess,
        realMemory, (long)cfgInt(@"memorySize", 4096), currentMemory,
        CGRectGetWidth(realBounds), CGRectGetHeight(realBounds), realScale,
        (long)cfgInt(@"screenWidth", 375), (long)cfgInt(@"screenHeight", 667), (long)cfgInt(@"screenScale", 2),
        CGRectGetWidth(currentBounds), CGRectGetHeight(currentBounds), currentScale];

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

    [advanced appendFormat:@"\nKeychain 拦截：%@", cfgBool(@"spoofKeychain", NO) ? @"开" : @"关"];

    [advanced appendFormat:@"\nUser-Agent：%@", cfgBool(@"spoofUserAgent", NO) ? @"开" : @"关"];
    if (cfgBool(@"spoofUserAgent", NO)) {
        WKWebView *wv = [[WKWebView alloc] init];
        NSString *ua = [wv performSelector:@selector(customUserAgent)];
        [advanced appendFormat:@"\n  WKWebView getter：%@", ua ?: @"nil（App未设置）"];
    }

    [advanced appendFormat:@"\n越狱绕过：%@", cfgBool(@"bypassJailbreakDetect", NO) ? @"开" : @"关"];
    if (cfgBool(@"bypassJailbreakDetect", NO)) {
        // B: 镜像名过滤自检
        if (orig_dyld_get_image_name) {
            uint32_t count = _dyld_image_count();
            int suspicious = 0;
            for (uint32_t i = 0; i < count; i++) {
                const char *orig = orig_dyld_get_image_name(i);
                if (orig && bds_c_should_hide_image(orig)) suspicious++;
            }
            [advanced appendFormat:@"\n  镜像名过滤：隐藏 %u 个可疑镜像", suspicious];
        }
        [advanced appendFormat:@"\n  C函数检测：stat/access/fopen 已拦截"];
        NSArray *frameworks = [NSBundle allFrameworks];
        [advanced appendFormat:@"\n  NSBundle过滤：%lu 个 framework", (unsigned long)frameworks.count];
    }

    [advanced appendFormat:@"\n--- 反关联增强 ---"];
    [advanced appendFormat:@"\nWiFi 隐藏：%@", cfgBool(@"spoofWiFi", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\n本地 IP：%@", cfgBool(@"spoofLocalIP", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\nApp Group：%@", cfgBool(@"spoofAppGroup", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\n剪贴板：%@", cfgBool(@"spoofPasteboard", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\n启动时间：%@", cfgBool(@"spoofBootTime", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\nCPU 参数：%@", cfgBool(@"spoofCPU", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\n定位保护：%@", cfgBool(@"spoofLocation", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\n代理设置隐藏：%@", cfgBool(@"spoofProxyDetection", NO) ? @"开" : @"关"];
    if (cfgBool(@"spoofBootTime", NO)) {
        struct timeval bt;
        size_t btLen = sizeof(bt);
        if (sysctlbyname("kern.boottime", &bt, &btLen, NULL, 0) == 0) {
            NSDate *bootDate = [NSDate dateWithTimeIntervalSince1970:bt.tv_sec];
            NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
            fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss";
            [advanced appendFormat:@"\n  伪造启动时间：%@", [fmt stringFromDate:bootDate]];
        }
    }
    if (cfgBool(@"spoofCPU", NO)) {
        int ncpu = 0; size_t ncpuLen = sizeof(ncpu);
        int physcpu = 0; size_t physLen = sizeof(physcpu);
        sysctlbyname("hw.ncpu", &ncpu, &ncpuLen, NULL, 0);
        sysctlbyname("hw.physicalcpu", &physcpu, &physLen, NULL, 0);
        [advanced appendFormat:@"\n  CPU：%d 核 / %d 物理核", ncpu, physcpu];
    }
    [advanced appendFormat:@"\n磁盘剩余空间：%@", cfgBool(@"spoofStatfs", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\ndlopen 反检测：%@", cfgBool(@"spoofDlopen", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\niCloud 容器：%@", cfgBool(@"spoofUbiquity", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\n隐私权限拒绝：%@", cfgBool(@"spoofPrivacyPermissions", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\nWebKit Cookie：%@", cfgBool(@"spoofWebKitCookie", NO) ? @"开" : @"关"];
    [advanced appendFormat:@"\n电池电量：%@", cfgBool(@"spoofBattery", NO) ? @"开" : @"关"];
    if (cfgBool(@"spoofBattery", NO)) {
        // 用 dispatch_once 保证读取在初始化写入之后
        dispatch_once(&g_batteryOnce, ^{
            g_fakeBatteryLevel = 0.30f + (float)(arc4random_uniform(56)) / 100.0f;
        });
        float level = g_fakeBatteryLevel;
        if (level >= 0) {
            [advanced appendFormat:@"\n  当前返回：%.0f%%", level * 100];
        }
    }

    message = [message stringByAppendingString:advanced];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *presenter = BDSTopController();
        if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"公开 API 返回值"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"复制结果" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            [self copyDiagnosticText:message];
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"分享 TXT" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            [self shareDiagnosticText:message];
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
            (void)action;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [self showSelfTest]; });
        }]];
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

// Crane 数据容器通常对应不同 NSHomeDirectory。显示使用容器目录名，ledger 键使用完整标准化路径，
// 不依赖 NSString.hash，避免跨进程不稳定和 32 位碰撞。
static NSString *bds_containerTag(void) {
    NSString *home = [NSHomeDirectory() stringByStandardizingPath] ?: @"";
    NSString *tag = home.lastPathComponent;
    return tag.length ? tag : @"unknown-container";
}

// 调用方必须在 UIDevice Hook 安装阶段结束后调用；主队列只负责推迟实际读取和写入。
static void bds_recordPresence(void) {
    NSString *dir = bds_globalConfigDir();
    if (!dir.length) return; // 沙盒回退无法跨 App 共享，记不了
    BOOL sysHookInstalled = (orig_systemVersion != NULL);
    BOOL idfvHookInstalled = (orig_identifierForVendor != NULL);
    dispatch_async(dispatch_get_main_queue(), ^{
        BOOL gotLock = bds_beginCriticalSection();
        @try {
            if (!gotLock) return; // presence 是共享读改写，禁止无锁覆盖其他 App 的登记。
            NSString *pf = [dir stringByAppendingPathComponent:@"presence.plist"];
            NSMutableDictionary *ledger = [NSMutableDictionary dictionaryWithContentsOfFile:pf] ?: [NSMutableDictionary dictionary];
            NSString *bid = g_bundleID.length ? g_bundleID : @"-";
            // 运行时实际读到的值；同时记录两个 UIDevice Hook 是否确实安装，避免把“开关未启用”误报为安装失败。
            UIDevice *dev = UIDevice.currentDevice;
            NSString *rtIDFV = dev.identifierForVendor.UUIDString ?: @"(nil)";
            NSString *rtSys = dev.systemVersion ?: @"-";
            NSString *home = [NSHomeDirectory() stringByStandardizingPath] ?: @"";
            NSString *tag = bds_containerTag();
            NSString *key = [NSString stringWithFormat:@"%@#%@", bid, home.length ? home : tag];
            ledger[key] = @{
                @"bundle": bid,
                @"containerTag": tag,
                @"identityId": cfgStr(@"identityId", @"-"),
                @"idfv": cfgStr(@"idfv", @"-"),
                @"model": cfgStr(@"deviceProfileName", @"-"),
                @"sys": cfgStr(@"systemVersion", @"-"),
                @"rtIDFV": rtIDFV,
                @"rtSys": rtSys,
                @"rtIDFVHookInstalled": @(idfvHookInstalled),
                @"rtSysHookInstalled": @(sysHookInstalled),
                @"dir": dir,
                @"cfgPath": configPath(),
                @"lock": gotLock ? @"ok" : @"NOLOCK",
                @"home": home.length ? home : @"-",
                @"time": [NSDateFormatter localizedStringFromDate:NSDate.date
                                                         dateStyle:NSDateFormatterShortStyle
                                                         timeStyle:NSDateFormatterMediumStyle]
            };
            [ledger writeToFile:pf atomically:YES];
        } @finally { bds_endCriticalSection(); }
    });
}

#pragma mark - 1.9.6 换号：清空芒果本机持久标识（Keychain / UserDefaults / Cookie / 容器与 AppGroup 内设备-ID 文件）

// 文件名 / 键名是否属于“设备 / 安装 / 登录 / 风控标识”。
// 仅接受精确标识名，或 Mango/Dipfy 厂商前缀与标识词同时出现；不再用 iid 等短子串模糊匹配。
static BOOL bds_nameLooksLikePersistID(NSString *name) {
    if (![name isKindOfClass:NSString.class] || name.length == 0) return NO;
    NSString *lower = name.lowercaseString;
    NSMutableString *n = [NSMutableString stringWithCapacity:lower.length];
    NSString *stemLower = name.lastPathComponent.stringByDeletingPathExtension.lowercaseString;
    NSMutableString *stem = [NSMutableString stringWithCapacity:stemLower.length];
    NSCharacterSet *allowed = NSCharacterSet.alphanumericCharacterSet;
    for (NSUInteger i = 0; i < lower.length; i++) {
        unichar c = [lower characterAtIndex:i];
        if ([allowed characterIsMember:c]) [n appendFormat:@"%C", c];
    }
    for (NSUInteger i = 0; i < stemLower.length; i++) {
        unichar c = [stemLower characterAtIndex:i];
        if ([allowed characterIsMember:c]) [stem appendFormat:@"%C", c];
    }
    static NSSet<NSString *> *exact;
    static NSArray<NSString *> *vendors;
    static NSArray<NSString *> *identityWords;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        exact = [NSSet setWithArray:@[@"dipfydeviceid", @"dipfydevicekey", @"dipfyuuid",
                                      @"deviceid", @"deviceuuid", @"devicekey", @"installid",
                                      @"utdid", @"umid", @"cuid", @"idfv", @"idfa", @"dfid",
                                      @"mgtvuuid", @"mgtvtoken", @"serverdeviceid", @"localdeviceid",
                                      @"devicetoken"]];
        vendors = @[@"dipfy", @"mgtv", @"hunantv", @"imgotv"];
        identityWords = @[@"deviceid", @"deviceuuid", @"devicekey", @"installid", @"utdid",
                          @"umid", @"cuid", @"idfv", @"idfa", @"dfid", @"fingerprint",
                          @"accesstoken", @"logintoken", @"sessionid", @"devicetoken", @"uuid"];
    });
    if ([exact containsObject:n] || [exact containsObject:stem]) return YES;
    BOOL hasVendor = NO, hasIdentityWord = NO;
    for (NSString *v in vendors) if ([n containsString:v]) { hasVendor = YES; break; }
    for (NSString *w in identityWords) if ([n containsString:w]) { hasIdentityWord = YES; break; }
    return hasVendor && hasIdentityWord;
}

static NSString *bds_keychainString(id value) {
    if ([value isKindOfClass:NSString.class]) return value;
    if ([value isKindOfClass:NSData.class]) return [[NSString alloc] initWithData:value encoding:NSUTF8StringEncoding];
    return nil;
}

// 必须同时出现 Mango/Dipfy 厂商信息与设备/安装标识词，避免误删正常登录密码和共享凭据。
static BOOL bds_isMangoPersistenceKeychainItem(NSDictionary *item) {
    NSArray *keys = @[(__bridge id)kSecAttrAccessGroup, (__bridge id)kSecAttrService,
                      (__bridge id)kSecAttrAccount, (__bridge id)kSecAttrLabel,
                      (__bridge id)kSecAttrDescription, (__bridge id)kSecAttrComment,
                      (__bridge id)kSecAttrServer, (__bridge id)kSecAttrPath,
                      (__bridge id)kSecAttrApplicationTag];
    NSMutableString *joined = [NSMutableString string];
    for (id key in keys) {
        NSString *s = bds_keychainString(item[key]);
        if (s.length) [joined appendFormat:@" %@", s.lowercaseString];
    }
    BOOL hasVendor = [joined containsString:@"dipfy"] || [joined containsString:@"mgtv"] ||
                     [joined containsString:@"hunantv"] || [joined containsString:@"imgotv"];
    return hasVendor && bds_nameLooksLikePersistID(joined);
}

// 只枚举并删除明确属于 Mango/Dipfy 持久标识的密码项；不触碰证书、私钥、Identity 或普通登录项。
static NSUInteger bds_wipeOwnKeychain(NSUInteger *scanned, NSUInteger *errors) {
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword,
                         (__bridge id)kSecClassInternetPassword];
    NSUInteger removed = 0;
    for (id cls in classes) {
        NSDictionary *q = @{(__bridge id)kSecClass: cls,
                            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                            (__bridge id)kSecReturnAttributes: @YES,
                            (__bridge id)kSecReturnPersistentRef: @YES};
        CFTypeRef raw = NULL;
        OSStatus copyStatus = SecItemCopyMatching((__bridge CFDictionaryRef)q, &raw);
        if (copyStatus == errSecItemNotFound) continue;
        if (copyStatus != errSecSuccess || !raw) {
            if (raw) CFRelease(raw);
            if (errors) (*errors)++;
            continue;
        }
        id result = CFBridgingRelease(raw);
        NSArray *items = [result isKindOfClass:NSArray.class] ? result : @[result];
        for (id obj in items) {
            if (![obj isKindOfClass:NSDictionary.class]) continue;
            NSDictionary *item = obj;
            if (scanned) (*scanned)++;
            if (!bds_isMangoPersistenceKeychainItem(item)) continue;
            NSData *persistentRef = item[(__bridge id)kSecValuePersistentRef];
            if (![persistentRef isKindOfClass:NSData.class]) {
                if (errors) (*errors)++;
                continue;
            }
            NSDictionary *deleteQuery = @{(__bridge id)kSecValuePersistentRef: persistentRef};
            OSStatus deleteStatus = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
            if (deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound) {
                if (deleteStatus == errSecSuccess) removed++;
            } else if (errors) {
                (*errors)++;
            }
        }
    }
    return removed;
}

static BOOL bds_pathIsInsideRoot(NSString *path, NSString *root) {
    if (!path.length || !root.length) return NO;
    if ([path isEqualToString:root]) return YES;
    return [path hasPrefix:[root stringByAppendingString:@"/"]];
}

// 在自有容器 / AppGroup 内做有界枚举；拒绝符号链接，并验证解析后的路径仍在原 root 内。
static NSUInteger bds_wipeIDFilesInRoot(NSString *root, NSFileManager *fm, NSUInteger *scanned,
                                        NSUInteger *errors, BOOL *complete) {
    if (root.length == 0) return 0;
    NSUInteger removed = 0;
    NSString *canonicalRoot = [[root stringByStandardizingPath] stringByResolvingSymlinksInPath];
    NSURL *rootURL = [NSURL fileURLWithPath:canonicalRoot isDirectory:YES];
    NSArray *resourceKeys = @[NSURLIsDirectoryKey, NSURLIsRegularFileKey, NSURLIsSymbolicLinkKey];
    __block NSUInteger enumerationErrors = 0;
    NSDirectoryEnumerator<NSURL *> *enumerator = [fm enumeratorAtURL:rootURL
                                           includingPropertiesForKeys:resourceKeys
                                                              options:0
                                                         errorHandler:^BOOL(NSURL *url, NSError *error) {
        (void)url; (void)error;
        enumerationErrors++;
        return YES;
    }];
    NSUInteger visited = 0;
    const NSUInteger maxVisited = 4096;
    for (NSURL *url in enumerator) {
        if (++visited > maxVisited) {
            if (complete) *complete = NO;
            break;
        }
        NSUInteger relativeDepth = url.pathComponents.count > rootURL.pathComponents.count
            ? url.pathComponents.count - rootURL.pathComponents.count : 0;
        if (relativeDepth > 4) {
            [enumerator skipDescendants];
            continue;
        }
        NSNumber *isDirectory = nil, *isRegular = nil, *isSymlink = nil;
        NSError *resourceError = nil;
        BOOL gotType = [url getResourceValue:&isSymlink forKey:NSURLIsSymbolicLinkKey error:&resourceError] &&
                       [url getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&resourceError] &&
                       [url getResourceValue:&isRegular forKey:NSURLIsRegularFileKey error:&resourceError];
        if (!gotType) {
            if (errors) (*errors)++;
            [enumerator skipDescendants];
            continue;
        }
        if (isSymlink.boolValue) {
            [enumerator skipDescendants];
            continue;
        }
        NSString *resolved = [[url.path stringByStandardizingPath] stringByResolvingSymlinksInPath];
        if (!bds_pathIsInsideRoot(resolved, canonicalRoot)) {
            if (errors) (*errors)++;
            [enumerator skipDescendants];
            continue;
        }
        if (isDirectory.boolValue) continue;
        if (!isRegular.boolValue) continue;
        if (scanned) (*scanned)++;
        if ([url.lastPathComponent isEqualToString:@"bdspoofer_config.plist"]) continue;
        if (bds_nameLooksLikePersistID(url.lastPathComponent)) {
            NSError *removeError = nil;
            if ([fm removeItemAtURL:url error:&removeError]) removed++;
            else if (errors) (*errors)++;
        }
    }
    if (enumerationErrors && errors) *errors += enumerationErrors;
    return removed;
}

// 总入口：返回人类可读的清理报告。全程 @try 保护，任何一步失败都不影响 App 启动。
static NSString *bds_wipeMangoPersistence(BOOL *outSuccess) {
    NSUInteger kc = 0, kcScanned = 0, ud = 0, ck = 0, files = 0, scanned = 0, errors = 0;
    BOOL complete = YES;
    if (outSuccess) *outSuccess = NO;
    @try {
        // 1) Keychain
        kc = bds_wipeOwnKeychain(&kcScanned, &errors);

        // 2) NSUserDefaults 标识类键
        NSUserDefaults *defs = NSUserDefaults.standardUserDefaults;
        NSDictionary *all = [defs dictionaryRepresentation];
        for (NSString *key in all) {
            if (bds_nameLooksLikePersistID(key)) {
                [defs removeObjectForKey:key];
                ud++;
            }
        }
        [defs synchronize];

        // 3) Foundation Cookie（WKWebView 的 Cookie 在容器内，Crane 新容器已隔离，此处尽力清理）
        @try {
            NSHTTPCookieStorage *store = NSHTTPCookieStorage.sharedHTTPCookieStorage;
            NSArray<NSHTTPCookie *> *cookies = [store.cookies copy];
            ck = 0;
            for (NSHTTPCookie *c in cookies) {
                NSString *domain = c.domain.lowercaseString ?: @"";
                if ([domain containsString:@"mgtv.com"] || [domain containsString:@"hunantv.com"]) {
                    [store deleteCookie:c];
                    ck++;
                }
            }
        } @catch (NSException *inner) {
            (void)inner;
            complete = NO;
            errors++;
        }

        // 4) 自有 Documents/Library/Caches + 可解析到的 AppGroup 内标识类文件
        NSFileManager *fm = NSFileManager.defaultManager;
        NSMutableArray<NSString *> *roots = [NSMutableArray array];
        NSArray<NSNumber *> *which = @[@(NSDocumentDirectory), @(NSLibraryDirectory), @(NSCachesDirectory)];
        for (NSNumber *w in which) {
            NSArray<NSURL *> *urls = [fm URLsForDirectory:w.unsignedIntegerValue inDomains:NSUserDomainMask];
            for (NSURL *u in urls) if (u.path.length) [roots addObject:u.path];
        }
        NSString *bid = g_bundleID ?: @"";
        NSMutableArray<NSString *> *groupIds = [NSMutableArray array];
        if (bid.length) [groupIds addObject:[@"group." stringByAppendingString:bid]];
        [groupIds addObject:@"group.com.hunantv.imgotv"];
        for (NSString *gid in groupIds) {
            NSURL *u = [fm containerURLForSecurityApplicationGroupIdentifier:gid];
            if (u.path.length && ![roots containsObject:u.path]) [roots addObject:u.path];
        }
        NSMutableSet<NSString *> *seenRoot = [NSMutableSet set];
        for (NSString *root in roots) {
            NSString *canonical = [[root stringByStandardizingPath] stringByResolvingSymlinksInPath];
            if (!canonical.length) continue;
            BOOL covered = NO;
            for (NSString *seen in seenRoot) {
                if (bds_pathIsInsideRoot(canonical, seen)) { covered = YES; break; }
            }
            if (covered) continue;
            [seenRoot addObject:canonical];
            files += bds_wipeIDFilesInRoot(canonical, fm, &scanned, &errors, &complete);
        }
    } @catch (NSException *e) {
        complete = NO;
        errors++;
        return [NSString stringWithFormat:@"清理异常：%@（Keychain:%lu/%lu 偏好键:%lu Cookie:%lu 标识文件:%lu/扫描%lu 错误:%lu）",
                e.name ?: @"?", (unsigned long)kc, (unsigned long)kcScanned, (unsigned long)ud,
                (unsigned long)ck, (unsigned long)files, (unsigned long)scanned, (unsigned long)errors];
    }
    complete = complete && errors == 0;
    if (outSuccess) *outSuccess = complete;
    return [NSString stringWithFormat:@"Keychain:%lu/%lu 偏好键:%lu Cookie:%lu 标识文件:%lu（扫描%lu） 错误:%lu%@",
            (unsigned long)kc, (unsigned long)kcScanned, (unsigned long)ud, (unsigned long)ck,
            (unsigned long)files, (unsigned long)scanned, (unsigned long)errors,
            complete ? @"" : @"，未完成"];
}

__attribute__((constructor))
static void bds_initialize() {
    @autoreleasepool {
        NSString *bundleID = [NSBundle mainBundle].bundleIdentifier ?: @"";
        g_bundleID = bundleID;
        g_isMango = [bundleID isEqualToString:BDS_MG_BUNDLE];

        // 主 App 门：只处理完整 .app 主程序，跳过 appex 扩展 / 守护进程 / 无 bundle 进程，缩小全局注入影响面。
        NSString *bdsBundlePath = [NSBundle mainBundle].bundlePath ?: @"";
        NSString *bdsPathExt = bdsBundlePath.pathExtension;
        if (bundleID.length == 0 || ![bdsPathExt isEqualToString:@"app"]) return;

        // 早期透传：用只读磁盘配置判定（绝不创建 / 迁移 / 写全局文件），
        // 保证系统 App、微信、支付宝、百度等既不生成身份，也不触碰共享配置。
        // 系统 App / 用户白名单无条件透传（与 globalMode 无关），命中即零 hook 返回。
        NSDictionary *bdsEarly = bds_readOnlyGlobalConfig();
        if (bds_passthroughWithRules(bundleID, bdsEarly[@"passthroughBundles"])) return;

        // 通过分流后才正式加载（跨进程锁内完成首次生成 / 迁移）。
        loadConfig();

        // loadConfig 后以权威 g_config 再确认一次（白名单同样无条件透传）。
        if (bds_isPassthroughBundle(bundleID)) return;

        // 1.9.6 换号：仅芒果主 App，且点过「换全新身份 / 下次启动清空」时，
        // 在所有业务 SDK（含 Dipfy）读取前执行有界清理；仅在完整成功后复位标记。
        if (g_isMango && cfgBool(@"wipePersistenceOnNextLaunch", NO)) {
            @try {
                BOOL wipeComplete = NO;
                g_lastWipeReport = bds_wipeMangoPersistence(&wipeComplete);
                saveConfigValues(@{@"wipePersistenceOnNextLaunch": @(!wipeComplete),
                                   @"lastWipeAt": @((long long)NSDate.date.timeIntervalSince1970),
                                   @"lastWipeReport": g_lastWipeReport ?: @""});
            } @catch (NSException *wipeEx) {
                (void)wipeEx;
                // 清理异常时保留标记，避免一次失败后永久跳过。
                saveConfigValues(@{@"wipePersistenceOnNextLaunch": @YES});
            }
        }

        // 配置浮窗只在芒果 TV 主 App 内显示；广告主 App 只静默应用同一套身份，不弹任何界面。
        if (g_isMango) BDSInstallUI();

        // MGspoofer1.0.0 起，enabled 只代表“基础功能总开关”。
        // 高级功能仍按各自开关独立加载，不能因基础功能关闭而提前返回。
        BOOL basicEnabled = cfgBool(@"enabled", NO);

        // 只在至少一个 C 层高级功能开启时安装 fishhook GOT 替换。
        // fishhook 保存的 orig 指针直接指向 libSystem 真实地址，
        // 调用 orig 不经过 GOT，结构上不可能递归。
        BOOL hasCHookFeature = BDSHasEnabledCHookFeature();
        if (hasCHookFeature) installCHooks();

        // 同步 C 全局开关
        // g_enabledC 表示插件 C 层基础设施已加载，不映射基础总开关。
        BDS_ATOMIC_SET(g_enabledC, hasCHookFeature ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofSysctlC, cfgBool(@"spoofSysctl", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_bypassJailbreakC, cfgBool(@"bypassJailbreakDetect", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofWiFiC, cfgBool(@"spoofWiFi", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofLocalIPC, cfgBool(@"spoofLocalIP", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofProxyC, cfgBool(@"spoofProxyDetection", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofBootTimeC, cfgBool(@"spoofBootTime", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofCPUC, cfgBool(@"spoofCPU", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofStatfsC, cfgBool(@"spoofStatfs", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofDlopenC, cfgBool(@"spoofDlopen", NO) ? 1 : 0);

        // 使用持久化偏移量和真实 boot time 生成稳定值：同一次系统启动期间，
        // App 重启不会重新跳到另一个随机日期；设备真实重启后会随之更新。
        if (BDS_ATOMIC_GET(g_spoofBootTimeC) && g_fakeBootTime.tv_sec == 0) {
            NSInteger offsetSeconds = cfgInt(@"bootTimeOffsetSeconds", 0);
            if (offsetSeconds < 86400 || offsetSeconds >= 8 * 86400) {
                offsetSeconds = 86400 + (NSInteger)arc4random_uniform(7 * 86400);
                saveConfigValues(@{@"bootTimeOffsetSeconds": @(offsetSeconds)});
            }
            struct timeval realBootTime = {0, 0};
            size_t realBootTimeLength = sizeof(realBootTime);
            if (!orig_sysctlbyname ||
                orig_sysctlbyname("kern.boottime", &realBootTime, &realBootTimeLength, NULL, 0) != 0) {
                gettimeofday(&realBootTime, NULL);
            }
            g_fakeBootTime = realBootTime;
            g_fakeBootTime.tv_sec -= offsetSeconds;
        }

        // UIDevice：公开基础参数只在基础总开关开启时安装。
        // IDFV 与电池属于高级功能，分别跟随高级开关加载。
        Class cls = objc_getClass("UIDevice");
        if (basicEnabled) {
            hookInst(cls, @selector(systemVersion), (IMP)new_systemVersion, &orig_systemVersion);
            hookInst(cls, @selector(model), (IMP)new_model, &orig_model);
            hookInst(cls, @selector(localizedModel), (IMP)new_localizedModel, &orig_localizedModel);
            hookInst(cls, @selector(name), (IMP)new_name, &orig_name);
            hookInst(cls, @selector(systemName), (IMP)new_systemName, &orig_systemName);
        }
        if (cfgBool(@"spoofBaiduSDK", NO)) {
            hookInst(cls, @selector(identifierForVendor), (IMP)new_identifierForVendor, &orig_identifierForVendor);
        }

        if (cfgBool(@"spoofBattery", NO)) {
            hookInst(cls, @selector(batteryLevel), (IMP)new_batteryLevel, &orig_batteryLevel);
            hookInst(cls, @selector(batteryState), (IMP)new_batteryState, &orig_batteryState);
        }

        // UIDevice 的 systemVersion / identifierForVendor 安装阶段已经结束，再登记运行时值。
        // 即使 dylib 由后台线程加载，主队列块也不会早于这两个 Hook 的安装尝试。
        bds_recordPresence();

        if (basicEnabled && cfgBool(@"spoofAdvertisingIdentifiers", NO)) {
            cls = objc_getClass("ASIdentifierManager");
            hookInst(cls, @selector(advertisingIdentifier), (IMP)new_advertisingIdentifier, &orig_advertisingIdentifier);
        }

        // NSProcessInfo 公开版本和基础硬件参数
        cls = objc_getClass("NSProcessInfo");
        if (basicEnabled) {
            hookInst(cls, @selector(operatingSystemVersion), (IMP)new_operatingSystemVersion, &orig_operatingSystemVersion);
            hookInst(cls, @selector(operatingSystemVersionString), (IMP)new_operatingSystemVersionString, &orig_operatingSystemVersionString);
        }
        if (basicEnabled && cfgBool(@"spoofProcessHardware", NO)) {
            hookInst(cls, @selector(hostName), (IMP)new_hostName, &orig_hostName);
            hookInst(cls, @selector(physicalMemory), (IMP)new_physicalMemory, &orig_physicalMemory);
        }

        if (basicEnabled && cfgBool(@"spoofLocale", NO)) {
            cls = objc_getClass("NSLocale");
            hookInst(cls, @selector(localeIdentifier), (IMP)new_localeIdentifier, &orig_localeIdentifier);
        }

        if (basicEnabled && cfgBool(@"spoofCarrier", NO)) {
            cls = objc_getClass("CTTelephonyNetworkInfo");
            hookInst(cls, @selector(subscriberCellularProvider), (IMP)new_subscriberCellularProvider, &orig_subscriberCellularProvider);
            hookInst(cls, @selector(serviceSubscriberCellularProviders), (IMP)new_serviceSubscriberCellularProviders, &orig_serviceSubscriberCellularProviders);

            cls = objc_getClass("CTCarrier");
            hookInst(cls, @selector(carrierName), (IMP)new_carrierName, &orig_carrierName);
            hookInst(cls, @selector(mobileCountryCode), (IMP)new_mobileCountryCode, &orig_mobileCountryCode);
            hookInst(cls, @selector(mobileNetworkCode), (IMP)new_mobileNetworkCode, &orig_mobileNetworkCode);
            hookInst(cls, @selector(isoCountryCode), (IMP)new_isoCountryCode, &orig_isoCountryCode);
            hookInst(cls, @selector(allowsVOIP), (IMP)new_allowsVOIP, &orig_allowsVOIP);
        }

        if (basicEnabled && cfgBool(@"spoofScreen", NO)) {
            cls = objc_getClass("UIScreen");
            hookInst(cls, @selector(bounds), (IMP)new_bounds, &orig_bounds);
            hookInst(cls, @selector(nativeBounds), (IMP)new_nativeBounds, &orig_nativeBounds);
            hookInst(cls, @selector(scale), (IMP)new_scale, &orig_scale);
        }

        if (basicEnabled && cfgBool(@"spoofStorage", NO)) {
            cls = objc_getClass("NSFileManager");
            hookInst(cls, @selector(attributesOfFileSystemForPath:error:), (IMP)new_attributesOfFileSystemForPath, &orig_attributesOfFileSystemForPath);
        }

        // 百度 SDK 设备标识 hook
        if (cfgBool(@"spoofBaiduSDK", NO)) {
            installBaiduSDKHooks();
        }

        // 芒果 Dipfy 安全 SDK 专属 hook（安全检测返回 NO + 伪造自产设备标识）
        if (cfgBool(@"spoofDipfy", NO)) {
            installDipfyHooks();
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

        // 越狱检测绕过（ObjC 层 + D: NSBundle 过滤）
        if (cfgBool(@"bypassJailbreakDetect", NO)) {
            cls = objc_getClass("NSFileManager");
            hookInst(cls, @selector(fileExistsAtPath:), (IMP)new_fileExistsAtPath, &orig_fileExistsAtPath);
            hookInst(cls, @selector(fileExistsAtPath:isDirectory:), (IMP)new_fileExistsAtPathIsDir, &orig_fileExistsAtPathIsDir);

            cls = objc_getClass("UIApplication");
            hookInst(cls, @selector(canOpenURL:), (IMP)new_canOpenURL, &orig_canOpenURL);

            // D: NSBundle 遍历过滤
            cls = objc_getClass("NSBundle");
            hookClass(cls, @selector(allFrameworks), (IMP)new_allFrameworks, &orig_allFrameworks);
            hookClass(cls, @selector(allBundles), (IMP)new_allBundles, &orig_allBundles);
            Method m = class_getClassMethod(cls, @selector(loadedBundles));
            if (m) {
                hookClass(cls, @selector(loadedBundles), (IMP)new_loadedBundles, &orig_loadedBundles);
            }
        }

        // P3: App Group 共享容器隔离
        if (cfgBool(@"spoofAppGroup", NO)) {
            cls = objc_getClass("NSFileManager");
            hookInst(cls, @selector(containerURLForSecurityApplicationGroupIdentifier:),
                     (IMP)new_containerURL, &orig_containerURL);
        }

        // P4: 剪贴板保护
        if (cfgBool(@"spoofPasteboard", NO)) {
            cls = objc_getClass("UIPasteboard");
            hookInst(cls, @selector(string), (IMP)new_pb_string, &orig_pb_string);
            hookInst(cls, @selector(strings), (IMP)new_pb_strings, &orig_pb_strings);
            hookInst(cls, @selector(URL), (IMP)new_pb_URL, &orig_pb_URL);
            hookInst(cls, @selector(items), (IMP)new_pb_items, &orig_pb_items);
        }

        // P7: 定位保护
        if (cfgBool(@"spoofLocation", NO)) {
            cls = objc_getClass("CLLocationManager");
            if (cls) {
                hookClass(cls, @selector(locationServicesEnabled),
                          (IMP)new_clm_locationServicesEnabled_class,
                          &orig_clm_locationServicesEnabled_class);
                Method authMethod = class_getClassMethod(cls, @selector(authorizationStatus));
                if (authMethod) {
                    hookClass(cls, @selector(authorizationStatus),
                              (IMP)new_clm_authorizationStatus_class,
                              &orig_clm_authorizationStatus_class);
                }
                hookInst(cls, @selector(authorizationStatus),
                         (IMP)new_clm_authorizationStatus_instance,
                         &orig_clm_authorizationStatus_instance);
                hookInst(cls, @selector(location), (IMP)new_clm_location, &orig_clm_location);
            }
        }

        // Q3: iCloud 容器隔离
        if (cfgBool(@"spoofUbiquity", NO)) {
            cls = objc_getClass("NSFileManager");
            hookInst(cls, @selector(URLForUbiquityContainerIdentifier:),
                     (IMP)new_ubiquityContainerURL, &orig_ubiquityContainerURL);
        }

        // Q4: 通讯录/日历权限返回拒绝；相机和照片均不 Hook。
        if (cfgBool(@"spoofPrivacyPermissions", NO)) {
            cls = objc_getClass("CNContactStore");
            if (cls) {
                hookClass(cls, @selector(authorizationStatusForEntityType:),
                          (IMP)new_cn_authorizationStatus, &orig_cn_authorizationStatus);
                hookInst(cls, @selector(requestAccessForEntityType:completionHandler:),
                         (IMP)new_cn_requestAccess, &orig_cn_requestAccess);
            }
            cls = objc_getClass("EKEventStore");
            if (cls) {
                hookClass(cls, @selector(authorizationStatusForEntityType:),
                          (IMP)new_ek_authorizationStatus, &orig_ek_authorizationStatus);
                hookInst(cls, @selector(requestAccessForEntityType:completionHandler:),
                         (IMP)new_ek_requestAccess, &orig_ek_requestAccess);
            }
        }

        // Q5: WebKit Cookie 过滤
        if (cfgBool(@"spoofWebKitCookie", NO)) {
            cls = objc_getClass("WKHTTPCookieStore");
            if (cls) {
                hookInst(cls, @selector(getAllCookies:),
                         (IMP)new_wk_getAllCookies, &orig_wk_getAllCookies);
            }
            cls = objc_getClass("NSHTTPCookie");
            if (cls) {
                Method m1 = class_getClassMethod(cls, @selector(requestHeaderFieldsWithCookies:));
                if (m1) {
                    hookClass(cls, @selector(requestHeaderFieldsWithCookies:),
                              (IMP)new_cookieRequestHeaders, &orig_cookieRequestHeaders);
                }
                Method m2 = class_getClassMethod(cls, @selector(cookiesWithResponseHeaderFields:forURL:));
                if (m2) {
                    hookClass(cls, @selector(cookiesWithResponseHeaderFields:forURL:),
                              (IMP)new_cookieSetCookies, &orig_cookieSetCookies);
                }
            }
        }
    }
}
