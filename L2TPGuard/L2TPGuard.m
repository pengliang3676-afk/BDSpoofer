#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <arpa/inet.h>
#import <notify.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

// 只注入 SpringBoard。不进极速进程。
// L2TP 网卡消失时立刻关掉名单里的 App。3 到 6 秒再补查一次，防止通知漏掉。

static NSString *const kPrefPath = @"/var/jb/var/mobile/Library/Preferences/com.bds.l2tpguard.plist";
static const NSTimeInterval kBackupInterval = 5.0;

static NSArray<NSString *> *g_bundles;
static BOOL g_enabled = YES;
static dispatch_source_t g_timer;
static int g_notifyToken = 0;
static IMP g_origProcessDidLaunch = NULL;

static int l2tp_up(void) {
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0 || !list) {
        if (list) freeifaddrs(list);
        return 0;
    }
    int up = 0;
    for (struct ifaddrs *ifa = list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || strncmp(ifa->ifa_name, "ppp", 3) != 0) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            up = 1;
            break;
        }
    }
    freeifaddrs(list);
    return up;
}

static void load_prefs(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:kPrefPath];
    NSArray *ids = prefs[@"bundleIDs"];
    NSMutableArray<NSString *> *clean = [NSMutableArray array];
    if ([ids isKindOfClass:NSArray.class]) {
        for (id item in ids) {
            if ([item isKindOfClass:NSString.class] && [item length]) [clean addObject:item];
        }
    }
    if (!clean.count) [clean addObject:@"com.baidu.BaiduMobileInfo"];
    g_bundles = [clean copy];
    id enabled = prefs[@"enabled"];
    g_enabled = enabled ? [enabled boolValue] : YES;
}

static void kill_bundle(NSString *bundleID) {
    if (!bundleID.length) return;
    Class serviceClass = objc_getClass("FBSSystemService");
    if (!serviceClass) return;
    SEL sharedSel = sel_registerName("sharedService");
    if (![serviceClass respondsToSelector:sharedSel]) return;
    id service = ((id (*)(id, SEL))objc_msgSend)(serviceClass, sharedSel);
    SEL killSel = sel_registerName("terminateApplication:forReason:andReport:withDescription:");
    if (![service respondsToSelector:killSel]) return;
    ((void (*)(id, SEL, id, int, BOOL, id))objc_msgSend)(
        service, killSel, bundleID, 1, NO, @"l2tp-down");
}

static void enforce(void) {
    load_prefs();
    if (!g_enabled) return;
    if (l2tp_up()) return;
    NSArray<NSString *> *ids = g_bundles;
    dispatch_async(dispatch_get_main_queue(), ^{
        for (NSString *bundleID in ids) kill_bundle(bundleID);
    });
}

static void hooked_processDidLaunch(id self, SEL _cmd, id process) {
    if (g_origProcessDidLaunch) ((void (*)(id, SEL, id))g_origProcessDidLaunch)(self, _cmd, process);
    load_prefs();
    if (!g_enabled || l2tp_up()) return;
    NSString *bundleID = nil;
    SEL bidSel = sel_registerName("bundleIdentifier");
    if ([process respondsToSelector:bidSel]) {
        bundleID = ((id (*)(id, SEL))objc_msgSend)(process, bidSel);
    }
    if (bundleID.length && [g_bundles containsObject:bundleID]) kill_bundle(bundleID);
}

static void install_launch_hook(void) {
    Class workspace = objc_getClass("SBMainWorkspace");
    SEL sel = sel_registerName("applicationProcessDidLaunch:");
    Method method = workspace ? class_getInstanceMethod(workspace, sel) : NULL;
    if (!method) return;
    g_origProcessDidLaunch = method_getImplementation(method);
    method_setImplementation(method, (IMP)hooked_processDidLaunch);
}

static void start_watch(void) {
    load_prefs();

    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    notify_register_dispatch("com.apple.system.config.network_change", &g_notifyToken, queue, ^(int token) {
        (void)token;
        enforce();
    });

    g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_timer(g_timer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kBackupInterval * NSEC_PER_SEC)),
                              (uint64_t)(kBackupInterval * NSEC_PER_SEC),
                              (uint64_t)(1 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(g_timer, ^{
        enforce();
    });
    dispatch_resume(g_timer);
    install_launch_hook();
}

__attribute__((constructor))
static void l2tpguard_init(void) {
    @autoreleasepool {
        NSString *bundleID = NSBundle.mainBundle.bundleIdentifier;
        if (![bundleID isEqualToString:@"com.apple.springboard"]) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            start_watch();
        });
    }
}
