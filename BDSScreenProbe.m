//
//  BDSScreenProbe.m  —  百度屏幕指纹探针（只读，不改任何值）
//
//  版本：1.0
//  目标：com.baidu.BaiduMobileInfo
//  目的：看清百度到底从哪里读屏幕尺寸，以及它实际拿到的是什么值。
//       用于验证“只改 B 层、A 层保持真机”的方案是否成立。
//
//  只读保证：所有钩子都先调原实现，然后把原值原样返回；
//            只记录日志，不修改任何返回值、不写配置文件、不发网络请求。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

// iOS SDK 头文件没有声明这个符号，手动声明（否则 -Werror=implicit-function-declaration 会失败）
extern void _dyld_register_func_for_add_image(void (*func)(const struct mach_header *mh, intptr_t vmaddr_slide));

static NSString * const BSPBundleID = @"com.baidu.BaiduMobileInfo";
static NSString * const BSPVersion  = @"1.1";

// ---------- 记录区 ----------

static NSUInteger g_seq = 0;
static NSMutableArray<NSString *> *g_log;
static NSMutableDictionary<NSString *, NSNumber *> *g_calls;
static NSMutableDictionary<NSString *, NSString *> *g_last;

static NSString *BSPDesc(id v) {
    if (!v) return @"(nil)";
    if (v == [NSNull null]) return @"(null)";
    if ([v isKindOfClass:NSString.class]) return v;
    if ([v isKindOfClass:NSNumber.class]) return [v stringValue];
    if ([v isKindOfClass:NSDictionary.class] || [v isKindOfClass:NSArray.class]) {
        NSData *d = [NSJSONSerialization dataWithJSONObject:v options:0 error:nil];
        if (d) return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: [v description];
        return [v description];
    }
    return [v description];
}

static void BSPRecord(NSString *label, NSString *value) {
    @synchronized (g_log) {
        g_seq++;
        g_calls[label] = @([g_calls[label] unsignedIntegerValue] + 1);
        g_last[label] = value;
        if (g_log.count < 400) {
            [g_log addObject:[NSString stringWithFormat:@"#%lu %@ = %@",
                              (unsigned long)g_seq, label, value]];
        }
    }
}

// ---------- 钩子安装 ----------

static NSMutableDictionary<NSString *, NSNumber *> *g_installed;

static void BSPHook(NSString *clsName, NSString *selName, BOOL isClassMethod, IMP newImp, IMP *outOrig) {
    Class cls = NSClassFromString(clsName);
    if (!cls) {
        g_installed[[NSString stringWithFormat:@"%@ %@", clsName, selName]] = @(-1);  // 类不存在
        return;
    }
    SEL sel = NSSelectorFromString(selName);
    Method m = isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m) {
        g_installed[[NSString stringWithFormat:@"%@ %@", clsName, selName]] = @(-2);  // 方法不存在
        return;
    }
    if (outOrig) *outOrig = method_getImplementation(m);
    method_setImplementation(m, newImp);
    g_installed[[NSString stringWithFormat:@"%@ %@", clsName, selName]] = @(1);
}

// 屏幕/像素相关出口：原值原样返回，只记录

static IMP o_getScreenResolution = NULL;
static CGSize p_getScreenResolution(id self, SEL _cmd) {
    CGSize r = o_getScreenResolution ? ((CGSize (*)(id, SEL))o_getScreenResolution)(self, _cmd) : CGSizeZero;
    BSPRecord(@"BaiduMobStatDeviceInfo +getScreenResolution",
              [NSString stringWithFormat:@"%.0f x %.0f", r.width, r.height]);
    return r;
}

static IMP o_bp_resolution = NULL;
static id p_bp_resolution(id self, SEL _cmd) {
    id r = o_bp_resolution ? ((id (*)(id, SEL))o_bp_resolution)(self, _cmd) : nil;
    BSPRecord(@"UIDevice +bp_resolution", BSPDesc(r));
    return r;
}

static IMP o_talos_platform = NULL;
static id p_talos_platform(id self, SEL _cmd) {
    id r = o_talos_platform ? ((id (*)(id, SEL))o_talos_platform)(self, _cmd) : nil;
    BSPRecord(@"BDPTalosBaseInfo +platformInfo", BSPDesc(r));
    return r;
}

static IMP o_talos_basic = NULL;
static id p_talos_basic(id self, SEL _cmd) {
    id r = o_talos_basic ? ((id (*)(id, SEL))o_talos_basic)(self, _cmd) : nil;
    BSPRecord(@"BDPTalosBaseInfo +getBasicPlatformInfo", BSPDesc(r));
    return r;
}

static IMP o_bbasm_const = NULL;
static id p_bbasm_const(id self, SEL _cmd) {
    id r = o_bbasm_const ? ((id (*)(id, SEL))o_bbasm_const)(self, _cmd) : nil;
    BSPRecord(@"BBASMPlugin +getConstantSystemInfoDictionary", BSPDesc(r));
    return r;
}

static IMP o_bbasm_sys = NULL;
static id p_bbasm_sys(id self, SEL _cmd, id a, id b) {
    id r = o_bbasm_sys ? ((id (*)(id, SEL, id, id))o_bbasm_sys)(self, _cmd, a, b) : nil;
    BSPRecord(@"BBASMPlugin +getSystemInfoWithAppID:cardID:", BSPDesc(r));
    return r;
}

static IMP o_ua_get = NULL;
static id p_ua_get(id self, SEL _cmd) {
    id r = o_ua_get ? ((id (*)(id, SEL))o_ua_get)(self, _cmd) : nil;
    BSPRecord(@"BDPUserAgent -useagent_getDeviceInfo", BSPDesc(r));
    return r;
}

static IMP o_dm_sysver = NULL;
static id p_dm_sysver(id self, SEL _cmd) {
    id r = o_dm_sysver ? ((id (*)(id, SEL))o_dm_sysver)(self, _cmd) : nil;
    BSPRecord(@"DMDeviceInfoWrapper -systemVersion", BSPDesc(r));
    return r;
}

static IMP o_bdp_sysver = NULL;
static id p_bdp_sysver(id self, SEL _cmd) {
    id r = o_bdp_sysver ? ((id (*)(id, SEL))o_bdp_sysver)(self, _cmd) : nil;
    BSPRecord(@"BDPDeviceUtility -getSystemVersion", BSPDesc(r));
    return r;
}

static void BSPInstallHooks(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_installed = [NSMutableDictionary dictionary];
        BSPHook(@"BaiduMobStatDeviceInfo", @"getScreenResolution", YES,
                (IMP)p_getScreenResolution, &o_getScreenResolution);
        BSPHook(@"UIDevice", @"bp_resolution", YES, (IMP)p_bp_resolution, &o_bp_resolution);
        BSPHook(@"BDPTalosBaseInfo", @"platformInfo", YES, (IMP)p_talos_platform, &o_talos_platform);
        BSPHook(@"BDPTalosBaseInfo", @"getBasicPlatformInfo", YES, (IMP)p_talos_basic, &o_talos_basic);
        BSPHook(@"BBASMPlugin", @"getConstantSystemInfoDictionary", YES,
                (IMP)p_bbasm_const, &o_bbasm_const);
        BSPHook(@"BBASMPlugin", @"getSystemInfoWithAppID:cardID:", YES, (IMP)p_bbasm_sys, &o_bbasm_sys);
        BSPHook(@"BDPUserAgent", @"useagent_getDeviceInfo", NO, (IMP)p_ua_get, &o_ua_get);
        BSPHook(@"DMDeviceInfoWrapper", @"systemVersion", NO, (IMP)p_dm_sysver, &o_dm_sysver);
        BSPHook(@"BDPDeviceUtility", @"getSystemVersion", NO, (IMP)p_bdp_sysver, &o_bdp_sysver);
    });
}

// 百度框架是后加载的：dyld 回调 + 定时重试补钩子
static void BSPRetry(void);
static void BSPAddImage(const struct mach_header *mh, intptr_t slide) {
    (void)mh; (void)slide;
    dispatch_async(dispatch_get_main_queue(), ^{ BSPInstallHooks(); BSPRetry(); });
}
static void BSPRetry(void) {
    static int tries = 0;
    if (tries++ > 40) return;
    BSPInstallHooks();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ BSPRetry(); });
}

// ---------- 报告 ----------

static NSString *BSPReport(void) {
    NSMutableString *out = [NSMutableString string];
    NSDateFormatter *fmt = [NSDateFormatter new];
    fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    fmt.timeZone = [NSTimeZone timeZoneWithName:@"Asia/Shanghai"];
    fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss Z";

    [out appendFormat:@"BDSScreenProbe %@\n", BSPVersion];
    [out appendFormat:@"capturedAt=%@\n", [fmt stringFromDate:NSDate.date]];
    [out appendFormat:@"bundleId=%@\n", NSBundle.mainBundle.bundleIdentifier ?: @""];
    [out appendFormat:@"\n--- 本机真实值（探针自己读的）---\n"];
    CGRect b = UIScreen.mainScreen.bounds;
    CGRect nb = UIScreen.mainScreen.nativeBounds;
    [out appendFormat:@"UIScreen.bounds=%.0fx%.0f\n", b.size.width, b.size.height];
    [out appendFormat:@"UIScreen.nativeBounds=%.0fx%.0f\n", nb.size.width, nb.size.height];
    [out appendFormat:@"UIScreen.scale=%.2f\n", UIScreen.mainScreen.scale];
    [out appendFormat:@"UIDevice.systemVersion=%@\n", UIDevice.currentDevice.systemVersion];
    [out appendFormat:@"UIDevice.model=%@\n", UIDevice.currentDevice.model];

    // 直接读配置文件：确认开关到底有没有被写进去。
    // 之前排查 UA 不生效时只能靠猜“插件有没有接管”，这一步把它变成事实。
    [out appendString:@"\n--- 配置文件开关（决定插件会不会接管）---\n"];
    NSString *docsDir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *cfgPath = [docsDir stringByAppendingPathComponent:@"bdspoofer_config.plist"];
    [out appendFormat:@"configPath=%@\n", cfgPath];
    NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:cfgPath];
    if (![cfg isKindOfClass:NSDictionary.class]) {
        [out appendString:@"(读不到配置文件)\n"];
    } else {
        [out appendFormat:@"configVersion=%@\n", cfg[@"configVersion"] ?: @"(缺)"];
        NSArray<NSString *> *keys = @[
            @"enabled",
            @"spoofBaiduSDK", @"spoofSysctl", @"bypassJailbreakDetect",
            @"spoofKeychain", @"spoofAppGroup", @"spoofWebKitCookie", @"spoofUserAgent",
            @"spoofBaiduTargeted",
            @"spoofBaiduTargetedSystem", @"spoofBaiduTargetedModel",
            @"spoofBaiduTargetedScreen", @"spoofBaiduTargetedUA", @"spoofBaiduTargetedPush",
            @"spoofScreen",
            @"targetedSystemVersion", @"targetedUASystemVersion",
            @"targetedScreenWidth", @"targetedScreenHeight", @"targetedScreenScale",
            @"systemVersion", @"hwMachine", @"deviceProfileName",
        ];
        for (NSString *k in keys) {
            id v = cfg[k];
            [out appendFormat:@"  %-26s = %@\n", k.UTF8String,
                              v ? [v description] : @"(键不存在)"];
        }
        [out appendFormat:@"  配置文件键数 = %lu\n", (unsigned long)cfg.count];
    }

    [out appendString:@"\n--- 钩子安装情况 ---\n"];
    for (NSString *k in [g_installed.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
        NSInteger v = g_installed[k].integerValue;
        NSString *s = v == 1 ? @"已挂钩" : (v == -1 ? @"类不存在" : @"方法不存在");
        [out appendFormat:@"%@ -> %@\n", k, s];
    }

    [out appendString:@"\n--- 各出口被读取次数 ---\n"];
    if (g_calls.count == 0) {
        [out appendString:@"(一次都没被调用)\n"];
    } else {
        for (NSString *k in [g_calls.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            [out appendFormat:@"%4lu 次  %@\n", (unsigned long)g_calls[k].unsignedIntegerValue, k];
        }
    }

    [out appendString:@"\n--- 各出口最近一次返回值（关键）---\n"];
    if (g_last.count == 0) {
        [out appendString:@"(没有记录到调用)\n"];
    } else {
        for (NSString *k in [g_last.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
            [out appendFormat:@"%@\n    = %@\n", k, g_last[k]];
        }
    }

    [out appendString:@"\n--- 调用流水（最多 400 条）---\n"];
    @synchronized (g_log) {
        if (g_log.count == 0) [out appendString:@"(空)\n"];
        for (NSString *line in g_log) [out appendFormat:@"%@\n", line];
    }
    return out;
}

// ---------- 悬浮按钮 ----------

static UIWindow *g_win;
static UIButton *g_btn;

@interface BSPPassWin : UIWindow
@end
@implementation BSPPassWin
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    return (v == self || v == self.rootViewController.view) ? nil : v;
}
@end

static UIWindowScene *BSPScene(void) {
    UIWindowScene *any = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if (![s isKindOfClass:UIWindowScene.class]) continue;
        if (!any) any = (UIWindowScene *)s;
        if (s.activationState == UISceneActivationStateForegroundActive) return (UIWindowScene *)s;
    }
    return any;
}

static UIViewController *BSPTop(void) {
    UIWindow *w = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if (![s isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *cand in ((UIWindowScene *)s).windows) {
            if (cand.isKeyWindow) { w = cand; break; }
        }
        if (w) break;
    }
    if (!w) w = UIApplication.sharedApplication.windows.firstObject;
    UIViewController *vc = w.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static void BSPShare(void) {
    NSString *report = BSPReport();
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *name = [NSString stringWithFormat:@"screen_probe_%@.txt",
                      [[NSDateFormatter new] stringFromDate:NSDate.date]];
    NSString *path = [docs stringByAppendingPathComponent:name];
    NSError *err = nil;
    [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&err];
    UIViewController *top = BSPTop();
    if (err || !top) {
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"导出失败"
                                                                   message:err.localizedDescription ?: @"没有可用界面"
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
        [top ?: BSPTop() presentViewController:a animated:YES completion:nil];
        return;
    }
    UIActivityViewController *ac = [[UIActivityViewController alloc]
        initWithActivityItems:@[[NSURL fileURLWithPath:path], report] applicationActivities:nil];
    if (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad) {
        ac.popoverPresentationController.sourceView = g_btn ?: top.view;
        ac.popoverPresentationController.sourceRect = g_btn ? g_btn.bounds : CGRectMake(0, 0, 1, 1);
    }
    [top presentViewController:ac animated:YES completion:nil];
}

@interface BSPTap : NSObject
@end
@implementation BSPTap
- (void)tap {
    NSString *report = BSPReport();
    UIAlertController *sheet = [UIAlertController
        alertControllerWithTitle:@"屏幕探针"
                         message:[report substringToIndex:MIN((NSUInteger)900, report.length)]
                  preferredStyle:UIAlertControllerStyleActionSheet];
    [sheet addAction:[UIAlertAction actionWithTitle:@"导出 / 分享 TXT"
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction *a) { BSPShare(); }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    if (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad) {
        sheet.popoverPresentationController.sourceView = g_btn;
        sheet.popoverPresentationController.sourceRect = g_btn.bounds;
    }
    [BSPTop() presentViewController:sheet animated:YES completion:nil];
}
@end
static BSPTap *g_tap;

static void BSPFloat(void) {
    if (g_win) { g_win.hidden = NO; return; }
    if (!g_tap) g_tap = [BSPTap new];
    UIWindowScene *scene = BSPScene();
    CGRect screen = scene ? scene.coordinateSpace.bounds : UIScreen.mainScreen.bounds;
    CGFloat y = screen.size.height - 56 - 21 - 210;
    if (y < 160) y = 160;
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = CGRectMake(8, y, 56, 56);
    b.layer.cornerRadius = 28;
    b.backgroundColor = [UIColor colorWithRed:0.10 green:0.35 blue:0.70 alpha:0.92];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:11];
    b.titleLabel.numberOfLines = 2;
    b.titleLabel.textAlignment = NSTextAlignmentCenter;
    [b setTitle:@"屏幕\n探针" forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [b addTarget:g_tap action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
    g_btn = b;
    BSPPassWin *w = scene ? [[BSPPassWin alloc] initWithWindowScene:scene]
                          : [[BSPPassWin alloc] initWithFrame:screen];
    w.frame = screen;
    w.windowLevel = UIWindowLevelStatusBar + 45;
    w.backgroundColor = UIColor.clearColor;
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = UIColor.clearColor;
    [vc.view addSubview:b];
    w.rootViewController = vc;
    w.hidden = NO;
    g_win = w;
}

__attribute__((constructor))
static void bsp_start(void) {
    NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"";
    if (![bid isEqualToString:BSPBundleID]) return;
    NSString *exe = NSBundle.mainBundle.executablePath ?: @"";
    if ([exe containsString:@".appex"] || [exe containsString:@"/PlugIns/"]) return;
    g_log = [NSMutableArray array];
    g_calls = [NSMutableDictionary dictionary];
    g_last = [NSMutableDictionary dictionary];
    g_installed = [NSMutableDictionary dictionary];
    BSPInstallHooks();
    _dyld_register_func_for_add_image(BSPAddImage);
    dispatch_async(dispatch_get_main_queue(), ^{
        BSPRetry();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ BSPFloat(); });
        [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidBecomeActiveNotification
                        object:nil
                         queue:NSOperationQueue.mainQueue
                    usingBlock:^(__unused NSNotification *n) { BSPFloat(); }];
    });
}
