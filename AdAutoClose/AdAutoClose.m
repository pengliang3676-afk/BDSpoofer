//
//  AdAutoClose.m  ——  百度极速「激励视频广告播完自动关闭」
//
//  独立 dylib，只注入 com.baidu.BaiduMobileInfo，不依赖任何其它插件。
//
//  设计要点：
//    · 只做「替你点关闭按钮」—— 不改奖励逻辑、不改播放逻辑
//    · 只点 ivar 名含 close 的按钮（广告【播完后】才出现的那种）；
//      不碰 skip（跳过按钮），避免广告没看完就跳过拿不到奖励
//    · 事件驱动：只在广告页出现→消失期间工作，其余时间零开销
//    · 悬浮球开关（可拖动、点击开/关、位置记住、状态存盘）
//    · 所有回调包 @try，出异常只记日志，绝不让 App 崩
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#pragma mark - 前向声明

static void ADLog(NSString *fmt, ...);
static NSString *ADLogPath(void);
static NSString *ADConfigPath(void);
static void ADLoadConfig(void);
static void ADSaveConfig(void);
static void ADInstallBall(void);
static void ADInstallHooks(void);
static void ADUpdateBallLook(void);
static void ADOnBallTapped(void);
static void ADOnBallPan(UIPanGestureRecognizer *g);
static void ADOnBallPanEnd(void);

static BOOL g_enabled = YES;              // 总开关
static CGPoint g_ballCenter = {0, 0};     // 悬浮球位置（0,0 = 用默认位置）

#pragma mark - 日志

static NSString *ADLogPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"adautoclose_log.txt"];
}

static void ADLog(NSString *fmt, ...) {
    @try {
        va_list ap;
        va_start(ap, fmt);
        NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);

        static NSDateFormatter *df = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            df = [NSDateFormatter new];
            df.dateFormat = @"MM-dd HH:mm:ss";
        });
        NSString *line = [NSString stringWithFormat:@"[%@] %@\n",
                          [df stringFromDate:[NSDate date]], msg ?: @""];
        NSString *p = ADLogPath();
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
        if (!fh) {
            [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            return;
        }
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
        NSDictionary *attr = [[NSFileManager defaultManager] attributesOfItemAtPath:p error:NULL];
        if ([attr fileSize] > 64 * 1024) {   // 超过 64KB 清空，防无限增长
            [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        }
    } @catch (NSException *e) {}
}

#pragma mark - 配置

static NSString *ADConfigPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"adautoclose_config.plist"];
}

static void ADLoadConfig(void) {
    @try {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:ADConfigPath()];
        if (![d isKindOfClass:[NSDictionary class]]) return;
        if (d[@"enabled"]) g_enabled = [d[@"enabled"] boolValue];
        double x = [d[@"ballX"] doubleValue], y = [d[@"ballY"] doubleValue];
        if (x > 0 && y > 0) g_ballCenter = CGPointMake(x, y);
    } @catch (NSException *e) {}
}

static void ADSaveConfig(void) {
    @try {
        [@{@"enabled": @(g_enabled),
           @"ballX": @(g_ballCenter.x),
           @"ballY": @(g_ballCenter.y)} writeToFile:ADConfigPath() atomically:YES];
    } @catch (NSException *e) {}
}

#pragma mark - 悬浮球手势目标

@interface ADTarget : NSObject
+ (instancetype)shared;
- (void)ballTapped;
- (void)ballPan:(UIPanGestureRecognizer *)g;
@end

@implementation ADTarget
+ (instancetype)shared {
    static ADTarget *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [ADTarget new]; });
    return s;
}
- (void)ballTapped { ADOnBallTapped(); }
- (void)ballPan:(UIPanGestureRecognizer *)g {
    ADOnBallPan(g);
    if (g.state == UIGestureRecognizerStateEnded ||
        g.state == UIGestureRecognizerStateCancelled ||
        g.state == UIGestureRecognizerStateFailed) {
        ADOnBallPanEnd();
    }
}
@end

#pragma mark - 悬浮球

static UIWindow *g_ballWindow = nil;
static UIButton *g_ballButton = nil;
static int g_ballRetry = 0;

static void ADUpdateBallLook(void) {
    if (!g_ballButton) return;
    g_ballButton.backgroundColor = g_enabled
        ? [UIColor colorWithRed:0.10 green:0.62 blue:0.30 alpha:0.75]
        : [UIColor colorWithWhite:0.30 alpha:0.60];
    [g_ballButton setTitle:(g_enabled ? @"广告关" : @"广告停")
                  forState:UIControlStateNormal];
    [g_ballButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    g_ballButton.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
}

static void ADOnBallTapped(void) {
    g_enabled = !g_enabled;
    ADUpdateBallLook();
    ADSaveConfig();
    ADLog(@"开关切换 → %@", g_enabled ? @"开" : @"关");
}

static void ADOnBallPan(UIPanGestureRecognizer *g) {
    if (!g_ballWindow) return;
    CGPoint t = [g translationInView:nil];
    CGRect screen = [UIScreen mainScreen].bounds;
    CGFloat half = 22.0;
    CGPoint c = CGPointMake(g_ballWindow.center.x + t.x, g_ballWindow.center.y + t.y);
    c.x = MAX(half + 4, MIN(screen.size.width - half - 4, c.x));
    c.y = MAX(half + 30, MIN(screen.size.height - half - 4, c.y));
    g_ballWindow.center = c;
    [g setTranslation:CGPointZero inView:nil];
    g_ballCenter = c;
}

static void ADOnBallPanEnd(void) {
    ADSaveConfig();
}

// iOS 13+ 必须给 window 关联 windowScene，否则窗口不会显示
static UIWindowScene *ADActiveWindowScene(void) {
    if (@available(iOS 13.0, *)) {
        UIWindowScene *fallback = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)s;
            if (ws.activationState == UISceneActivationStateForegroundActive) return ws;
            if (!fallback) fallback = ws;
        }
        return fallback;
    }
    return nil;
}

static void ADInstallBall(void) {
    @try {
        if (g_ballWindow) return;
        UIWindowScene *scene = ADActiveWindowScene();
        if (@available(iOS 13.0, *)) {
            // 场景还没连上：等一会儿再试（最多 10 次）
            if (!scene && g_ballRetry < 10) {
                g_ballRetry++;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ ADInstallBall(); });
                return;
            }
        }
        CGRect screen = [UIScreen mainScreen].bounds;
        CGFloat side = 44.0;
        CGPoint center = g_ballCenter;
        if (center.x <= 0 || center.y <= 0) {
            center = CGPointMake(screen.size.width - side / 2 - 6, screen.size.height * 0.30);
        }
        g_ballWindow = [[UIWindow alloc] initWithFrame:
            CGRectMake(center.x - side / 2, center.y - side / 2, side, side)];
        if (@available(iOS 13.0, *)) {
            if (scene) g_ballWindow.windowScene = scene;
        }
        g_ballWindow.windowLevel = UIWindowLevelAlert + 100;
        g_ballWindow.backgroundColor = [UIColor clearColor];
        g_ballWindow.rootViewController = [UIViewController new];
        g_ballWindow.hidden = NO;

        g_ballButton = [UIButton buttonWithType:UIButtonTypeCustom];
        g_ballButton.frame = CGRectMake(0, 0, side, side);
        g_ballButton.layer.cornerRadius = side / 2;
        g_ballButton.clipsToBounds = YES;
        g_ballButton.layer.borderWidth = 1.0;
        g_ballButton.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.5].CGColor;
        [g_ballButton addTarget:[ADTarget shared]
                         action:@selector(ballTapped)
               forControlEvents:UIControlEventTouchUpInside];
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
            initWithTarget:[ADTarget shared] action:@selector(ballPan:)];
        pan.cancelsTouchesInView = NO;   // 拖动不吞掉点击
        [g_ballButton addGestureRecognizer:pan];
        [g_ballWindow.rootViewController.view addSubview:g_ballButton];
        ADUpdateBallLook();
        ADLog(@"悬浮球已安装（开关=%@，scene=%@）",
              g_enabled ? @"开" : @"关", scene ? @"有" : @"无");
    } @catch (NSException *e) {
        ADLog(@"悬浮球安装失败：%@", e.reason);
    }
}

#pragma mark - 广告页监听

static NSHashTable *g_watching = nil;
static NSMapTable *g_timers = nil;

/// 这个按钮现在真的能点吗（多层可见性检查）
static BOOL ADButtonClickable(UIButton *b) {
    if (!b || ![b isKindOfClass:[UIButton class]]) return NO;
    if (b.hidden || !b.enabled || b.alpha < 0.05) return NO;
    if (!b.window) return NO;
    UIView *sup = b.superview;
    int guard = 0;
    while (sup && guard++ < 12) {
        if (sup.hidden || sup.alpha < 0.05) return NO;
        sup = sup.superview;
    }
    return YES;
}

/// 找「关闭广告」按钮：只认 ivar 名含 close 的 UIButton
static UIButton *ADFindCloseButton(UIViewController *vc) {
    unsigned int n = 0;
    Ivar *ivars = class_copyIvarList([vc class], &n);
    if (!ivars || n == 0) { if (ivars) free(ivars); return nil; }
    UIButton *found = nil;
    for (unsigned int i = 0; i < n; i++) {
        const char *nm = ivar_getName(ivars[i]);
        const char *enc = ivar_getTypeEncoding(ivars[i]);
        if (!nm || !enc || enc[0] != '@') continue;
        NSString *name = [[NSString stringWithUTF8String:nm] lowercaseString];
        if (![name containsString:@"close"]) continue;
        id v = nil;
        @try { v = object_getIvar(vc, ivars[i]); } @catch (NSException *e) { continue; }
        if ([v isKindOfClass:[UIButton class]] && ADButtonClickable((UIButton *)v)) {
            found = (UIButton *)v;
            break;
        }
    }
    free(ivars);
    return found;
}

static void ADTryCloseAd(UIViewController *vc) {
    if (!g_enabled || !vc) return;
    UIButton *btn = ADFindCloseButton(vc);
    if (!btn) return;
    ADLog(@"点到关闭按钮：%@ title=%@",
          NSStringFromClass([btn class]), btn.titleLabel.text ?: @"-");
    [btn sendActionsForControlEvents:UIControlEventTouchUpInside];
}

/// 只对广告页工作。即使 swizzle 影响到所有 VC，这里也会拦住。
static BOOL ADIsAdPage(UIViewController *vc) {
    if (!vc) return NO;
    NSString *n = NSStringFromClass([vc class]);
    if (!n.length) return NO;
    return [n containsString:@"VendorAdRewardVideo"] ||
           [n containsString:@"RewardVideoView"] ||
           [n containsString:@"BNMAdView"];
}

static void ADStartWatch(UIViewController *vc) {
    if (!vc || !ADIsAdPage(vc)) return;
    if (!g_watching) g_watching = [NSHashTable weakObjectsHashTable];
    if (!g_timers) g_timers = [NSMapTable weakToStrongObjectsMapTable];
    if ([g_watching containsObject:vc]) return;
    [g_watching addObject:vc];

    __weak UIViewController *weakVC = vc;
    NSTimer *t = [NSTimer scheduledTimerWithTimeInterval:0.5
                                                 repeats:YES
                                                   block:^(NSTimer *timer) {
        UIViewController *strongVC = weakVC;
        if (!strongVC || !strongVC.view.window) { [timer invalidate]; return; }
        @try { ADTryCloseAd(strongVC); } @catch (NSException *e) {}
    }];
    [g_timers setObject:t forKey:vc];
    ADLog(@"广告页出现，开始监听：%@", NSStringFromClass([vc class]));
}

static void ADStopWatch(UIViewController *vc) {
    if (!vc || !g_timers) return;
    NSTimer *t = [g_timers objectForKey:vc];
    if (t) { [t invalidate]; [g_timers removeObjectForKey:vc]; }
    if (g_watching) [g_watching removeObject:vc];
    ADLog(@"广告页消失，停止监听：%@", NSStringFromClass([vc class]));
}

#pragma mark - hook 安装

static void ADSwizzle(Class cls, SEL orig, SEL repl) {
    Method m1 = class_getInstanceMethod(cls, orig);
    Method m2 = class_getInstanceMethod(cls, repl);
    if (!m1 || !m2) return;
    if (m1 == m2) return;
    method_exchangeImplementations(m1, m2);
}

@implementation UIViewController (ADAutoClose)
- (void)adac_viewDidAppear:(BOOL)animated {
    [self adac_viewDidAppear:animated];
    @try { ADStartWatch(self); } @catch (NSException *e) {}
}
- (void)adac_viewDidDisappear:(BOOL)animated {
    @try { ADStopWatch(self); } @catch (NSException *e) {}
    [self adac_viewDidDisappear:animated];
}
@end

static void ADInstallHooks(void) {
    @try {
        for (NSString *name in @[@"BBAVendorAdRewardVideoViewController",
                                 @"BBAVendorAdRewardVideoController"]) {
            Class cls = NSClassFromString(name);
            if (!cls) { ADLog(@"没找到类：%@", name); continue; }
            ADSwizzle(cls, @selector(viewDidAppear:), @selector(adac_viewDidAppear:));
            ADSwizzle(cls, @selector(viewDidDisappear:), @selector(adac_viewDidDisappear:));
            ADLog(@"已挂钩：%@", name);
        }
    } @catch (NSException *e) {
        ADLog(@"挂钩失败：%@", e.reason);
    }
}

#pragma mark - 入口

__attribute__((constructor))
static void ADInit(void) {
    @autoreleasepool {
        NSString *bid = [NSBundle mainBundle].bundleIdentifier;
        if (![bid isEqualToString:@"com.baidu.BaiduMobileInfo"]) return;
        ADLoadConfig();
        ADLog(@"==== AdAutoClose 启动（开关=%@）====", g_enabled ? @"开" : @"关");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            ADInstallHooks();
            ADInstallBall();
        });
    }
}
