//
//  KSProbe.m —— 快手检测探针（只读）+ 悬浮窗显示结果
//
//  注入快手后：
//    ① 在快手进程内做检测（rootless 特征 / dyld 镜像 / 环境变量 / cydia scheme）
//    ② 屏幕右侧出现绿色小圆球「检测」：点一下展开结果面板，再点收起
//    ③ 结果同时写入 Documents/ksprobe_log.txt（完整版）
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>
#import <stdlib.h>
#import <string.h>

static NSString *g_result = nil;
static NSString *g_logPath = nil;
static UIWindow *g_ballWin = nil;
static UIWindow *g_panelWin = nil;
static UIView *g_ball = nil;
static UILabel *g_ballLabel = nil;
static UIView *g_panel = nil;
static UITextView *g_text = nil;
static BOOL g_expanded = NO;
static CGPoint g_ballCenter = {0, 0};

#pragma mark - 检测

static NSString *KSRunProbe(void) {
    NSMutableString *s = [NSMutableString string];
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"MM-dd HH:mm:ss";
    [s appendFormat:@"KSProbe %@\n", [df stringFromDate:[NSDate date]]];
    [s appendFormat:@"bid=%@\n\n", [NSBundle mainBundle].bundleIdentifier];

    [s appendString:@"=== 关键路径 ===\n"];
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
    for (NSString *p in paths) {
        struct stat st;
        BOOL ok = (stat(p.UTF8String, &st) == 0);
        BOOL lok = (lstat(p.UTF8String, &st) == 0);
        [s appendFormat:@"%@ %@%s\n",
            (ok || lok) ? @"可见" : @"隐藏",
            p,
            (ok != lok) ? " (stat/lstat不一致)" : ""];
    }

    [s appendString:@"\n=== dyld ===\n"];
    uint32_t n = _dyld_image_count();
    [s appendFormat:@"镜像数 %u\n", n];
    int jb = 0;
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        NSString *p = [NSString stringWithUTF8String:nm] ?: @"";
        if ([p containsString:@"/jb/"] || [p containsString:@"Substrate"] ||
            [p containsString:@"substitute"] || [p containsString:@"KSProbe"] ||
            [p containsString:@"ellkit"] || [p containsString:@"libhooker"]) {
            jb++;
            [s appendFormat:@"  ★ %@\n", p.lastPathComponent];
        }
    }
    [s appendFormat:@"可疑镜像 %d 个\n", jb];

    // ── 读 gifCommonFramework 里那个加密关键字（运行时可能已解密）──
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (!strstr(nm, "gifCommonFramework")) continue;
        const uint8_t *base = (const uint8_t *)_dyld_get_image_header(i);
        if (!base) break;
        const uint8_t *p = base + 0x9cfe5;
        [s appendString:@"\n=== gifCommonFramework+0x9cfe5 ===\n"];
        [s appendString:@"hex: "];
        for (int k = 0; k < 48; k++) [s appendFormat:@"%02x", p[k]];
        [s appendString:@"\nascii: "];
        for (int k = 0; k < 48; k++) {
            unsigned char c = p[k];
            [s appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
        }
        [s appendString:@"\n"];
        break;
    }

    const char *env = getenv("DYLD_INSERT_LIBRARIES");
    [s appendFormat:@"\nDYLD_INSERT_LIBRARIES=%s\n", env ? env : "(null)"];

    BOOL cydia = NO;
    @try {
        cydia = [[UIApplication sharedApplication]
                    canOpenURL:[NSURL URLWithString:@"cydia://"]];
    } @catch (NSException *e) {}
    [s appendFormat:@"cydia:// 可打开=%d\n", cydia];
    [s appendFormat:@"uid=%d euid=%d\n", getuid(), geteuid()];

    NSDictionary *e = [[NSProcessInfo processInfo] environment];
    for (NSString *k in @[@"_MSSafeMode", @"JB_ROOT", @"ROOTHIDE", @"DYLD_LIBRARY_PATH"]) {
        if (e[k]) [s appendFormat:@"env[%@]=%@\n", k, e[k]];
    }
    return s;
}

static UIWindowScene *KSActiveScene(void) {
    if (@available(iOS 13.0, *)) {
        UIWindowScene *fb = nil;
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            if (ws.activationState == UISceneActivationStateForegroundActive) return ws;
            if (!fb) fb = ws;
        }
        return fb;
    }
    return nil;
}

static void KSShowPanel(BOOL show) {
    if (!g_panelWin) return;
    @try {
        CGRect screen = [UIScreen mainScreen].bounds;
        CGFloat w = MIN(340, screen.size.width - 24);
        CGFloat h = MIN(430, screen.size.height * 0.55);
        g_panelWin.hidden = !show;
        if (show) {
            g_panelWin.frame = CGRectMake((screen.size.width - w) / 2,
                                          (screen.size.height - h) / 2, w, h);
            g_panel.frame = CGRectMake(0, 0, w, h);
            g_text.frame = CGRectMake(8, 8, w - 16, h - 16);
            g_text.text = g_result ?: @"(未采集)";
        }
    } @catch (NSException *e) {}
}

@interface KSTarget : NSObject
+ (instancetype)shared;
- (void)tap;
- (void)pan:(UIPanGestureRecognizer *)g;
@end

@implementation KSTarget
+ (instancetype)shared {
    static KSTarget *s;
    static dispatch_once_t o;
    dispatch_once(&o, ^{ s = [KSTarget new]; });
    return s;
}
- (void)tap {
    g_expanded = !g_expanded;
    KSShowPanel(g_expanded);
    g_ballLabel.text = g_expanded ? @"关闭" : @"检测";
    g_ball.backgroundColor = g_expanded
        ? [UIColor colorWithRed:0.78 green:0.16 blue:0.16 alpha:0.95]
        : [UIColor colorWithRed:0.10 green:0.62 blue:0.30 alpha:0.92];
}
- (void)pan:(UIPanGestureRecognizer *)g {
    if (!g_ballWin) return;
    CGPoint t = [g translationInView:nil];
    CGRect screen = [UIScreen mainScreen].bounds;
    CGPoint c = CGPointMake(g_ballWin.center.x + t.x, g_ballWin.center.y + t.y);
    c.x = MAX(30, MIN(screen.size.width - 30, c.x));
    c.y = MAX(40, MIN(screen.size.height - 30, c.y));
    g_ballWin.center = c;
    [g setTranslation:CGPointZero inView:nil];
    g_ballCenter = c;
}
@end

static void KSInstallBall(void) {
    @try {
        if (g_ballWin) return;
        UIWindowScene *scene = KSActiveScene();
        if (@available(iOS 13.0, *)) {
            if (!scene) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ KSInstallBall(); });
                return;
            }
        }
        CGRect screen = [UIScreen mainScreen].bounds;
        CGFloat side = 52.0;
        CGPoint center = g_ballCenter;
        if (center.x <= 0) {
            center = CGPointMake(screen.size.width - side / 2 - 8,
                                 screen.size.height * 0.35);
        }

        // ── 球（只占 52x52，不挡快手操作）──
        g_ballWin = [[UIWindow alloc] initWithFrame:CGRectMake(center.x - side / 2,
                                                               center.y - side / 2,
                                                               side, side)];
        if (@available(iOS 13.0, *)) { if (scene) g_ballWin.windowScene = scene; }
        g_ballWin.windowLevel = UIWindowLevelAlert + 100;
        g_ballWin.backgroundColor = [UIColor clearColor];
        g_ballWin.rootViewController = [UIViewController new];
        g_ballWin.hidden = NO;

        g_ball = [[UIView alloc] initWithFrame:CGRectMake(0, 0, side, side)];
        g_ball.layer.cornerRadius = side / 2;
        g_ball.clipsToBounds = YES;
        g_ball.backgroundColor = [UIColor colorWithRed:0.10 green:0.62 blue:0.30 alpha:0.92];
        g_ball.userInteractionEnabled = YES;
        [g_ball addGestureRecognizer:[[UITapGestureRecognizer alloc]
            initWithTarget:[KSTarget shared] action:@selector(tap)]];
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
            initWithTarget:[KSTarget shared] action:@selector(pan:)];
        pan.cancelsTouchesInView = NO;
        [g_ball addGestureRecognizer:pan];

        g_ballLabel = [[UILabel alloc] initWithFrame:g_ball.bounds];
        g_ballLabel.text = @"检测";
        g_ballLabel.textColor = [UIColor whiteColor];
        g_ballLabel.font = [UIFont boldSystemFontOfSize:13];
        g_ballLabel.textAlignment = NSTextAlignmentCenter;
        [g_ball addSubview:g_ballLabel];
        [g_ballWin.rootViewController.view addSubview:g_ball];

        // ── 结果面板窗口（默认隐藏，点击球时显示）──
        CGFloat w = MIN(340, screen.size.width - 24);
        CGFloat h = MIN(430, screen.size.height * 0.55);
        g_panelWin = [[UIWindow alloc] initWithFrame:CGRectMake((screen.size.width - w) / 2,
                                                                (screen.size.height - h) / 2,
                                                                w, h)];
        if (@available(iOS 13.0, *)) { if (scene) g_panelWin.windowScene = scene; }
        g_panelWin.windowLevel = UIWindowLevelAlert + 99;
        g_panelWin.backgroundColor = [UIColor clearColor];
        g_panelWin.rootViewController = [UIViewController new];
        g_panelWin.hidden = YES;

        g_panel = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, h)];
        g_panel.backgroundColor = [UIColor colorWithWhite:0.05 alpha:0.93];
        g_panel.layer.cornerRadius = 12;
        g_panel.clipsToBounds = YES;

        g_text = [[UITextView alloc] initWithFrame:CGRectMake(8, 8, w - 16, h - 16)];
        g_text.backgroundColor = [UIColor clearColor];
        g_text.textColor = [UIColor whiteColor];
        g_text.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
        g_text.editable = NO;
        g_text.selectable = YES;
        g_text.text = g_result ?: @"(未采集)";
        [g_panel addSubview:g_text];
        [g_panelWin.rootViewController.view addSubview:g_panel];
    } @catch (NSException *e) {}
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
            g_result = KSRunProbe();
            NSString *docs = [NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
            g_logPath = [docs stringByAppendingPathComponent:@"ksprobe_log.txt"];
            [g_result writeToFile:g_logPath atomically:YES
                         encoding:NSUTF8StringEncoding error:NULL];

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                KSInstallBall();
            });
        } @catch (NSException *e) {}
    }
}
