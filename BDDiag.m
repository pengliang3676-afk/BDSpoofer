//
//  BDDiag.m —— 百度极速版 设备信息采集「只读诊断」dylib
//  目标：com.baidu.BaiduMobileInfo
//
//  原则：
//   1) 只读、只记录，绝不伪造。所有 hook 方法都调用原实现并原样返回，App 行为与未注入一致。
//   2) 热路径只用“数字返回地址”做键，命中过的调用点仅 +1（不做 dladdr/字符串/锁内重活）；
//      首次出现的调用点才抓原始返回地址，符号化统一延迟到导出报告时（此时方法索引已建好）。
//   3) 跳过“本 dylib 自身镜像”的栈帧按地址区间判断，不依赖固定帧数，兼容 -O2 内联。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <execinfo.h>
#import <os/lock.h>
#import <ptrauth.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

static NSString *const kTargetBundle = @"com.baidu.BaiduMobileInfo";

// arm64e 下去除函数指针的 PAC 签名高位，否则与地址区间比较会全部落空。
static void *bdd_strip(void *p) {
#ifdef __arm64e__
    return ptrauth_strip(p, ptrauth_key_asia);
#else
    return p;
#endif
}

// MARK: - 镜像区间
static const struct mach_header *g_mainHeader = NULL; // image 0（主二进制，已含 slide）
static uintptr_t g_mainLow = 0, g_mainHigh = 0;       // 主 __TEXT 运行时区间
static uintptr_t g_ownLow = 0, g_ownHigh = 0;         // 本诊断 dylib __TEXT 区间（用于剔除自身栈帧）

static void bdd_textRangeOfImage(const struct mach_header *hp, intptr_t slide, uintptr_t *lo, uintptr_t *hi) {
    *lo = (uintptr_t)hp; *hi = *lo;
    if (!hp) return;
    uintptr_t lc = (uintptr_t)hp + sizeof(struct mach_header_64);
    struct load_command *cmd = (struct load_command *)lc;
    for (uint32_t i = 0; i < hp->ncmds; i++, cmd = (void *)((uintptr_t)cmd + cmd->cmdsize)) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                *lo = (uintptr_t)seg->vmaddr + slide;
                *hi = *lo + seg->vmsize;
                return;
            }
        }
    }
}
static void bdd_setupRanges(void *addrInSelf) {
    // 主二进制 = image 0
    const struct mach_header *mh = (const struct mach_header *)_dyld_get_image_header(0);
    intptr_t mslide = _dyld_get_image_vmaddr_slide(0);
    g_mainHeader = mh;
    bdd_textRangeOfImage(mh, mslide, &g_mainLow, &g_mainHigh);

    // 自身镜像：用本函数地址反查 fbase，再找到对应 image 取 __TEXT
    Dl_info info;
    if (dladdr(addrInSelf, &info) && info.dli_fbase) {
        uint32_t cnt = _dyld_image_count();
        for (uint32_t i = 0; i < cnt; i++) {
            if ((void *)_dyld_get_image_header(i) == info.dli_fbase) {
                const struct mach_header *oh = _dyld_get_image_header(i);
                intptr_t oslide = _dyld_get_image_vmaddr_slide(i);
                bdd_textRangeOfImage(oh, oslide, &g_ownLow, &g_ownHigh);
                break;
            }
        }
    }
}
static BOOL bdd_inMain(const void *p) {
    return (uintptr_t)p >= g_mainLow && (uintptr_t)p < g_mainHigh;
}
static BOOL bdd_inSelf(uintptr_t p) {
    return g_ownLow && p >= g_ownLow && p < g_ownHigh;
}

// MARK: - ObjC 方法地址索引（主二进制 IMP -> "+/-[Class sel]"），加锁发布
static os_unfair_lock g_idxLock = OS_UNFAIR_LOCK_INIT;
static NSArray<NSDictionary *> *g_methodIndex = nil;

static void bdd_buildMethodIndex(void) {
    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:20000];
    unsigned int clsCount = 0;
    Class *classes = objc_copyClassList(&clsCount);
    for (unsigned int ci = 0; ci < clsCount; ci++) {
        Class cls = classes[ci];
        if (!cls) continue;
        const char *clsName = class_getName(cls);
        Class lists[2] = { cls, object_getClass(cls) };
        char prefix[2] = {'-', '+'};
        for (int mi = 0; mi < 2; mi++) {
            unsigned int mc = 0;
            Method *methods = class_copyMethodList(lists[mi], &mc);
            for (unsigned int k = 0; k < mc; k++) {
                void *imp = bdd_strip((void *)method_getImplementation(methods[k]));
                if (!bdd_inMain(imp)) continue;
                SEL sel = method_getName(methods[k]);
                NSString *n = [NSString stringWithFormat:@"%c[%s %s]", prefix[mi], clsName, sel_getName(sel)];
                [arr addObject:@{@"p": @((uintptr_t)imp), @"n": n}];
            }
            free(methods);
        }
    }
    free(classes);
    [arr sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"p"] compare:b[@"p"]];
    }];
    os_unfair_lock_lock(&g_idxLock);
    g_methodIndex = [arr copy];
    os_unfair_lock_unlock(&g_idxLock);
}

// MARK: - 记录存储（热路径：数字地址做键，仅首次抓栈）
static os_unfair_lock g_storeLock = OS_UNFAIR_LOCK_INIT;
// api -> { @(siteAddr): {count, frames:[@(addr)...]} }
static NSMutableDictionary<NSString *, NSMutableDictionary<NSNumber *, NSMutableDictionary *> *> *g_byApi = nil;
static NSUInteger g_siteTotal = 0;
static const NSUInteger kMaxSites = 600;
// 诊断自身创建浮窗等会读取 UIScreen，置位期间当前线程不记录，避免制造假调用点（线程局部，不影响其他线程）
static _Thread_local int t_suppress = 0;

// externalRA：由各交换方法用 __builtin_return_address(0) 直接传入（即外部调用方），
// 不依赖多层栈帧深度，最稳。
__attribute__((noinline))
static void bdd_note(NSString *api, void *externalRA) {
    if (!api || !externalRA || t_suppress) return;
    NSNumber *key = @((uintptr_t)externalRA);

    // 快速路径：已记录的调用点仅 +1，不做 backtrace（高频路径零抓栈）。
    os_unfair_lock_lock(&g_storeLock);
    NSMutableDictionary *subFast = g_byApi[api];
    NSMutableDictionary *fast = subFast[key];
    if (fast) {
        fast[@"count"] = @([fast[@"count"] unsignedIntegerValue] + 1);
        os_unfair_lock_unlock(&g_storeLock);
        return;
    }
    os_unfair_lock_unlock(&g_storeLock);

    // 首次出现：完整抓栈，按本 dylib 镜像区间剔除自身帧，仅作上下文。
    void *bt[10];
    int n = backtrace(bt, 10);
    NSMutableArray<NSNumber *> *chain = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        uintptr_t p = (uintptr_t)bt[i];
        if (bdd_inSelf(p)) continue;
        if (chain.count < 16) [chain addObject:@(p)];
    }

    os_unfair_lock_lock(&g_storeLock);
    if (!g_byApi) g_byApi = [NSMutableDictionary dictionary];
    NSMutableDictionary *sub = g_byApi[api];
    if (!sub) { sub = [NSMutableDictionary dictionary]; g_byApi[api] = sub; }
    NSMutableDictionary *rec = sub[key];
    if (rec) {
        rec[@"count"] = @([rec[@"count"] unsignedIntegerValue] + 1);
        os_unfair_lock_unlock(&g_storeLock);
        return;
    }
    if (g_siteTotal >= kMaxSites) { os_unfair_lock_unlock(&g_storeLock); return; }
    rec = [NSMutableDictionary dictionary];
    rec[@"count"] = @1;
    rec[@"frames"] = chain;
    sub[key] = rec;
    g_siteTotal++;
    os_unfair_lock_unlock(&g_storeLock);
}

// MARK: - 交换方法（原值原样透传，仅记录）
@interface UIScreen (BDDiag)
- (CGRect)bd_bounds;
- (CGRect)bd_nativeBounds;
- (CGRect)bd_applicationFrame;
- (CGFloat)bd_scale;
- (CGFloat)bd_nativeScale;
@end
@interface UIDevice (BDDiag)
- (NSString *)bd_systemVersion;
- (NSString *)bd_model;
- (NSString *)bd_localizedModel;
- (NSString *)bd_systemName;
- (NSString *)bd_name;
- (NSUUID *)bd_identifierForVendor;
@end

@implementation UIScreen (BDDiag)
- (CGRect)bd_bounds { bdd_note(@"UIScreen.bounds", __builtin_return_address(0)); return [self bd_bounds]; }
- (CGRect)bd_nativeBounds { bdd_note(@"UIScreen.nativeBounds", __builtin_return_address(0)); return [self bd_nativeBounds]; }
- (CGRect)bd_applicationFrame { bdd_note(@"UIScreen.applicationFrame", __builtin_return_address(0)); return [self bd_applicationFrame]; }
- (CGFloat)bd_scale { bdd_note(@"UIScreen.scale", __builtin_return_address(0)); return [self bd_scale]; }
- (CGFloat)bd_nativeScale { bdd_note(@"UIScreen.nativeScale", __builtin_return_address(0)); return [self bd_nativeScale]; }
@end
@implementation UIDevice (BDDiag)
- (NSString *)bd_systemVersion { bdd_note(@"UIDevice.systemVersion", __builtin_return_address(0)); return [self bd_systemVersion]; }
- (NSString *)bd_model { bdd_note(@"UIDevice.model", __builtin_return_address(0)); return [self bd_model]; }
- (NSString *)bd_localizedModel { bdd_note(@"UIDevice.localizedModel", __builtin_return_address(0)); return [self bd_localizedModel]; }
- (NSString *)bd_systemName { bdd_note(@"UIDevice.systemName", __builtin_return_address(0)); return [self bd_systemName]; }
- (NSString *)bd_name { bdd_note(@"UIDevice.name", __builtin_return_address(0)); return [self bd_name]; }
- (NSUUID *)bd_identifierForVendor { bdd_note(@"UIDevice.identifierForVendor", __builtin_return_address(0)); return [self bd_identifierForVendor]; }
@end

// 安全 swizzle：若原方法继承自父类，先 class_addMethod 到本类，避免改动父类 Method。
static void bdd_swizzle(Class cls, SEL orig, SEL swz) {
    Method om = class_getInstanceMethod(cls, orig);
    Method sm = class_getInstanceMethod(cls, swz);
    if (!om || !sm) return;
    BOOL added = class_addMethod(cls, orig, method_getImplementation(sm), method_getTypeEncoding(sm));
    if (added) {
        class_replaceMethod(cls, swz, method_getImplementation(om), method_getTypeEncoding(om));
    } else {
        method_exchangeImplementations(om, sm);
    }
}

// MARK: - 符号化（仅导出时执行）
static NSString *bdd_nearestMethod(const void *p) {
    NSArray *idx;
    os_unfair_lock_lock(&g_idxLock); idx = [g_methodIndex copy]; os_unfair_lock_unlock(&g_idxLock);
    if (!idx.count || !bdd_inMain(p)) return nil;
    NSInteger lo = 0, hi = (NSInteger)idx.count - 1, best = -1;
    uintptr_t target = (uintptr_t)p;
    while (lo <= hi) {
        NSInteger mid = (lo + hi) / 2;
        uintptr_t v = [idx[mid][@"p"] unsignedIntegerValue];
        if (v <= target) { best = mid; lo = mid + 1; } else hi = mid - 1;
    }
    if (best < 0) return nil;
    uintptr_t base = [idx[best][@"p"] unsignedIntegerValue];
    return [NSString stringWithFormat:@"~%@+0x%lx", idx[best][@"n"], (unsigned long)(target - base)];
}
static NSString *bdd_formatFrame(const void *p) {
    Dl_info info;
    NSString *image = @"?";
    uintptr_t base = 0;
    if (dladdr(p, &info) && info.dli_fname) {
        image = [[NSString stringWithUTF8String:info.dli_fname] lastPathComponent];
        base = (uintptr_t)info.dli_fbase;
    }
    uintptr_t off = base ? ((uintptr_t)p - base) : 0;
    NSString *near = bdd_inMain(p) ? bdd_nearestMethod(p) : nil;
    if (near) return [NSString stringWithFormat:@"%@  %@  (img+0x%lx)", image, near, (unsigned long)off];
    return [NSString stringWithFormat:@"%@  img+0x%lx", image, (unsigned long)off];
}

// MARK: - 导出
@interface BDDiagStore : NSObject
+ (NSString *)buildReport;
+ (NSURL *)writeReport;
+ (void)share;
@end
@implementation BDDiagStore
+ (NSString *)buildReport {
    // 仅当后台索引尚未建好（过早导出）时才同步补建，避免常规导出时全量扫描卡顿。
    os_unfair_lock_lock(&g_idxLock); BOOL empty = (g_methodIndex.count == 0); os_unfair_lock_unlock(&g_idxLock);
    if (empty) bdd_buildMethodIndex();
    // 锁内做深拷贝快照，离开锁后不再触碰可变容器
    NSMutableArray<NSDictionary *> *snap = [NSMutableArray array];
    os_unfair_lock_lock(&g_storeLock);
    [g_byApi enumerateKeysAndObjectsUsingBlock:^(NSString *api, NSMutableDictionary *sub, BOOL *stop) {
        [sub enumerateKeysAndObjectsUsingBlock:^(NSNumber *siteAddr, NSMutableDictionary *rec, BOOL *s2) {
            [snap addObject:@{@"api": api,
                              @"site": siteAddr,
                              @"count": rec[@"count"],
                              @"frames": [rec[@"frames"] copy]}];
        }];
    }];
    os_unfair_lock_unlock(&g_storeLock);

    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"BDDiag 只读诊断报告\n生成时间: %@\n主二进制: %s  区间 0x%lx-0x%lx\n本诊断镜像区间: 0x%lx-0x%lx\n不同调用点: %lu\n（~ 表示最近 ObjC 方法为近似归属）\n",
     [NSDate date], _dyld_get_image_name(0) ?: "(null)",
     (unsigned long)g_mainLow, (unsigned long)g_mainHigh,
     (unsigned long)g_ownLow, (unsigned long)g_ownHigh, (unsigned long)snap.count];

    NSMutableSet *apiSet = [NSMutableSet set];
    for (NSDictionary *r in snap) [apiSet addObject:r[@"api"]];
    NSArray *apis = [apiSet.allObjects sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *api in apis) {
        NSArray *rows = [snap filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"api == %@", api]];
        rows = [rows sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [b[@"count"] compare:a[@"count"]];
        }];
        [out appendFormat:@"\n==================== %@ （%lu 个调用点）====================\n", api, (unsigned long)rows.count];
        for (NSDictionary *r in rows) {
            uintptr_t sa = [r[@"site"] unsignedIntegerValue];
            [out appendFormat:@"\n● 命中 %@ 次  调用点: %@\n", r[@"count"], bdd_formatFrame((void *)sa)];
            for (NSNumber *f in r[@"frames"]) [out appendFormat:@"      %@\n", bdd_formatFrame((void *)f.unsignedIntegerValue)];
        }
    }
    return out;
}
+ (NSURL *)writeReport {
    NSString *text = [self buildReport];
    NSString *doc = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *name = [NSString stringWithFormat:@"BDDiag_log_%@.txt", [NSDate date]];
    name = [[name componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@": /"]]
            componentsJoinedByString:@"_"];
    NSString *path = [doc stringByAppendingPathComponent:name];
    NSError *e = nil;
    BOOL ok = [text writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&e];
    [UIPasteboard generalPasteboard].string = text;   // 始终兜底到剪贴板
    return (ok && !e) ? [NSURL fileURLWithPath:path] : nil;
}
+ (void)share {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSURL *url = [self writeReport];
        UIViewController *vc = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:UIWindowScene.class] && s.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in ((UIWindowScene *)s).windows) if (w.isKeyWindow) { vc = w.rootViewController; break; }
            }
        }
        while (vc.presentedViewController) vc = vc.presentedViewController;
        if (!vc) return;
        NSArray *items = url ? @[url] : @[[UIPasteboard generalPasteboard].string ?: @""];
        UIActivityViewController *ac = [[UIActivityViewController alloc] initWithActivityItems:items applicationActivities:nil];
        ac.popoverPresentationController.sourceView = vc.view;
        [vc presentViewController:ac animated:YES completion:nil];
    });
}
@end

// MARK: - 浮窗：自定义 UIWindow，命中窗口/根视图时返回 nil，保证触摸真正透传给 App
@interface BDDiagWindow : UIWindow @end
@implementation BDDiagWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *h = [super hitTest:point withEvent:event];
    return (h == self || h == self.rootViewController.view) ? nil : h;
}
@end
@interface UIButton (BDDiagDrag)
- (void)bd_drag:(UIPanGestureRecognizer *)g;
@end

static BDDiagWindow *g_floatWindow = nil;
static void bdd_showFloat(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_floatWindow) return;
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes)
            if ([s isKindOfClass:UIWindowScene.class] && s.activationState == UISceneActivationStateForegroundActive)
                { scene = (UIWindowScene *)s; break; }
        if (!scene) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ bdd_showFloat(); });
            return;
        }
        t_suppress++;   // 仅当前主线程抑制：浮窗自身会读 UIScreen.bounds，避免假调用点
        @try {
        BDDiagWindow *w = [[BDDiagWindow alloc] initWithWindowScene:scene];
        w.frame = UIScreen.mainScreen.bounds;
        w.windowLevel = UIWindowLevelAlert + 100;
        UIViewController *vc = [UIViewController new];
        vc.view.backgroundColor = UIColor.clearColor;
        w.rootViewController = vc;

        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(8, 180, 132, 40);
        b.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.72];
        [b setTitle:@"BDDiag 导出日志" forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont systemFontOfSize:13];
        [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
        b.layer.cornerRadius = 8;
        [b addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:b action:@selector(bd_drag:)]];
        [b addTarget:[BDDiagStore class] action:@selector(share) forControlEvents:UIControlEventTouchUpInside];
        [vc.view addSubview:b];
        w.hidden = NO;
        g_floatWindow = w;
        } @finally { t_suppress--; }
    });
}
@implementation UIButton (BDDiagDrag)
- (void)bd_drag:(UIPanGestureRecognizer *)g {
    UIView *sup = self.superview;
    CGPoint t = [g translationInView:sup];
    CGPoint c = self.center; c.x += t.x; c.y += t.y; self.center = c;
    [g setTranslation:CGPointZero inView:sup];
}
@end

// MARK: - 入口
__attribute__((constructor))
static void bdd_start(void) {
    @autoreleasepool {
        NSString *bid = NSBundle.mainBundle.bundleIdentifier ?: @"";
        if (![bid isEqualToString:kTargetBundle]) return;
        NSString *ext = NSBundle.mainBundle.bundlePath.pathExtension.lowercaseString;
        if (![ext isEqualToString:@"app"]) return;

        bdd_setupRanges((void *)&bdd_start);
        // 自身/主二进制镜像区间必须解析成功，否则无法区分自身帧，宁可不记录也不产出脏数据。
        if (!g_ownLow || g_ownHigh <= g_ownLow || !g_mainLow || g_mainHigh <= g_mainLow) return;

        bdd_swizzle(UIScreen.class, @selector(bounds), @selector(bd_bounds));
        bdd_swizzle(UIScreen.class, @selector(nativeBounds), @selector(bd_nativeBounds));
        bdd_swizzle(UIScreen.class, @selector(applicationFrame), @selector(bd_applicationFrame));
        bdd_swizzle(UIScreen.class, @selector(scale), @selector(bd_scale));
        bdd_swizzle(UIScreen.class, @selector(nativeScale), @selector(bd_nativeScale));

        bdd_swizzle(UIDevice.class, @selector(systemVersion), @selector(bd_systemVersion));
        bdd_swizzle(UIDevice.class, @selector(model), @selector(bd_model));
        bdd_swizzle(UIDevice.class, @selector(localizedModel), @selector(bd_localizedModel));
        bdd_swizzle(UIDevice.class, @selector(systemName), @selector(bd_systemName));
        bdd_swizzle(UIDevice.class, @selector(name), @selector(bd_name));
        bdd_swizzle(UIDevice.class, @selector(identifierForVendor), @selector(bd_identifierForVendor));

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            @autoreleasepool { bdd_buildMethodIndex(); }
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ bdd_showFloat(); });
    }
}
