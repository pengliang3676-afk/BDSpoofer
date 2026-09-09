//
//  HMProbe3.m —— 河马剧场 只读诊断探针 v3（v2 基础上：constructor 提前安装 + C层 open/fopen interpose + 快照增强）
//
//  v1 已证实：主风控=数美 SMantifraud(fp-it.fengkongcloud.com/deviceprofile/v4)，另有邦盛 NBSDevice、
//  阿里 UMID、腾讯 TMF、字节 mssdk、快手 gdfp；业务 portal 接口与风控包全部加密；剪贴板 .string 0 命中。
//  v2 新增目标（全部只读）：
//   E. 风控类深度枚举/动态安全 Hook：对类名命中 smantifraud/shumei/nbsdevice/bangsun/assumid/
//      umidtoken/antifraud/smid 的类，列出全部类/实例方法与真实签名，并对 ABI 安全白名单内的方法
//      （对象返回、0~2 个对象参数；拒绝 init/未知结构体/标量复杂参数）安装只读观测，取一次返回样本+短栈；
//   F. Keychain：DYLD_INTERPOSE 观测 SecItemCopyMatching/Add/Update/Delete，只记操作与
//      kSecClass/kSecAttrService/kSecAttrAccount/kSecAttrAccessGroup 键名（值永不记录），定位数美本地ID是否落 Keychain；
//   G. NSUserDefaults：观测 objectForKey:/stringForKey:/boolForKey:/integerForKey: 与 setObject:forKey:，
//      按键去重，值给类型/脱敏样本，定位 smid/deviceId 等持久化键；
//   H. 文件持久化：导出时快照沙盒目录树（路径+大小，关键词高亮），运行期观测
//      createFileAtPath: 与 NSData writeToFile:atomically: 的写入路径（去重、上限）；
//   I. 剪贴板补全：items / dataForPasteboardType: / containsPasteboardTypes:（v1 只挂了 .string）。
//  v1 的 A.SDK普查 / B.设备出口 / C.网络观测 / 浮窗/门控/脱敏/递归抑制 全部保留。
//
//  安全原则（沿用 BDDiag2 v4 已真机验证的机制）：
//   1. 运行时确认类/selector 存在并读取真实 type encoding；仅 Hook 已验证 ABI 安全的方法；
//   2. 所有 Hook 先调原实现，再做安全摘要，原值原样返回；
//   3. _Thread_local 递归抑制，摘要过程触发的二次调用不进入探针；
//   4. 类可能晚加载：每 0.5s 重试安装、最多 30s；SDK 普查在 2s/8s 各跑一次后合并；
//   5. 手机号/UUID/长 token 脱敏；NSString 最多 300 字；NSData 默认只记长度，Body 仅解析键结构；
//   6. 只在河马剧场主 App 进程运行（按 App 显示名含“河马”或 bundleId 关键字匹配，跳过 appex）。
//
//  编译：arm64 + arm64e 通用 dylib（见 .github/workflows/build.yml），TrollFools 注入。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <execinfo.h>
#import <os/lock.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <ctype.h>
#import <errno.h>
#import <limits.h>
#import <stdlib.h>
#import <unistd.h>
#import <sys/utsname.h>
#import <stdatomic.h>
#import <Security/Security.h>
#if __has_include(<mach-o/dyld-interposing.h>)
#import <mach-o/dyld-interposing.h>
#else
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { const void *replacement; const void *replacee; } \
    _hm_interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&_replacement, (const void *)(uintptr_t)&_replacee \
    };
#endif

// ============================== B. 设备/剪贴板通用出口目标清单 ==============================
// preferClass: 1=类方法 0=实例方法（运行时仍双向确认）；group 仅用于报告分组
typedef struct { const char *cls; const char *sel; int preferClass; const char *group; } HMTarget;
static const HMTarget kTargets[] = {
    {"UIDevice",             "name",                         0, "设备信息"},
    {"UIDevice",             "systemName",                   0, "设备信息"},
    {"UIDevice",             "systemVersion",                0, "设备信息"},
    {"UIDevice",             "model",                        0, "设备信息"},
    {"UIDevice",             "localizedModel",               0, "设备信息"},
    {"UIDevice",             "identifierForVendor",          0, "设备信息"},
    {"UIScreen",             "bounds",                       0, "屏幕"},
    {"UIScreen",             "nativeBounds",                 0, "屏幕"},
    {"UIScreen",             "scale",                        0, "屏幕"},
    {"UIScreen",             "nativeScale",                  0, "屏幕"},
    {"NSBundle",             "objectForInfoDictionaryKey:",  0, "App信息"},
    {"NSLocale",             "currentLocale",                1, "地区语言"},
    {"NSLocale",             "localeIdentifier",             0, "地区语言"},
    {"UIPasteboard",         "generalPasteboard",            1, "剪贴板归因"},
    {"UIPasteboard",         "string",                       0, "剪贴板归因"},
    {"UIPasteboard",         "valueForPasteboardType:",      0, "剪贴板归因"},
    {"UIPasteboard",         "items",                        0, "剪贴板归因v2"},
    {"UIPasteboard",         "dataForPasteboardType:",       0, "剪贴板归因v2"},
    {"UIPasteboard",         "containsPasteboardTypes:",     0, "剪贴板归因v2"},
    {"ASIdentifierManager",  "advertisingIdentifier",        0, "广告标识"},
    {"CTTelephonyNetworkInfo","subscriberCellularProvider",  0, "运营商"},
    {"CTCarrier",            "carrierName",                  0, "运营商"},
};
static const int kTargetCount = sizeof(kTargets)/sizeof(kTargets[0]);

// ============================== A. SDK 识别关键字表（匹配小写类名/镜像名） ==============================
typedef struct { const char *vendor; const char *keys[8]; } HMVendor;
static const HMVendor kVendors[] = {
    {"同盾 TongDun",        {"tongdun","fmdevice","fmsdk","tdrisk","fmpingan"}},
    {"顶象 Dingxiang",      {"dingxiang","dxdevice","dxpixie","dxcaptcha","dxrisk"}},
    {"数美 Shumei",         {"shumei","smantifraud","smid","smdevice"}},
    {"邦盛 Bangsun",        {"bangsun","bsantifraud","bsdevice"}},
    {"网易易盾 YiDun",      {"yidun","ntesquick","nequickpass","ntescaptcha"}},
    {"阿里安全 SecurityGuard",{"alisecurity","securityguard","sgmain","umidtoken"}},
    {"友盟 Umeng",          {"umeng","umcommon","umanalytics","utmini"}},
    {"腾讯 灯塔/Bugly/MTA/TPNS",{"tencent","bugly","qqmta","tpns","beacon","tencentmta"}},
    {"极光 JPush",          {"jpush","jcore","janalytics"}},
    {"个推 GeTui",          {"getui","gtsdk","gtsdkmanager"}},
    {"AppsFlyer",           {"appsflyer"}},
    {"Adjust",              {"adjust"}},
    {"OpenInstall 归因",    {"openinstall"}},
    {"shareinstall 归因",   {"shareinstall"}},
    {"热云 TrackingIO",     {"trackingio","trckio","reyun","reyuninfo"}},
    {"神策 Sensors",        {"sensorsdata","sensorsanalytics"}},
    {"TalkingData",         {"talkingdata","tddeviceinfo","tddata"}},
    {"GrowingIO",           {"growingio","growing"}},
    {"穿山甲 Pangle/CSJ",   {"pangle","csjad","bytedance","buad"}},
    {"优量汇 GDT",          {"gdt","gdtad"}},
    {"快手广告 KSAd",       {"ksad","ksadmanager"}},
    {"Mobvista/Mintegral",  {"mobvista","mintegral"}},
    {"Dipfy",               {"dipfy"}},
    {"百度 Baidu",          {"baidu","baidumobstat","bpush"}},
};
static const int kVendorCount = sizeof(kVendors)/sizeof(kVendors[0]);

// ============================== 全局状态 ==============================
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;
static NSMutableArray<NSMutableDictionary *> *g_records = nil;
static NSMutableDictionary<NSString *, NSMutableDictionary *> *g_vendorHit = nil; // 厂商 -> {classes:Set, images:Set}
static NSMutableArray<NSMutableDictionary *> *g_events = nil;                   // 网络事件（保持顺序）
static NSMutableDictionary<NSString *, NSMutableDictionary *> *g_evByKey = nil;
static NSMutableArray<NSString *> *g_markers = nil;
// ---- v2 新增状态 ----
static NSMutableSet<NSString *> *g_deepDone = nil;        // 已深度处理的风控类
static NSMutableArray<NSDictionary *> *g_deepInv = nil;   // 风控类方法清单
static NSMutableDictionary<NSString *, NSMutableDictionary *> *g_udSeen = nil; // NSUserDefaults 键观测
static NSMutableDictionary<NSString *, NSMutableDictionary *> *g_kcSeen = nil; // Keychain 观测
static NSMutableDictionary<NSString *, NSMutableDictionary *> *g_fileSeen = nil; // ObjC 写文件路径观测
static NSMutableDictionary<NSString *, NSMutableDictionary *> *g_cFileSeen = nil; // v3: C 层 open/fopen 观测
static char g_homeC[1024] = {0};                                                // v3: 沙盒前缀(C 快速过滤)
static _Thread_local int t_suppress = 0;
// 一轮运行时安装共享同一份类列表，避免 constructor/重试阶段为每个 selector 重复全量扫描。
static Class *g_runtimeScanClasses = NULL;
static unsigned int g_runtimeScanClassCount = 0;
static uintptr_t g_ownLow = 0, g_ownHigh = 0;
static BOOL bdd_inSelf(uintptr_t p){ return p>=g_ownLow && p<g_ownHigh; }

// Hook 调用热路径只读取这组 C/atomic 元数据，不碰可变 NSDictionary，也不获取 g_lock。
// alias 先发布、installedClass 再以 release 发布；交换后的调用方以 acquire 读取。
typedef struct {
    SEL targetSel;
    _Atomic(void *) aliasSel;
    _Atomic(void *) installedClass;
} HMHookSlot;
#define HM_MAX_SLOTS 512
static HMHookSlot g_hookSlots[HM_MAX_SLOTS];
static _Atomic(int) g_slotCount = 0; // release/acquire 发布完整槽位；固定目标之后为动态 Hook 槽

static Method hm_ownMethod(Class cls, SEL sel) {
    if (!cls || !sel) return NULL;
    unsigned int count = 0;
    Method found = NULL;
    Method *list = class_copyMethodList(cls, &count);
    for (unsigned int i=0; i<count; i++) {
        if (method_getName(list[i]) == sel) { found = list[i]; break; }
    }
    free(list);
    return found;
}

static BOOL hm_isSubclassOrSame(Class cls, Class ancestor) {
    for (Class c=cls; c; c=class_getSuperclass(c)) if (c==ancestor) return YES;
    return NO;
}

static int hm_findSlot(id self, SEL cmd, SEL *aliasOut) {
    if (aliasOut) *aliasOut = NULL;
    Class selfCls = object_getClass(self);
    int best = -1, bestDistance = INT_MAX;
    int slotCount = atomic_load_explicit(&g_slotCount, memory_order_acquire);
    for (int i=0; i<slotCount; i++) {
        if (g_hookSlots[i].targetSel != cmd) continue;
        Class installed = (__bridge Class)atomic_load_explicit(&g_hookSlots[i].installedClass, memory_order_acquire);
        if (!installed) continue;
        int distance = 0;
        for (Class c=selfCls; c; c=class_getSuperclass(c), distance++) {
            if (c != installed) continue;
            if (distance < bestDistance) { best = i; bestDistance = distance; }
            break;
        }
    }
    if (best >= 0 && aliasOut)
        *aliasOut = (SEL)atomic_load_explicit(&g_hookSlots[best].aliasSel, memory_order_acquire);
    return best;
}

static char hm_typeKind(const char *enc) {
    if (!enc) return '?';
    while (*enc) {
        char c = *enc;
        if (isdigit(c)||c=='r'||c=='n'||c=='N'||c=='o'||c=='O'||c=='R'||c=='V') { enc++; continue; }
        return c;
    }
    return '?';
}

// ============================== 脱敏 ==============================
static NSRegularExpression *g_phoneRx = nil, *g_uuidRx = nil, *g_tokenRx = nil;
static void hm_ensureRx(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_phoneRx = [NSRegularExpression regularExpressionWithPattern:@"1[3-9]\\d{9}" options:0 error:nil];
        g_uuidRx  = [NSRegularExpression regularExpressionWithPattern:@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" options:0 error:nil];
        g_tokenRx = [NSRegularExpression regularExpressionWithPattern:@"[A-Za-z0-9_\\-]{24,}" options:0 error:nil];
    });
}
static BOOL hm_sensitiveKey(NSString *k) {
    NSString *x = k.lowercaseString;
    NSString *compact = [[[x stringByReplacingOccurrencesOfString:@"_" withString:@""]
                            stringByReplacingOccurrencesOfString:@"-" withString:@""]
                            stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSArray *bad = @[@"cookie",@"token",@"session",@"pass",@"pwd",@"secret",
                     @"account",@"idfa",@"idfv",@"auth",@"ticket",@"sign",
                     @"deviceid",@"udid",@"cuid",@"utdid",@"openid",@"unionid"];
    for (NSString *b in bad) if ([x containsString:b]) return YES;
    NSArray *phoneKeys = @[@"phonenumber", @"mobilephonenumber", @"mobilenumber",
                           @"telephonenumber", @"telnumber", @"msisdn"];
    for (NSString *b in phoneKeys) if ([compact containsString:b]) return YES;
    if ([compact isEqualToString:@"phone"] || [compact isEqualToString:@"mobile"] ||
        [compact isEqualToString:@"telephone"] || [compact isEqualToString:@"tel"]) return YES;
    return NO;
}
static NSString *hm_maskString(NSString *s) {
    if (!s) return nil;
    hm_ensureRx();
    NSString *out = [g_phoneRx stringByReplacingMatchesInString:s options:0 range:NSMakeRange(0,s.length) withTemplate:@"1XX****XXXX"];
    out = [g_uuidRx stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0,out.length) withTemplate:@"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"];
    out = [g_tokenRx stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0,out.length) withTemplate:@"token***"];
    if (out.length > 300) out = [[out substringToIndex:300] stringByAppendingString:@"…(截断)"];
    return out;
}

static NSString *hm_summary(id v, int depth, NSString *keyHint) {
    if (!v) return @"nil";
    Class c = [v class];
    if ([v isKindOfClass:NSString.class]) {
        if (keyHint && hm_sensitiveKey(keyHint)) return [NSString stringWithFormat:@"<NSString len=%lu 已脱敏>",(unsigned long)((NSString*)v).length];
        return [NSString stringWithFormat:@"NSString: %@", hm_maskString((NSString*)v)];
    }
    if ([v isKindOfClass:NSNumber.class]) return [NSString stringWithFormat:@"%@: %@", NSStringFromClass(c), v];
    if ([v isKindOfClass:NSUUID.class])
        return [NSString stringWithFormat:@"NSUUID: %@", hm_maskString([(NSUUID*)v UUIDString])];
    if ([v isKindOfClass:NSDate.class]) return [NSString stringWithFormat:@"NSDate: %@", v];
    if ([v isKindOfClass:NSData.class]) return [NSString stringWithFormat:@"<NSData len=%lu>",(unsigned long)((NSData*)v).length];
    if ([v isKindOfClass:NSURL.class]) return [NSString stringWithFormat:@"NSURL: %@://%@%@", ((NSURL*)v).scheme?:@"", ((NSURL*)v).host?:@"", ((NSURL*)v).path?:@""];
    if ([v isKindOfClass:NSArray.class]) {
        NSArray *snap = nil;
        @try { snap = [[NSArray alloc] initWithArray:(NSArray*)v copyItems:NO]; }
        @catch (NSException *e) { return [NSString stringWithFormat:@"[NSArray count=%lu 枚举失败:%@]",(unsigned long)[(NSArray*)v count], e.name]; }
        NSMutableArray *ts = [NSMutableArray array];
        for (id e in snap) { if (ts.count>=8) break; [ts addObject:NSStringFromClass([e class]) ?: @"?"]; }
        return [NSString stringWithFormat:@"[NSArray count=%lu 元素类型:%@]",(unsigned long)snap.count, [ts componentsJoinedByString:@","]];
    }
    if ([v isKindOfClass:NSDictionary.class]) {
        if (depth > 1) return [NSString stringWithFormat:@"{NSDictionary count=%lu}",(unsigned long)[(NSDictionary*)v count]];
        NSDictionary *snap = nil;
        @try { snap = [[NSDictionary alloc] initWithDictionary:(NSDictionary*)v copyItems:NO]; }
        @catch (NSException *e) { return [NSString stringWithFormat:@"{NSDictionary count=%lu 枚举失败:%@}",(unsigned long)[(NSDictionary*)v count], e.name]; }
        NSMutableArray *parts = [NSMutableArray array];
        int n = 0;
        for (id k in snap) {
            if (n++ >= 40) { [parts addObject:@"…"]; break; }
            id val = snap[k];
            NSString *ks = [k isKindOfClass:NSString.class] ? (NSString*)k : NSStringFromClass([k class]);
            if (ks.length > 60) ks = [[ks substringToIndex:60] stringByAppendingString:@"…"];
            NSString *vs;
            if (hm_sensitiveKey(ks)) vs = [NSString stringWithFormat:@"<%@ 已脱敏>", NSStringFromClass([val class])];
            else if ([val isKindOfClass:NSDictionary.class] || [val isKindOfClass:NSArray.class]) vs = hm_summary(val, depth+1, ks);
            else if ([val isKindOfClass:NSString.class]) vs = [NSString stringWithFormat:@"NSString(值=%@)", hm_maskString((NSString*)val)];
            else if ([val isKindOfClass:NSNumber.class]) vs = [NSString stringWithFormat:@"%@(值=%@)", NSStringFromClass([val class]), val];
            else vs = NSStringFromClass([val class]) ?: @"?";
            [parts addObject:[NSString stringWithFormat:@"%@=%@", ks, vs]];
        }
        return [NSString stringWithFormat:@"{NSDictionary count=%lu keys: [%@]}",(unsigned long)snap.count,[parts componentsJoinedByString:@", "]];
    }
    return [NSString stringWithFormat:@"<%@>", NSStringFromClass(c)];
}

static NSString *hm_shortStack(void) {
    void *bt[12]; int n = backtrace(bt, 12);
    NSMutableArray *a = [NSMutableArray array];
    for (int i=0; i<n && a.count<8; i++) {
        if (bdd_inSelf((uintptr_t)bt[i])) continue;
        Dl_info info; memset(&info,0,sizeof(info));
        if (dladdr(bt[i], &info)) {
            const char *img = info.dli_fname ? strrchr(info.dli_fname,'/') : NULL;
            img = img ? img+1 : (info.dli_fname ?: "?");
            uintptr_t off = (uintptr_t)bt[i] - (uintptr_t)info.dli_fbase;
            NSString *sym = info.dli_sname ? [NSString stringWithUTF8String:info.dli_sname] : nil;
            [a addObject:[NSString stringWithFormat:@"    %s+0x%lx %@", img, (unsigned long)off, sym?:@""]];
        }
    }
    return [a componentsJoinedByString:@"\n"];
}

// ============================== B. 设备出口记录 ==============================
static void hm_observe(int index, id ret, NSArray *args) {
    if (index < 0 || t_suppress) return;
    t_suppress++;
    @try {
        BOOL needSample = NO;
        NSMutableDictionary *rec = nil;
        os_unfair_lock_lock(&g_lock);
        @try {
            if ((NSUInteger)index >= g_records.count) return;
            rec = g_records[index];
            rec[@"hits"] = @([rec[@"hits"] unsignedLongValue] + 1);
            if (![rec[@"sampled"] boolValue]) { rec[@"sampled"] = @YES; needSample = YES; }
        } @finally { os_unfair_lock_unlock(&g_lock); }
        if (!needSample) return;

        NSString *retSum=nil, *stack=nil; NSMutableArray *argSum=nil;
        BOOL sampleFailed = NO;
        @try {
            retSum = hm_summary(ret, 0, nil);
            argSum = [NSMutableArray array];
            if (args) for (id a in args) [argSum addObject:hm_summary(a, 0, nil)];
            stack = hm_shortStack();
        } @catch (NSException *e) {
            sampleFailed = YES;
            retSum = [NSString stringWithFormat:@"<采样异常: %@>", e.name];
        }
        os_unfair_lock_lock(&g_lock);
        @try {
            rec[@"sampleReturn"] = retSum ?: @"nil";
            if (argSum.count) rec[@"sampleArgs"] = argSum;
            rec[@"sampleStack"] = stack ?: @"";
            if (sampleFailed) rec[@"sampled"] = @NO;
        } @finally { os_unfair_lock_unlock(&g_lock); }
    } @finally { t_suppress--; }
}
static void hm_observeScalar(int index, char kind, double v0, double v1, double v2, double v3) {
    if (index < 0 || index >= kTargetCount || t_suppress) return;
    t_suppress++;
    @try {
        BOOL needSample = NO;
        NSMutableDictionary *rec = nil;
        os_unfair_lock_lock(&g_lock);
        @try {
            rec = g_records[index];
            rec[@"hits"] = @([rec[@"hits"] unsignedLongValue] + 1);
            if (![rec[@"sampled"] boolValue]) { rec[@"sampled"]=@YES; needSample=YES; }
        } @finally { os_unfair_lock_unlock(&g_lock); }
        if (!needSample) return;

        NSString *sum=nil, *stack=nil;
        BOOL sampleFailed = NO;
        @try {
            if (kind=='r')
                sum = [NSString stringWithFormat:@"CGRect(只读,原值返回): x=%.1f y=%.1f w=%.1f h=%.1f",v0,v1,v2,v3];
            else if (kind=='f')
                sum = [NSString stringWithFormat:@"float(只读,原值返回): %.3f",v0];
            else
                sum = [NSString stringWithFormat:@"double(只读,原值返回): %.3f",v0];
            stack = hm_shortStack();
        } @catch (NSException *e) {
            sampleFailed = YES;
            sum = [NSString stringWithFormat:@"<采样异常: %@>", e.name];
        }
        os_unfair_lock_lock(&g_lock);
        @try {
            rec[@"sampleReturn"] = sum ?: @""; rec[@"sampleStack"]=stack?:@"";
            if (sampleFailed) rec[@"sampled"] = @NO;
        } @finally { os_unfair_lock_unlock(&g_lock); }
    } @finally { t_suppress--; }
}

// 用原始指针转发对象返回/参数，避免 ARC 给动态 IMP 强加 +0 返回约定。
// 这样 alloc/copy/new 或显式 ns_returns_retained 的原始所有权位保持不变；init 仍拒绝 Hook。
static void *hm_call0_raw(id s, SEL sel){ return ((void *(*)(id,SEL))objc_msgSend)(s,sel); }
static void *hm_call1_raw(id s, SEL sel,void *a){ return ((void *(*)(id,SEL,void *))objc_msgSend)(s,sel,a); }
static void *hm_call2_raw(id s, SEL sel,void *a,void *b){ return ((void *(*)(id,SEL,void *,void *))objc_msgSend)(s,sel,a,b); }

// 对象返回 trampoline（0~2 个对象参数）
static void *hm_tramp0(id self, SEL _cmd) {
    SEL aliasSel = NULL; int index = hm_findSlot(self,_cmd,&aliasSel);
    if (!aliasSel) return NULL;
    void *ret = hm_call0_raw(self, aliasSel);
    hm_observe(index, (__bridge id)ret, nil);
    return ret;
}
static void *hm_tramp1(id self, SEL _cmd, void *a0) {
    SEL aliasSel = NULL; int index = hm_findSlot(self,_cmd,&aliasSel);
    if (!aliasSel) return NULL;
    void *ret = hm_call1_raw(self, aliasSel, a0);
    NSArray *args = (index >= 0 && index < kTargetCount)
        ? @[(__bridge id)a0 ?: [NSNull null]] : nil;
    hm_observe(index, (__bridge id)ret, args);
    return ret;
}
static void *hm_tramp2(id self, SEL _cmd, void *a0, void *a1) {
    SEL aliasSel = NULL; int index = hm_findSlot(self,_cmd,&aliasSel);
    if (!aliasSel) return NULL;
    void *ret = hm_call2_raw(self, aliasSel, a0, a1);
    NSArray *args = (index >= 0 && index < kTargetCount)
        ? @[(__bridge id)a0 ?: [NSNull null], (__bridge id)a1 ?: [NSNull null]] : nil;
    hm_observe(index, (__bridge id)ret, args);
    return ret;
}
// CGRect 只读 trampoline（arm64 经 d 寄存器返回，objc_msgSend 可承载，无 stret）
static CGRect hm_tramp_cgrect(id self, SEL _cmd) {
    SEL aliasSel = NULL; int index = hm_findSlot(self,_cmd,&aliasSel);
    if (!aliasSel) return CGRectZero;
    CGRect ret = ((CGRect(*)(id,SEL))objc_msgSend)(self, aliasSel);
    hm_observeScalar(index, 'r', ret.origin.x,ret.origin.y,ret.size.width,ret.size.height);
    return ret;
}
// double 只读 trampoline（scale/nativeScale）
static double hm_tramp_dbl(id self, SEL _cmd) {
    SEL aliasSel = NULL; int index = hm_findSlot(self,_cmd,&aliasSel);
    if (!aliasSel) return 0;
    double ret = ((double(*)(id,SEL))objc_msgSend)(self, aliasSel);
    hm_observeScalar(index, 'd', ret,0,0,0);
    return ret;
}
// float 与 double 必须使用不同函数原型；两者虽同在 v0，位宽和解释不同。
static float hm_tramp_flt(id self, SEL _cmd) {
    SEL aliasSel = NULL; int index = hm_findSlot(self,_cmd,&aliasSel);
    if (!aliasSel) return 0;
    float ret = ((float(*)(id,SEL))objc_msgSend)(self, aliasSel);
    hm_observeScalar(index, 'f', ret,0,0,0);
    return ret;
}

// ============================== 安装设备出口 Hook ==============================
static void hm_installNet(void); // 网络出口安装器定义在后，前置声明
static void hm_tryInstall(NSMutableDictionary *rec, int index) {
    NSString *status=nil, *clsName=nil, *selName=nil;
    BOOL final=NO, preferClass=NO;
    os_unfair_lock_lock(&g_lock);
    status = [rec[@"status"] copy]; final = [rec[@"final"] boolValue];
    clsName = [rec[@"clsName"] copy]; selName = [rec[@"selName"] copy];
    preferClass = [rec[@"preferClass"] boolValue];
    os_unfair_lock_unlock(&g_lock);
    if ([status isEqualToString:@"已Hook"] || final) return;
    Class appCls = NSClassFromString(clsName);
    if (!appCls) {
        os_unfair_lock_lock(&g_lock); rec[@"status"] = @"未找到（类未加载/未链接）"; os_unfair_lock_unlock(&g_lock);
        return;
    }

    Class meta = object_getClass(appCls);
    Class hookCls = preferClass ? meta : appCls;
    Method m = class_getInstanceMethod(hookCls, NSSelectorFromString(selName));
    BOOL isClass = preferClass;
    if (!m) { hookCls = preferClass ? appCls : meta; m = class_getInstanceMethod(hookCls, NSSelectorFromString(selName)); isClass = !preferClass; }
    if (!m) {
        os_unfair_lock_lock(&g_lock); rec[@"status"] = @"未找到（selector 不存在）"; os_unfair_lock_unlock(&g_lock);
        return;
    }
    if ([selName hasPrefix:@"init"]) {
        os_unfair_lock_lock(&g_lock);
        rec[@"kind"] = isClass?@"+(类)":@"-(实例)";
        rec[@"encoding"]=[NSString stringWithUTF8String:method_getTypeEncoding(m)?: "?"];
        rec[@"status"]=@"未Hook(init方法族)"; rec[@"final"]=@YES;
        os_unfair_lock_unlock(&g_lock);
        return;
    }

    const char *types = method_getTypeEncoding(m) ?: "?";
    char rbuf[8]={0}; method_getReturnType(m, rbuf, sizeof(rbuf));
    char retKind = hm_typeKind(rbuf);
    unsigned narg = method_getNumberOfArguments(m);
    int userArgc = (int)narg - 2;
    NSMutableArray *argKinds = [NSMutableArray array];
    BOOL argsSafe = YES;
    for (unsigned i=2; i<narg; i++) {
        char abuf[16]={0}; method_getArgumentType(m, i, abuf, sizeof(abuf));
        char k = hm_typeKind(abuf);
        [argKinds addObject:[NSString stringWithFormat:@"%c",k]];
        if (!(k=='@' || k=='#')) argsSafe = NO;
    }
    os_unfair_lock_lock(&g_lock);
    rec[@"kind"] = isClass?@"+(类)":@"-(实例)";
    rec[@"encoding"]=[NSString stringWithUTF8String:types];
    rec[@"retType"]=[NSString stringWithFormat:@"%c",retKind];
    rec[@"argc"]=@(userArgc); rec[@"argTypes"]=argKinds;
    os_unfair_lock_unlock(&g_lock);

    IMP tramp = NULL;
    NSString *alias = nil;
    if (retKind=='{' && userArgc==0 && strncmp(types,"{CGRect",7)==0) {
        tramp = (IMP)hm_tramp_cgrect;
        alias = [NSString stringWithFormat:@"hm_orig_rect_%d", index];
    } else if (retKind=='d' && userArgc==0) {
        tramp = (IMP)hm_tramp_dbl;
        alias = [NSString stringWithFormat:@"hm_orig_dbl_%d", index];
    } else if (retKind=='f' && userArgc==0) {
        tramp = (IMP)hm_tramp_flt;
        alias = [NSString stringWithFormat:@"hm_orig_flt_%d", index];
    } else if (retKind=='@' && userArgc>=0 && userArgc<=2 && argsSafe) {
        tramp = (userArgc==0)?(IMP)hm_tramp0 : (userArgc==1)?(IMP)hm_tramp1 : (IMP)hm_tramp2;
        alias = [NSString stringWithFormat:@"hm_orig_obj_%d%@", index,
                 userArgc==0?@"":(userArgc==1?@":":@"::")];
    } else {
        os_unfair_lock_lock(&g_lock);
        rec[@"status"]=[NSString stringWithFormat:@"未Hook(ABI不匹配 返回=%c 参数=%@)",retKind,argKinds];
        rec[@"final"]=@YES;
        os_unfair_lock_unlock(&g_lock);
        return;
    }

    SEL aliasSel = sel_registerName(alias.UTF8String);
    SEL targetSel = NSSelectorFromString(selName);
    IMP origImp = method_getImplementation(m);
    // 若目标来自父类，先把原实现落地到本类；随后添加 alias trampoline。
    Method ownTarget = hm_ownMethod(hookCls, targetSel);
    BOOL landedTarget = ownTarget ? YES : class_addMethod(hookCls, targetSel, origImp, types);
    BOOL addAlias = landedTarget && class_addMethod(hookCls, aliasSel, tramp, types);
    Method targetM = hm_ownMethod(hookCls, targetSel);
    Method aliasM  = hm_ownMethod(hookCls, aliasSel);
    if (!landedTarget || !addAlias || !targetM || !aliasM || method_getImplementation(aliasM)!=tramp) {
        os_unfair_lock_lock(&g_lock);
        rec[@"status"]=@"未Hook(swizzle失败/alias冲突)"; rec[@"final"]=@YES;
        os_unfair_lock_unlock(&g_lock);
        return;
    }

    // 交换前发布只读 alias/class 元数据；热路径不读取 rec 字典。
    atomic_store_explicit(&g_hookSlots[index].aliasSel, (void *)aliasSel, memory_order_relaxed);
    atomic_store_explicit(&g_hookSlots[index].installedClass, (__bridge void *)hookCls, memory_order_release);
    method_exchangeImplementations(targetM, aliasM);
    os_unfair_lock_lock(&g_lock);
    rec[@"aliasSel"]=alias; rec[@"installedClass"]=hookCls;
    rec[@"status"]=@"已Hook"; rec[@"final"]=@YES;
    os_unfair_lock_unlock(&g_lock);
}

static int g_tries = 0;
static void hm_pass(void) {
    t_suppress++;
    @try {
        BOOL allDone = YES;
        for (int i=0;i<kTargetCount;i++) {
            NSMutableDictionary *r;
            os_unfair_lock_lock(&g_lock); r = g_records[i]; os_unfair_lock_unlock(&g_lock);
            hm_tryInstall(r, i);
            os_unfair_lock_lock(&g_lock);
            BOOL final = [r[@"final"] boolValue];
            os_unfair_lock_unlock(&g_lock);
            if (!final) allDone = NO;
        }
        hm_installNet(); // 网络类簇扫描器内部独立重试 30s
        g_tries++;
        if (!allDone && g_tries < 60) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ hm_pass(); });
        } else {
            os_unfair_lock_lock(&g_lock);
            for (NSMutableDictionary *r in g_records)
                if (![r[@"final"] boolValue]) { r[@"status"]=@"未找到(30s内未加载)"; r[@"final"]=@YES; }
            os_unfair_lock_unlock(&g_lock);
        }
    } @finally { t_suppress--; }
}

// ============================== C. 网络上报观测 ==============================
static SEL g_selDt1=NULL,g_selDt2=NULL,g_selConn=NULL;

static NSString *hm_headerSummary(NSDictionary *h) {
    if (!h || ![h isKindOfClass:NSDictionary.class] || h.count==0) return @"(无)";
    NSMutableArray *a = [NSMutableArray array];
    NSDictionary *snap;
    @try { snap = [h copy]; } @catch (NSException *e) { return @"(枚举失败)"; }
    int n=0;
    for (NSString *k in snap) {
        if (n++>=24) { [a addObject:@"…"]; break; }
        if (![k isKindOfClass:NSString.class]) continue;
        id v = snap[k];
        NSString *kl = k.lowercaseString;
        if ([kl isEqualToString:@"user-agent"] || [kl isEqualToString:@"content-type"] ||
            [kl isEqualToString:@"accept-language"] || [kl isEqualToString:@"accept"]) {
            [a addObject:[NSString stringWithFormat:@"%@=%@", k, hm_maskString([v description])]];
        } else {
            [a addObject:[NSString stringWithFormat:@"%@=<不取值>", k]]; // 其余头只记录键名
        }
    }
    return [a componentsJoinedByString:@", "];
}
static NSString *hm_queryKeys(NSString *q) {
    if (!q.length) return @"(无)";
    NSMutableArray *names = [NSMutableArray array];
    for (NSString *pair in [q componentsSeparatedByString:@"&"]) {
        NSString *name = [[pair componentsSeparatedByString:@"="] firstObject];
        if (name.length) [names addObject:name];
        if (names.count>=30) break;
    }
    // 查询参数只回显字段名，值不外带
    return [NSString stringWithFormat:@"字段名[%@]", [names componentsJoinedByString:@","]];
}
static NSString *hm_bodySummary(NSData *body) {
    if (!body) return @"(无body)";
    NSUInteger len = body.length;
    if (len==0) return @"(body空)";
    if (len > 256*1024) return [NSString stringWithFormat:@"<大包 len=%lu 超过256KB不解析>",(unsigned long)len];
    // 1) JSON：只解析顶层键结构，敏感键脱敏、数字/短字符串给脱敏值
    NSError *err=nil;
    id json=nil;
    @try { json = [NSJSONSerialization JSONObjectWithData:body options:0 error:&err]; } @catch (NSException *e) { json=nil; }
    if (json) {
        if ([json isKindOfClass:NSDictionary.class]) return [NSString stringWithFormat:@"JSON len=%lu %@",(unsigned long)len, hm_summary(json,0,nil)];
        if ([json isKindOfClass:NSArray.class])  return [NSString stringWithFormat:@"JSON数组 len=%lu count=%lu",(unsigned long)len,(unsigned long)[(NSArray*)json count]];
    }
    // 2) 表单：只取字段名
    NSString *s = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (s && [s containsString:@"="] && [s rangeOfString:@"\0"].location==NSNotFound) {
        NSMutableArray *names=[NSMutableArray array];
        for (NSString *pair in [s componentsSeparatedByString:@"&"]) {
            NSString *name=[[pair componentsSeparatedByString:@"="] firstObject];
            if (name.length) [names addObject:name];
            if (names.count>=40) break;
        }
        return [NSString stringWithFormat:@"表单 len=%lu 字段名[%@]",(unsigned long)len,[names componentsJoinedByString:@","]];
    }
    // 3) protobuf/加密二进制：只记长度
    return [NSString stringWithFormat:@"<二进制 len=%lu 不解析>",(unsigned long)len];
}

static void hm_netObserve(NSURLRequest *req) {
    if (!req || t_suppress) return;
    t_suppress++;
    @try {
        if (![req isKindOfClass:NSURLRequest.class]) return;
        NSURL *u = req.URL;
        NSString *host = u.host ?: @"(无host)";
        NSString *path = u.path ?: @"/";
        NSString *method = req.HTTPMethod ?: @"GET";
        NSString *key = [NSString stringWithFormat:@"%@ %@%@", method, host, path];
        BOOL needSample=NO;
        NSMutableDictionary *ev = nil;
        os_unfair_lock_lock(&g_lock);
        @try {
            if (g_events.count<220) {
                ev = g_evByKey[key];
                if (!ev) {
                    ev = [NSMutableDictionary dictionary];
                    ev[@"key"]=key; ev[@"method"]=method; ev[@"host"]=host; ev[@"path"]=path;
                    ev[@"hits"]=@0; ev[@"sampled"]=@NO;
                    g_evByKey[key]=ev; [g_events addObject:ev];
                }
                ev[@"hits"]=@([ev[@"hits"] unsignedLongValue]+1);
                if (![ev[@"sampled"] boolValue]) { ev[@"sampled"]=@YES; needSample=YES; }
            }
        } @finally { os_unfair_lock_unlock(&g_lock); }
        if (!ev || !needSample) return;

        NSString *hdr=nil,*qkeys=nil,*bsum=nil,*stack=nil;
        BOOL sampleFailed=NO;
        @try {
            hdr = hm_headerSummary(req.allHTTPHeaderFields);
            qkeys = hm_queryKeys(u.query);
            bsum = hm_bodySummary(req.HTTPBody);
            if (!req.HTTPBody && req.HTTPBodyStream) bsum = @"<HTTPBodyStream 流式 不取>";
            stack = hm_shortStack();
        } @catch (NSException *e) {
            sampleFailed=YES;
            hdr=[NSString stringWithFormat:@"<采样异常:%@>",e.name];
        }
        os_unfair_lock_lock(&g_lock);
        @try {
            ev[@"headers"]=hdr?:@""; ev[@"query"]=qkeys?:@""; ev[@"body"]=bsum?:@""; ev[@"stack"]=stack?:@"";
            if (sampleFailed) ev[@"sampled"]=@NO;
        } @finally { os_unfair_lock_unlock(&g_lock); }
    } @finally { t_suppress--; }
}

// 手写安全 swizzle：继承方法先在本类落地；alias 必须由本次安装成功添加。
static BOOL hm_swap(Class cls, SEL target, IMP tramp, SEL aliasSel, const char *types) {
    Method ownTarget = hm_ownMethod(cls, target);
    if (ownTarget && method_getImplementation(ownTarget)==tramp)
        return hm_ownMethod(cls, aliasSel)!=NULL; // 目标和本类 alias 同时存在才视为已安装
    Method m = class_getInstanceMethod(cls, target);
    if (!m) return NO;
    IMP orig = method_getImplementation(m);
    const char *realTypes = method_getTypeEncoding(m);
    if (!ownTarget && !class_addMethod(cls, target, orig, realTypes)) return NO;
    if (!class_addMethod(cls, aliasSel, tramp, types ?: realTypes)) return NO;
    Method tm = hm_ownMethod(cls, target);
    Method am = hm_ownMethod(cls, aliasSel);
    if (!tm || !am || method_getImplementation(am)!=tramp) return NO;
    method_exchangeImplementations(tm, am);
    return method_getImplementation(tm)==tramp;
}
static id hm_tr_dt1(id self, SEL _cmd, NSURLRequest *req) {
    id ret = ((id(*)(id,SEL,id))objc_msgSend)(self, g_selDt1, req);
    hm_netObserve(req);
    return ret;
}
static id hm_tr_dt2(id self, SEL _cmd, NSURLRequest *req, id handler) {
    id ret = ((id(*)(id,SEL,id,id))objc_msgSend)(self, g_selDt2, req, handler);
    hm_netObserve(req);
    return ret;
}
static void hm_tr_conn(id cls, SEL _cmd, NSURLRequest *req, id queue, id handler) {
    ((void(*)(id,SEL,id,id,id))objc_msgSend)(cls, g_selConn, req, queue, handler);
    hm_netObserve(req);
}
static BOOL g_netScanStarted = NO;
static int g_netScanTries = 0;
static void hm_netScanPass(void) {
    t_suppress++;
    @try {
        Class sess = NSClassFromString(@"NSURLSession");
        Class conn = NSClassFromString(@"NSURLConnection");
        if (sess) {
            SEL t1 = @selector(dataTaskWithRequest:);
            SEL t2 = @selector(dataTaskWithRequest:completionHandler:);
            // 类簇：Hook NSURLSession 以及所有已实现目标 selector 的已加载具体子类。
            unsigned int count=0;
            Class *classes=objc_copyClassList(&count);
            if (classes) {
                for (unsigned int i=0; i<count; i++) {
                    Class c=classes[i];
                    if (!hm_isSubclassOrSame(c, sess)) continue;
                    Method m1=hm_ownMethod(c,t1);
                    if (m1) hm_swap(c,t1,(IMP)hm_tr_dt1,g_selDt1,method_getTypeEncoding(m1));
                    Method m2=hm_ownMethod(c,t2);
                    if (m2) hm_swap(c,t2,(IMP)hm_tr_dt2,g_selDt2,method_getTypeEncoding(m2));
                }
                free(classes);
            }
        }
        if (conn) {
            // +sendAsynchronousRequest:queue:completionHandler:（类方法 → metaclass）
            SEL t3 = @selector(sendAsynchronousRequest:queue:completionHandler:);
            Class meta = object_getClass(conn);
            Method m3 = hm_ownMethod(meta, t3);
            if (m3) hm_swap(meta, t3, (IMP)hm_tr_conn, g_selConn, method_getTypeEncoding(m3));
        }
    } @finally { t_suppress--; }
    if (++g_netScanTries < 60)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ hm_netScanPass(); });
}
static void hm_installNet(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_netScanStarted) return;
        g_netScanStarted=YES;
        g_selDt1 = sel_registerName("hm_orig_dt1:");
        g_selDt2 = sel_registerName("hm_orig_dt2::");
        g_selConn = sel_registerName("hm_orig_conn:::");
        hm_netScanPass();
    });
}

// ============================== E. 风控类深度枚举 + 动态安全 Hook ==============================
static const char *kDeepKeys[] = {"smantifraud","shumei","nbsdevice","bangsun","assumid",
                                  "umidtoken","antifraud","smid"};
static BOOL hm_deepNameMatch(NSString *lower) {
    if (!lower) return NO;
    for (unsigned i=0;i<sizeof(kDeepKeys)/sizeof(kDeepKeys[0]);i++)
        if ([lower containsString:[NSString stringWithUTF8String:kDeepKeys[i]]]) return YES;
    return NO;
}
static BOOL hm_interestPath(NSString *p) {
    if (!p) return NO;
    NSString *x = p.lowercaseString;
    NSArray *kw = @[@"shumei",@"smantifraud",@"/sm",@"nbs",@"bangsun",@"umid",@"tdid",
                    @"idfa",@"idfv",@"deviceid",@"device_id",@"getui",@"sensor",@"reyun",
                    @"osprey",@"tracking",@"keychain",@"credential",@"fingerprint",@"deviceprofile"];
    for (NSString *k in kw) if ([x containsString:k]) return YES;
    return NO;
}

// 枚举一个类（实例或元类）的方法：全部进清单；ABI 安全的加入可 Hook 列表
static void hm_deepEnumClass(Class cls, BOOL isMeta, NSString *clsName,
                             NSMutableArray *inv, NSMutableArray *hookable) {
    unsigned int mc=0;
    Method *ms = class_copyMethodList(cls, &mc);
    unsigned int shown = 0;
    for (unsigned int i=0;i<mc;i++) {
        Method m = ms[i];
        SEL sel = method_getName(m);
        const char *enc = method_getTypeEncoding(m) ?: "?";
        char rb[8]={0}; method_getReturnType(m, rb, sizeof(rb));
        char rk = hm_typeKind(rb);
        unsigned na = method_getNumberOfArguments(m);
        int argc = (int)na-2;
        NSMutableArray *argKinds=[NSMutableArray array];
        BOOL argsSafe=YES;
        for (unsigned a=2;a<na;a++){
            char ab[16]={0}; method_getArgumentType(m,a,ab,sizeof(ab));
            char k=hm_typeKind(ab); [argKinds addObject:[NSString stringWithFormat:@"%c",k]];
            if (!(k=='@'||k=='#')) argsSafe=NO;
        }
        NSString *selName = NSStringFromSelector(sel);
        BOOL isInit = [selName hasPrefix:@"init"];
        NSString *decision;
        BOOL canHook = NO;
        if (isInit) decision=@"不Hook(init族)";
        else if (rk=='@' && argc>=0 && argc<=2 && argsSafe) { canHook=YES; decision=@"将只读Hook"; }
        else decision=[NSString stringWithFormat:@"不Hook(返回=%c 参数=%@)",rk,argKinds];
        if (shown++ < 150)
            [inv addObject:@{@"cls":clsName, @"kind":isMeta?@"+":@"-", @"sel":selName,
                             @"enc":[NSString stringWithUTF8String:enc], @"decision":decision}];
        if (canHook && hookable.count < 60)
            [hookable addObject:@{@"cls":clsName, @"sel":selName, @"meta":@(isMeta)}];
    }
    if (ms) free(ms);
}

static int g_deepTries = 0;
static void hm_deepScanOnce(void) {
        t_suppress++;
        @try {
            unsigned int cnt=g_runtimeScanClassCount;
            BOOL ownsClassList=(g_runtimeScanClasses==NULL);
            Class *all = ownsClassList ? objc_copyClassList(&cnt) : g_runtimeScanClasses;
            if (all) {
                for (unsigned int i=0;i<cnt;i++) {
                    if (atomic_load_explicit(&g_slotCount, memory_order_acquire) >= HM_MAX_SLOTS-4) break;
                    Class c = all[i];
                    const char *cn = class_getName(c);
                    if (!cn) continue;
                    NSString *name = [NSString stringWithUTF8String:cn];
                    NSString *lower = name.lowercaseString;
                    if (!hm_deepNameMatch(lower)) continue;
                    BOOL already=NO;
                    os_unfair_lock_lock(&g_lock);
                    already = [g_deepDone containsObject:name];
                    if (!already) [g_deepDone addObject:name];
                    os_unfair_lock_unlock(&g_lock);
                    if (already) continue;

                    NSMutableArray *inv=[NSMutableArray array], *hookable=[NSMutableArray array];
                    hm_deepEnumClass(c, NO, name, inv, hookable);
                    hm_deepEnumClass(object_getClass(c), YES, name, inv, hookable);
                    os_unfair_lock_lock(&g_lock);
                    [g_deepInv addObjectsFromArray:inv];
                    os_unfair_lock_unlock(&g_lock);

                    for (NSDictionary *h in hookable) {
                        if (atomic_load_explicit(&g_slotCount, memory_order_acquire) >= HM_MAX_SLOTS) break;
                        NSMutableDictionary *rec=[NSMutableDictionary dictionary];
                        rec[@"clsName"]=h[@"cls"]; rec[@"selName"]=h[@"sel"];
                        rec[@"preferClass"]=h[@"meta"]; rec[@"group"]=@"风控类深度";
                        rec[@"hits"]=@0; rec[@"sampled"]=@NO; rec[@"status"]=@"待安装";
                        int idx;
                        os_unfair_lock_lock(&g_lock);
                        idx = atomic_load_explicit(&g_slotCount, memory_order_relaxed);
                        if (idx >= HM_MAX_SLOTS) { os_unfair_lock_unlock(&g_lock); break; }
                        [g_records addObject:rec];
                        g_hookSlots[idx].targetSel = NSSelectorFromString(h[@"sel"]);
                        atomic_store_explicit(&g_hookSlots[idx].aliasSel,NULL,memory_order_relaxed);
                        atomic_store_explicit(&g_hookSlots[idx].installedClass,NULL,memory_order_relaxed);
                        atomic_store_explicit(&g_slotCount, idx+1, memory_order_release);
                        os_unfair_lock_unlock(&g_lock);
                        hm_tryInstall(rec, idx);
                    }
                }
                if (ownsClassList) free(all);
            }
        } @finally { t_suppress--; }
}
static void hm_runtimeScanOnce(void);
static void hm_deepScanPass(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        hm_runtimeScanOnce();
        if (++g_deepTries < 60)
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{hm_deepScanPass();});
    });
}

// ============================== F. Keychain 观测（dyld interpose，只记键名不记值） ==============================
// interposer 自身对 SecItem* 的直接绑定由 dyld 保留为原实现调用链；不要再经 dlsym，
// dlsym 的结果仍会应用通用 interpose，反而会解析回本包装函数并递归。
static NSString *hm_kcQueryStr(CFDictionaryRef q, CFStringRef k) {
    if (!q || !k) return nil;
    @try {
        id v = [(__bridge NSDictionary*)q objectForKey:(__bridge id)k];
        if (!v) return nil;
        if ([v isKindOfClass:NSString.class]) return hm_maskString((NSString*)v);
        return NSStringFromClass([v class]);
    } @catch (NSException *e) { return @"<枚举异常>"; }
}
static void hm_kcNote(NSString *op, CFDictionaryRef q, OSStatus st) {
    if (t_suppress) return;
    t_suppress++;
    @try {
        NSString *cls =hm_kcQueryStr(q,kSecClass);
        NSString *svc =hm_kcQueryStr(q,kSecAttrService);
        NSString *acct=hm_kcQueryStr(q,kSecAttrAccount);
        NSString *grp =hm_kcQueryStr(q,kSecAttrAccessGroup);
        NSString *key=[NSString stringWithFormat:@"%@|%@|%@|%@",op,svc?:@"-",acct?:@"-",cls?:@"-"];
        BOOL first=NO; NSMutableDictionary *rec=nil;
        os_unfair_lock_lock(&g_lock);
        rec=g_kcSeen[key];
        if(!rec){rec=[NSMutableDictionary dictionary];
            rec[@"op"]=op;rec[@"class"]=cls?:@"-";rec[@"service"]=svc?:@"-";
            rec[@"account"]=acct?:@"-";rec[@"group"]=grp?:@"-";
            rec[@"hits"]=@0;g_kcSeen[key]=rec;first=YES;}
        rec[@"hits"]=@([rec[@"hits"] unsignedLongValue]+1);
        if(!rec[@"firstStatus"]) rec[@"firstStatus"]=@(st);
        os_unfair_lock_unlock(&g_lock);
        if(first){ os_unfair_lock_lock(&g_lock); rec[@"stack"]=hm_shortStack(); os_unfair_lock_unlock(&g_lock); }
    } @finally { t_suppress--; }
}
static OSStatus hm_kc_CopyMatching(CFDictionaryRef q, CFTypeRef *r) {
    OSStatus s = SecItemCopyMatching(q,r);
    hm_kcNote(@"CopyMatching(读)", q, s);
    return s;
}
static OSStatus hm_kc_Add(CFDictionaryRef q, CFTypeRef *r) {
    OSStatus s = SecItemAdd(q,r);
    hm_kcNote(@"Add(写)", q, s);
    return s;
}
static OSStatus hm_kc_Update(CFDictionaryRef q, CFDictionaryRef attrs) {
    OSStatus s = SecItemUpdate(q,attrs);
    hm_kcNote(@"Update(改)", q, s);
    return s;
}
static OSStatus hm_kc_Delete(CFDictionaryRef q) {
    OSStatus s = SecItemDelete(q);
    hm_kcNote(@"Delete(删)", q, s);
    return s;
}
DYLD_INTERPOSE(hm_kc_CopyMatching, SecItemCopyMatching)
DYLD_INTERPOSE(hm_kc_Add,        SecItemAdd)
DYLD_INTERPOSE(hm_kc_Update,     SecItemUpdate)
DYLD_INTERPOSE(hm_kc_Delete,     SecItemDelete)

// ============================== F2. C 层文件打开观测（dyld interpose open/openat/fopen） ==============================
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
// 与上面的 SecItem interposer 相同：替换函数所在镜像对原符号的直接绑定由 dyld 保留。
// 不使用 dlsym；dlsym 的结果仍会应用 interpose，可能解析回本包装函数并自递归。
static BOOL hm_inSandboxC(const char *p) {
    if (!p || !g_homeC[0]) return NO;
    size_t n=strlen(g_homeC);
    return strncmp(p,g_homeC,n)==0 && (p[n]=='\0' || p[n]=='/');
}
static BOOL hm_openMayWrite(int oflag) {
    return ((oflag&O_ACCMODE)!=O_RDONLY) || (oflag&(O_CREAT|O_TRUNC));
}
// openat 的相对路径在成功打开后优先 realpath；否则用 dirfd/cwd 的纯 C 路径供沙盒预筛。
static const char *hm_openatAbsolutePath(int dirfd, const char *path, char *buf, size_t cap) {
    if (!path || !path[0]) return NULL;
    if (path[0]=='/') return path;
    char base[PATH_MAX]={0}, joined[PATH_MAX]={0};
    if (dirfd==AT_FDCWD) {
        if (!getcwd(base,sizeof(base))) return NULL;
    } else if (fcntl(dirfd,F_GETPATH,base)<0) {
        return NULL;
    }
    int n=snprintf(joined,sizeof(joined),"%s/%s",base,path);
    if (n<0 || (size_t)n>=sizeof(joined)) return NULL;
    if (realpath(joined,buf)) return buf;
    if ((size_t)n>=cap) return NULL;
    memcpy(buf,joined,(size_t)n+1);
    return buf;
}
static void hm_cFileNote(NSString *op, const char *path) {
    if (t_suppress || !path) return;
    if (!hm_inSandboxC(path)) return;
    t_suppress++;
    @try {
        NSString *ps=[NSString stringWithUTF8String:path];
        if (!ps) return;
        BOOL first=NO; NSMutableDictionary *rec=nil;
        os_unfair_lock_lock(&g_lock);
        if (!g_cFileSeen) g_cFileSeen=[NSMutableDictionary dictionary];
        NSString *key=[NSString stringWithFormat:@"%@|%@",op,ps];
        rec=g_cFileSeen[key];
        if (!rec && g_cFileSeen.count>=800) { os_unfair_lock_unlock(&g_lock); return; }
        if (!rec) { rec=[NSMutableDictionary dictionary]; rec[@"op"]=op; rec[@"path"]=ps;
            rec[@"hits"]=@0; rec[@"interest"]=@(hm_interestPath(ps)); g_cFileSeen[key]=rec; first=YES; }
        rec[@"hits"]=@([rec[@"hits"] unsignedLongValue]+1);
        os_unfair_lock_unlock(&g_lock);
        if (first) { os_unfair_lock_lock(&g_lock); rec[@"stack"]=hm_shortStack(); os_unfair_lock_unlock(&g_lock); }
    } @finally { t_suppress--; }
}
static int hm_c_open(const char *path, int oflag, ...) {
    mode_t mode=0;
    if (oflag&O_CREAT) { va_list ap; va_start(ap,oflag); mode=(mode_t)va_arg(ap,int); va_end(ap); }
    int fd=open(path,oflag,mode);
    int savedErrno=errno;
    if (fd>=0 && hm_openMayWrite(oflag)) hm_cFileNote(@"open(写)",path);
    errno=savedErrno;
    return fd;
}
static int hm_c_openat(int dirfd, const char *path, int oflag, ...) {
    mode_t mode=0;
    if (oflag&O_CREAT) { va_list ap; va_start(ap,oflag); mode=(mode_t)va_arg(ap,int); va_end(ap); }
    int fd=openat(dirfd,path,oflag,mode);
    int savedErrno=errno;
    if (fd>=0 && hm_openMayWrite(oflag)) {
        char absolutePath[PATH_MAX]={0};
        const char *observedPath=hm_openatAbsolutePath(dirfd,path,absolutePath,sizeof(absolutePath));
        hm_cFileNote(@"openat(写)",observedPath);
    }
    errno=savedErrno;
    return fd;
}
static FILE *hm_c_fopen(const char *path, const char *mode) {
    FILE *f=fopen(path,mode);
    int savedErrno=errno;
    if (f && mode && (mode[0]=='w'||mode[0]=='a'||strchr(mode,'+'))) hm_cFileNote(@"fopen(写)",path);
    errno=savedErrno;
    return f;
}
DYLD_INTERPOSE(hm_c_open, open)
DYLD_INTERPOSE(hm_c_openat, openat)
DYLD_INTERPOSE(hm_c_fopen, fopen)

// ============================== G. NSUserDefaults 观测 ==============================
// 类簇兼容：基类与所有“自身实现了该 selector”的已加载子类都安装
static NSUInteger hm_swapClassCluster(Class root, SEL target, IMP tramp, SEL alias) {
    if (!root) return 0;
    NSUInteger installed=0;
    Method m0=hm_ownMethod(root,target);
    if (m0 && hm_swap(root,target,tramp,alias,method_getTypeEncoding(m0))) installed++;
    unsigned int cc=g_runtimeScanClassCount;
    BOOL ownsClassList=(g_runtimeScanClasses==NULL);
    Class *all=ownsClassList ? objc_copyClassList(&cc) : g_runtimeScanClasses;
    if (all) {
        for (unsigned int i=0;i<cc;i++) {
            Class c=all[i];
            if (c==root || !hm_isSubclassOrSame(c,root)) continue;
            Method mm=hm_ownMethod(c,target); // 仅自身实现才需要装；继承的走基类
            if (mm && hm_swap(c,target,tramp,alias,method_getTypeEncoding(mm))) installed++;
        }
        if (ownsClassList) free(all);
    }
    return installed;
}
static SEL g_udObj=NULL,g_udSet=NULL,g_udStr=NULL,g_udBool=NULL,g_udInt=NULL;
static void hm_udNote(NSString *op, NSString *key, id val) {
    if (t_suppress || ![key isKindOfClass:NSString.class]) return;
    t_suppress++;
    @try {
        NSString *kk=[NSString stringWithFormat:@"%@|%@",op,key];
        BOOL first=NO; NSMutableDictionary *rec=nil;
        os_unfair_lock_lock(&g_lock);
        rec=g_udSeen[kk];
        if(!rec){rec=[NSMutableDictionary dictionary];rec[@"op"]=op;rec[@"key"]=key;
            rec[@"hits"]=@0;rec[@"interest"]=@(hm_sensitiveKey(key)||hm_interestPath(key));
            g_udSeen[kk]=rec;first=YES;}
        rec[@"hits"]=@([rec[@"hits"] unsignedLongValue]+1);
        os_unfair_lock_unlock(&g_lock);
        if(first){
            NSString *sum=nil, *stack=nil;
            @try { sum=hm_summary(val,0,key); stack=hm_shortStack(); }
            @catch (NSException *e) { sum=[NSString stringWithFormat:@"<采样异常:%@>",e.name]; }
            os_unfair_lock_lock(&g_lock); rec[@"sample"]=sum?:@"nil"; rec[@"stack"]=stack?:@""; os_unfair_lock_unlock(&g_lock);
        }
    } @finally { t_suppress--; }
}
static id hm_ud_tr_object(id self,SEL _cmd,NSString*key){
    id r=((id(*)(id,SEL,id))objc_msgSend)(self,g_udObj,key); hm_udNote(@"objectForKey:",key,r); return r;
}
static void hm_ud_tr_set(id self,SEL _cmd,id val,NSString*key){
    hm_udNote(@"setObject:forKey:",key,val); ((void(*)(id,SEL,id,id))objc_msgSend)(self,g_udSet,val,key);
}
static id hm_ud_tr_string(id self,SEL _cmd,NSString*key){
    id r=((id(*)(id,SEL,id))objc_msgSend)(self,g_udStr,key); hm_udNote(@"stringForKey:",key,r); return r;
}
static BOOL hm_ud_tr_bool(id self,SEL _cmd,NSString*key){
    BOOL r=((BOOL(*)(id,SEL,id))objc_msgSend)(self,g_udBool,key); hm_udNote(@"boolForKey:",key,@(r)); return r;
}
static long long hm_ud_tr_int(id self,SEL _cmd,NSString*key){
    long long r=((long long(*)(id,SEL,id))objc_msgSend)(self,g_udInt,key); hm_udNote(@"integerForKey:",key,@(r)); return r;
}
static void hm_installDefaultsOnce(void) {
        Class c=NSClassFromString(@"NSUserDefaults"); if(!c) return;
        g_udObj=sel_registerName("hm2_ud_object:");
        g_udSet=sel_registerName("hm2_ud_set::");
        g_udStr=sel_registerName("hm2_ud_string:");
        g_udBool=sel_registerName("hm2_ud_bool:");
        g_udInt=sel_registerName("hm2_ud_int:");
        hm_swapClassCluster(c,@selector(objectForKey:),(IMP)hm_ud_tr_object,g_udObj);
        hm_swapClassCluster(c,@selector(setObject:forKey:),(IMP)hm_ud_tr_set,g_udSet);
        hm_swapClassCluster(c,@selector(stringForKey:),(IMP)hm_ud_tr_string,g_udStr);
        hm_swapClassCluster(c,@selector(boolForKey:),(IMP)hm_ud_tr_bool,g_udBool);
        hm_swapClassCluster(c,@selector(integerForKey:),(IMP)hm_ud_tr_int,g_udInt);
}

// ============================== H. 文件写入观测 + 沙盒快照 ==============================
static SEL g_fmCreate=NULL,g_dataWrite=NULL,g_strWrite=NULL;
static void hm_fileNote(NSString *op, NSString *path, NSUInteger len) {
    if (t_suppress || ![path isKindOfClass:NSString.class]) return;
    t_suppress++;
    @try {
        NSString *key=[NSString stringWithFormat:@"%@|%@",op,path];
        BOOL first=NO; NSMutableDictionary *rec=nil;
        os_unfair_lock_lock(&g_lock);
        rec=g_fileSeen[key];
        if (!rec && g_fileSeen.count>=400) { os_unfair_lock_unlock(&g_lock); return; }
        if(!rec){rec=[NSMutableDictionary dictionary];rec[@"op"]=op;rec[@"path"]=path;
            rec[@"hits"]=@0;rec[@"interest"]=@(hm_interestPath(path));g_fileSeen[key]=rec;first=YES;}
        rec[@"hits"]=@([rec[@"hits"] unsignedLongValue]+1);
        if(len>0) rec[@"lastLen"]=@(len);
        os_unfair_lock_unlock(&g_lock);
        if(first){os_unfair_lock_lock(&g_lock);rec[@"stack"]=hm_shortStack();os_unfair_lock_unlock(&g_lock);}
    } @finally { t_suppress--; }
}
static BOOL hm_fm_tr_create(id self,SEL _cmd,NSString*path,NSData*contents,NSDictionary*attr){
    BOOL r=((BOOL(*)(id,SEL,id,id,id))objc_msgSend)(self,g_fmCreate,path,contents,attr);
    hm_fileNote(@"NSFileManager.createFile",path,contents.length); return r;
}
static BOOL hm_data_tr_write(id self,SEL _cmd,NSString*path,BOOL atom){
    BOOL r=((BOOL(*)(id,SEL,id,BOOL))objc_msgSend)(self,g_dataWrite,path,atom);
    hm_fileNote(@"NSData.writeToFile",path,0); return r;
}
static BOOL hm_str_tr_write(id self,SEL _cmd,NSString*path,BOOL atom,NSStringEncoding enc,NSError**err){
    BOOL r=((BOOL(*)(id,SEL,id,BOOL,NSUInteger,void*))objc_msgSend)(self,g_strWrite,path,atom,enc,err);
    hm_fileNote(@"NSString.writeToFile",path,0); return r;
}
static void hm_installFilesOnce(void) {
        Class fm=NSClassFromString(@"NSFileManager");
        Class data=NSClassFromString(@"NSData");
        Class str=NSClassFromString(@"NSString");
        g_fmCreate=sel_registerName("hm2_fm_create:::");
        g_dataWrite=sel_registerName("hm2_data_write:");
        g_strWrite=sel_registerName("hm2_str_write:::");
        if(fm)  hm_swap(fm,@selector(createFileAtPath:contents:attributes:),(IMP)hm_fm_tr_create,g_fmCreate,NULL);
        if(data)hm_swapClassCluster(data,@selector(writeToFile:atomically:),(IMP)hm_data_tr_write,g_dataWrite);
        if(str) hm_swapClassCluster(str,@selector(writeToFile:atomically:encoding:error:),(IMP)hm_str_tr_write,g_strWrite);
}
static void hm_runtimeScanOnce(void) {
    unsigned int count=0;
    Class *classes=objc_copyClassList(&count);
    g_runtimeScanClasses=classes;
    g_runtimeScanClassCount=count;
    @try {
        hm_installDefaultsOnce();
        hm_installFilesOnce();
        hm_deepScanOnce();
    } @finally {
        g_runtimeScanClasses=NULL;
        g_runtimeScanClassCount=0;
        if (classes) free(classes);
    }
}
// 导出时只读快照容器目录树（不读文件内容）。v3：上限放大、合并运行期写标记、单列小文件
static NSDictionary *hm_containerSnapshot(void) {
    NSMutableArray *tree=[NSMutableArray array];
    NSMutableArray *hits=[NSMutableArray array];
    NSMutableArray *small=[NSMutableArray array];
    unsigned long long totalBytes=0; NSUInteger totalFiles=0, totalDirs=0, truncated=0;
    NSMutableSet *written=[NSMutableSet set];
    os_unfair_lock_lock(&g_lock);
    for (NSMutableDictionary *r in g_fileSeen.allValues) { NSString *p=r[@"path"]; if(p)[written addObject:p]; }
    for (NSMutableDictionary *r in g_cFileSeen.allValues) { NSString *p=r[@"path"]; if(p)[written addObject:p]; }
    os_unfair_lock_unlock(&g_lock);
    @try {
        NSString *home=NSHomeDirectory();
        NSFileManager *fm=NSFileManager.defaultManager;
        NSDirectoryEnumerator *en=[fm enumeratorAtPath:home];
        NSString *rel;
        while ((rel=[en nextObject])) {
            if (tree.count>=3000) { truncated++; continue; }
            NSString *full=[home stringByAppendingPathComponent:rel];
            BOOL dir=NO;
            if (![fm fileExistsAtPath:full isDirectory:&dir]) continue;
            if (dir) { totalDirs++; continue; }
            totalFiles++;
            unsigned long long sz=0;
            NSDictionary *attr=[fm attributesOfItemAtPath:full error:nil];
            sz=[attr fileSize]; totalBytes+=sz;
            BOOL wasWrite=[written containsObject:full];
            NSString *tag=wasWrite?@"  [运行期写]":@"";
            NSString *line=[NSString stringWithFormat:@"%@  (%llu B)%@",rel,sz,tag];
            [tree addObject:line];
            if (hm_interestPath(rel) && hits.count<300) [hits addObject:line];
            if (sz<=4096 && small.count<600) {
                [small addObject:[NSString stringWithFormat:@"%@  (%llu B)%@%@",rel,sz,
                                  hm_interestPath(rel)?@"  [重点]":@"",tag]];
            }
        }
    } @catch (NSException *e) {
        [tree addObject:[NSString stringWithFormat:@"<快照枚举异常: %@>",e.name]];
    }
    return @{@"tree":tree,@"hits":hits,@"small":small,@"files":@(totalFiles),@"dirs":@(totalDirs),
             @"bytes":@(totalBytes),@"truncated":@(truncated)};
}


// ============================== A. SDK 普查 ==============================
static void hm_matchVendor(NSString *lowerName, NSString *imageName, BOOL fromImage) {
    for (int v=0; v<kVendorCount; v++) {
        BOOL hit=NO;
        for (int k=0; k<8 && kVendors[v].keys[k]; k++) {
            if ([lowerName containsString:[NSString stringWithUTF8String:kVendors[v].keys[k]]]) { hit=YES; break; }
        }
        if (!hit) continue;
        NSString *vn=[NSString stringWithUTF8String:kVendors[v].vendor];
        NSMutableDictionary *bucket=g_vendorHit[vn];
        if (!bucket) { bucket=[NSMutableDictionary dictionary];
            bucket[@"classes"]=[NSMutableSet set]; bucket[@"images"]=[NSMutableSet set]; g_vendorHit[vn]=bucket; }
        if (fromImage) { if(imageName) [(NSMutableSet*)bucket[@"images"] addObject:imageName]; }
        else { if(imageName) [(NSMutableSet*)bucket[@"images"] addObject:imageName];
               [(NSMutableSet*)bucket[@"classes"] addObject:lowerName]; }
    }
}
static void hm_census(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        t_suppress++;
        @try {
            // 1) ObjC 类名
            unsigned int cnt=0;
            Class *all=objc_copyClassList(&cnt);
            if (all) {
                for (unsigned int i=0;i<cnt;i++) {
                    const char *cn=class_getName(all[i]);
                    if (!cn) continue;
                    NSString *lower=[[NSString stringWithUTF8String:cn] lowercaseString];
                    const char *img=class_getImageName(all[i]);
                    NSString *imgName=nil;
                    if (img) { const char *b=strrchr(img,'/'); imgName=[NSString stringWithUTF8String:b?b+1:img]; }
                    os_unfair_lock_lock(&g_lock);
                    hm_matchVendor(lower, imgName, NO);
                    os_unfair_lock_unlock(&g_lock);
                }
                free(all);
            }
            // 2) 已加载镜像名（覆盖纯 C/无 ObjC 类的 SDK）
            uint32_t ic=_dyld_image_count();
            for (uint32_t i=0;i<ic;i++) {
                const char *in=_dyld_get_image_name(i);
                if (!in) continue;
                const char *b=strrchr(in,'/');
                NSString *name=[[NSString stringWithUTF8String:b?b+1:in] lowercaseString];
                NSString *disp=[NSString stringWithUTF8String:b?b+1:in];
                os_unfair_lock_lock(&g_lock);
                hm_matchVendor(name, disp, YES);
                os_unfair_lock_unlock(&g_lock);
            }
        } @finally { t_suppress--; }
    });
}

// ============================== 报告 / 浮窗 ==============================
static NSString *hm_machineName(void) {
    struct utsname u; memset(&u,0,sizeof(u));
    if (uname(&u)==0) return [NSString stringWithUTF8String:u.machine];
    return @"?";
}
@interface HMProbeStore : NSObject
+ (NSString *)buildReport;
+ (void)share;
+ (void)mark;
@end
@interface HMProbeWindow : UIWindow @end
@implementation HMProbeWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *h=[super hitTest:point withEvent:event];
    return (h==self||h==self.rootViewController.view)?nil:h;
}
@end
@interface UIButton (HMDrag) - (void)hm_drag:(UIPanGestureRecognizer*)g; @end

@implementation HMProbeStore
+ (NSString *)buildReport {
    t_suppress++;
    @try {
    NSMutableString *s=[NSMutableString string];
    NSBundle *mb=NSBundle.mainBundle;
    NSDictionary *info=mb.infoDictionary;
    [s appendString:@"河马剧场 只读诊断探针 HMProbe v3 报告\n"];
    [s appendFormat:@"生成时间: %@\n",[NSDate date]];
    [s appendString:@"========== 一、运行环境 ==========\n"];
    [s appendFormat:@"App显示名: %@\n", info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: @"?"];
    [s appendFormat:@"BundleID: %@\n", mb.bundleIdentifier?:@"?"];
    [s appendFormat:@"App版本: %@ (%@)\n", info[@"CFBundleShortVersionString"]?:@"?", info[@"CFBundleVersion"]?:@"?"];
    [s appendFormat:@"iOS: %@ | 机型: %@\n", UIDevice.currentDevice.systemVersion, hm_machineName()];

    NSDictionary *vendors=nil; NSArray *evs=nil,*recs=nil,*marks=nil;
    NSArray *deepInv=nil,*deepRecs=nil,*kcAll=nil,*udAll=nil,*fileAll=nil,*cFileAll=nil;
    NSMutableArray *baseRecs=nil;
    os_unfair_lock_lock(&g_lock);
    @try {
        NSMutableDictionary *vendorSnapshot=[NSMutableDictionary dictionaryWithCapacity:g_vendorHit.count];
        for (NSString *vn in g_vendorHit) {
            NSDictionary *bucket=g_vendorHit[vn];
            vendorSnapshot[vn]=@{@"classes":[(NSSet*)bucket[@"classes"] copy] ?: [NSSet set],
                                 @"images":[(NSSet*)bucket[@"images"] copy] ?: [NSSet set]};
        }
        vendors=[vendorSnapshot copy];
        evs=[[NSArray alloc] initWithArray:g_events copyItems:YES];
        recs=[[NSArray alloc] initWithArray:g_records copyItems:YES];
        marks=[g_markers copy];
        baseRecs=[NSMutableArray array];
        for (NSDictionary *r in g_records)
            if ([r[@"group"] isEqualToString:@"风控类深度"]) {} else [baseRecs addObject:r];
        deepRecs=[[g_records filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"group == %@",@"风控类深度"]] copy];
        deepInv=[g_deepInv copy];
        NSMutableArray *kcSnapshot=[NSMutableArray arrayWithCapacity:g_kcSeen.count];
        NSMutableArray *udSnapshot=[NSMutableArray arrayWithCapacity:g_udSeen.count];
        NSMutableArray *fileSnapshot=[NSMutableArray arrayWithCapacity:g_fileSeen.count];
        NSMutableArray *cFileSnapshot=[NSMutableArray arrayWithCapacity:g_cFileSeen.count];
        for (NSDictionary *r in g_kcSeen.allValues) [kcSnapshot addObject:[r copy]];
        for (NSDictionary *r in g_udSeen.allValues) [udSnapshot addObject:[r copy]];
        for (NSDictionary *r in g_fileSeen.allValues) [fileSnapshot addObject:[r copy]];
        for (NSDictionary *r in g_cFileSeen.allValues) [cFileSnapshot addObject:[r copy]];
        kcAll=[kcSnapshot copy]; udAll=[udSnapshot copy]; fileAll=[fileSnapshot copy];
        cFileAll=[cFileSnapshot sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){
            NSComparisonResult r=[a[@"op"] compare:b[@"op"]];
            return r==NSOrderedSame?[a[@"path"] localizedCompare:b[@"path"]]:r;
        }];
    } @finally { os_unfair_lock_unlock(&g_lock); }
    NSDictionary *snap = hm_containerSnapshot();

    [s appendString:@"\n========== 二、SDK 普查（风控/统计/归因/广告） ==========\n"];
    if (vendors.count==0) [s appendString:@"未命中内置关键字表中的任何 SDK（可能使用自研或未收录 SDK，需结合网络事件与镜像名判断）\n"];
    for (NSString *vn in vendors) {
        NSDictionary *b=vendors[vn];
        NSArray *cls=[(NSSet*)b[@"classes"] allObjects];
        NSArray *imgs=[(NSSet*)b[@"images"] allObjects];
        NSArray *cs=[cls sortedArrayUsingSelector:@selector(compare:)];
        NSArray *is=[imgs sortedArrayUsingSelector:@selector(compare:)];
        [s appendFormat:@"● %@\n",vn];
        [s appendFormat:@"  命中类(%lu): %@\n",(unsigned long)cs.count, cs.count?[[cs subarrayWithRange:NSMakeRange(0,MIN(cs.count,8))] componentsJoinedByString:@", "]:@"-"];
        [s appendFormat:@"  所在镜像: %@\n", is.count?[is componentsJoinedByString:@", "]:@"-"];
    }

    [s appendString:@"\n========== 三、设备/剪贴板信息读取 ==========\n"];
    for (NSDictionary *r in baseRecs) {
        [s appendFormat:@"[%@] %@ %@ %@\n",r[@"group"],r[@"kind"]?:@"?",r[@"clsName"],r[@"selName"]];
        [s appendFormat:@"  状态:%@ 命中:%@\n",r[@"status"],r[@"hits"]?:@0];
        if (r[@"encoding"])
            [s appendFormat:@"  签名:%@ | 返回=%@ | 参数数=%@ [%@]\n",r[@"encoding"],r[@"retType"],r[@"argc"],[(NSArray*)r[@"argTypes"] componentsJoinedByString:@","]];
        if (r[@"sampleArgs"]) [s appendFormat:@"  入参样本: %@\n",r[@"sampleArgs"]];
        if (r[@"sampleReturn"]) [s appendFormat:@"  返回样本: %@\n",r[@"sampleReturn"]];
        if ([(NSString*)r[@"sampleStack"] length]) [s appendFormat:@"  首次短栈:\n%@\n",r[@"sampleStack"]];
    }

    [s appendString:@"\n========== 四、风控类深度枚举/动态只读 Hook（数美/邦盛/UMID 等） ==========\n"];
    [s appendFormat:@"命中风控类: %lu 个；方法清单条目: %lu；动态Hook记录: %lu\n",
     (unsigned long)g_deepDone.count,(unsigned long)deepInv.count,(unsigned long)deepRecs.count];
    NSString *lastCls=@"";
    for (NSDictionary *m in deepInv) {
        if (![m[@"cls"] isEqualToString:lastCls]) { [s appendFormat:@"── %@ ──\n",m[@"cls"]]; lastCls=m[@"cls"]; }
        [s appendFormat:@"  %@ %@  [%@]  => %@\n",m[@"kind"],m[@"sel"],m[@"enc"],m[@"decision"]];
    }
    [s appendString:@"  —— 已动态 Hook 方法的返回样本 ——\n"];
    for (NSDictionary *r in deepRecs) {
        [s appendFormat:@"[%@] %@ %@ 状态:%@ 命中:%@\n",r[@"group"],r[@"kind"]?:@"?",r[@"selName"],r[@"status"],r[@"hits"]?:@0];
        if (r[@"encoding"]) [s appendFormat:@"  签名:%@\n",r[@"encoding"]];
        if (r[@"sampleReturn"]) [s appendFormat:@"  返回样本: %@\n",r[@"sampleReturn"]];
        if ([(NSString*)r[@"sampleStack"] length]) [s appendFormat:@"  首次短栈:\n%@\n",r[@"sampleStack"]];
    }

    [s appendString:@"\n========== 五、Keychain 读写观测（只记键名，不记值） ==========\n"];
    [s appendFormat:@"不同 Keychain 项: %lu\n",(unsigned long)kcAll.count];
    for (NSDictionary *r in kcAll) {
        [s appendFormat:@"● %@ class=%@ service=%@ account=%@ group=%@ 命中:%@ 首次状态:%@\n",
         r[@"op"],r[@"class"],r[@"service"],r[@"account"],r[@"group"],r[@"hits"],r[@"firstStatus"]];
        if ([(NSString*)r[@"stack"] length]) [s appendFormat:@"  首次短栈:\n%@\n",r[@"stack"]];
    }

    [s appendString:@"\n========== 六、NSUserDefaults 读写观测（按键去重） ==========\n"];
    NSArray *udSorted=[udAll sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b){
        if ([a[@"interest"] boolValue]!=[b[@"interest"] boolValue]) return [a[@"interest"] boolValue]?NSOrderedAscending:NSOrderedDescending;
        return [a[@"key"] compare:b[@"key"]]; }];
    [s appendFormat:@"不同键: %lu（★为设备/标识相关）\n",(unsigned long)udSorted.count];
    for (NSDictionary *r in udSorted) {
        [s appendFormat:@"%@ [%@] key=%@ 命中:%@ 样本:%@\n",
         [r[@"interest"] boolValue]?@"★":@" ",r[@"op"],r[@"key"],r[@"hits"],r[@"sample"]?:@"-"];
    }

    [s appendString:@"\n========== 七、文件持久化（运行期写入 + 导出时沙盒快照） ==========\n"];
    NSArray *fSorted=[fileAll sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b){
        if ([a[@"interest"] boolValue]!=[b[@"interest"] boolValue]) return [a[@"interest"] boolValue]?NSOrderedAscending:NSOrderedDescending;
        return [a[@"path"] compare:b[@"path"]]; }];
    [s appendFormat:@"运行期写文件路径(去重): %lu（★为关键词命中）\n",(unsigned long)fSorted.count];
    for (NSDictionary *r in fSorted) {
        [s appendFormat:@"%@ [%@] %@ 命中:%@ %@\n",[r[@"interest"] boolValue]?@"★":@" ",
         r[@"op"],r[@"path"],r[@"hits"],r[@"lastLen"]?[NSString stringWithFormat:@"最后写入:%@ B",r[@"lastLen"]]:@""];
        if ([r[@"interest"] boolValue] && [(NSString*)r[@"stack"] length]) [s appendFormat:@"  首次短栈:\n%@\n",r[@"stack"]];
    }
    [s appendString:@"\n—— 7.2 C 层 open/openat/fopen 以写方式打开（dyld interpose，全镜像生效）——\n"];
    if (!cFileAll.count) [s appendString:@"(无)\n"];
    for (NSDictionary *r in cFileAll) {
        [s appendFormat:@"● [%@] %@  命中:%@%@\n",r[@"op"],r[@"path"],r[@"hits"],
         [r[@"interest"] boolValue]?@"  [重点路径]":@""];
        if ([r[@"interest"] boolValue] && [(NSString*)r[@"stack"] length])
            [s appendFormat:@"  首次栈:\n%@\n",r[@"stack"]];
    }
    [s appendFormat:@"\n沙盒快照: 文件%@个 目录%@个 总大小%@ B 超限未列:%@\n",
     snap[@"files"],snap[@"dirs"],snap[@"bytes"],snap[@"truncated"]];
    [s appendString:@"小文件清单(<=4KB，重点找数美/UMID 等 ID 文件):\n"];
    for (NSString *l in (NSArray*)snap[@"small"]) [s appendFormat:@"  %@\n",l];
    [s appendString:@"\n★ 关键词命中文件/目录（数美/邦盛/设备ID 持久化重点排查）:\n"];
    for (NSString *l in (NSArray*)snap[@"hits"]) [s appendFormat:@"  %@\n",l];
    [s appendString:@"完整目录树(最多3000项):\n"];
    for (NSString *l in (NSArray*)snap[@"tree"]) [s appendFormat:@"  %@\n",l];

    [s appendString:@"\n========== 八、网络请求事件（去重后） ==========\n"];
    [s appendFormat:@"不同请求端点: %lu 个\n",(unsigned long)evs.count];
    for (NSDictionary *e in evs) {
        [s appendFormat:@"● [%@] %@  命中:%@\n",e[@"method"],e[@"key"],e[@"hits"]?:@0];
        [s appendFormat:@"  请求头: %@\n",e[@"headers"]?:@""];
        [s appendFormat:@"  Query: %@\n",e[@"query"]?:@""];
        [s appendFormat:@"  Body: %@\n",e[@"body"]?:@""];
        if ([(NSString*)e[@"stack"] length]) [s appendFormat:@"  首次短栈:\n%@\n",e[@"stack"]];
    }

    [s appendString:@"\n========== 九、用户手动标记 ==========\n"];
    [s appendFormat:@"%@\n", marks.count?[marks componentsJoinedByString:@"\n"]:@"(无)"];
    return s;
    } @finally { t_suppress--; }
}
+ (void)mark {
    t_suppress++;
    @try {
        NSString *line=[NSString stringWithFormat:@"%@ 用户标记",[NSDate date]];
        os_unfair_lock_lock(&g_lock); [g_markers addObject:line]; os_unfair_lock_unlock(&g_lock);
    } @finally { t_suppress--; }
}
+ (void)share {
    t_suppress++;
    NSString *report=nil; NSString *path=nil; NSError *e=nil;
    @try {
        report=[self buildReport];
        UIPasteboard.generalPasteboard.string=report;
        NSString *docs=NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES).firstObject;
        NSDateFormatter *f=[NSDateFormatter new]; f.dateFormat=@"yyyy-MM-dd_HH_mm_ss_ZZZ";
        path=[docs stringByAppendingPathComponent:[NSString stringWithFormat:@"HMProbe3_log_%@.txt",[f stringFromDate:[NSDate date]]]];
        [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&e];
    } @finally { t_suppress--; }
    NSURL *url=(e||!path)?nil:[NSURL fileURLWithPath:path];
    dispatch_async(dispatch_get_main_queue(), ^{
        t_suppress++;
        @try {
            UIViewController *vc=nil;
            for (UIScene *sc in UIApplication.sharedApplication.connectedScenes)
                if ([sc isKindOfClass:UIWindowScene.class]&&sc.activationState==UISceneActivationStateForegroundActive)
                    for (UIWindow *x in ((UIWindowScene*)sc).windows){UIViewController *t=x.rootViewController;if(t){vc=t;break;}}
            if (!vc) return;
            UIActivityViewController *ac=[[UIActivityViewController alloc] initWithActivityItems:(url?@[url,report]:@[report]) applicationActivities:nil];
            UIViewController *top=vc; while(top.presentedViewController) top=top.presentedViewController;
            ac.popoverPresentationController.sourceView=top.view;
            [top presentViewController:ac animated:YES completion:nil];
        } @finally { t_suppress--; }
    });
}
@end

static HMProbeWindow *g_win=nil; static int g_floatTries=0;
static void hm_float(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_win) return;
        UIWindowScene *scene=nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes)
            if ([s isKindOfClass:UIWindowScene.class]&&s.activationState==UISceneActivationStateForegroundActive){scene=(UIWindowScene*)s;break;}
        if (!scene){ if(++g_floatTries<=10) dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{hm_float();}); return;}
        t_suppress++;
        @try {
            HMProbeWindow *w=[[HMProbeWindow alloc] initWithWindowScene:scene];
            w.frame=UIScreen.mainScreen.bounds; w.windowLevel=UIWindowLevelAlert+100;
            UIViewController *vc=[UIViewController new]; vc.view.backgroundColor=UIColor.clearColor; w.rootViewController=vc;
            UIButton *b=[UIButton buttonWithType:UIButtonTypeSystem];
            b.frame=CGRectMake(8,220,96,38); b.backgroundColor=[[UIColor blackColor]colorWithAlphaComponent:0.72];
            [b setTitle:@"HM探针3 导出" forState:UIControlStateNormal]; b.titleLabel.font=[UIFont systemFontOfSize:12];
            [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; b.layer.cornerRadius=8;
            [b addGestureRecognizer:[[UIPanGestureRecognizer alloc]initWithTarget:b action:@selector(hm_drag:)]];
            [b addTarget:HMProbeStore.class action:@selector(share) forControlEvents:UIControlEventTouchUpInside];
            UIButton *m=[UIButton buttonWithType:UIButtonTypeSystem];
            m.frame=CGRectMake(8,264,96,34); m.backgroundColor=[[UIColor darkGrayColor]colorWithAlphaComponent:0.72];
            [m setTitle:@"打标记" forState:UIControlStateNormal]; m.titleLabel.font=[UIFont systemFontOfSize:12];
            [m setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; m.layer.cornerRadius=8;
            [m addGestureRecognizer:[[UIPanGestureRecognizer alloc]initWithTarget:m action:@selector(hm_drag:)]];
            [m addTarget:HMProbeStore.class action:@selector(mark) forControlEvents:UIControlEventTouchUpInside];
            [vc.view addSubview:b]; [vc.view addSubview:m];
            w.hidden=NO; g_win=w;
        } @finally { t_suppress--; }
    });
}
@implementation UIButton (HMDrag)
- (void)hm_drag:(UIPanGestureRecognizer*)g {
    UIView *sup=self.superview; CGPoint t=[g translationInView:sup];
    CGPoint c=self.center; c.x+=t.x;c.y+=t.y; self.center=c; [g setTranslation:CGPointZero inView:sup];
}
@end

// ============================== 入口 ==============================
__attribute__((constructor)) static void hmprobe_entry(void) {
    @autoreleasepool {
        NSBundle *mb=NSBundle.mainBundle;
        NSString *bid=mb.bundleIdentifier?:@"";
        NSString *bpath=mb.bundlePath?:@"";
        if ([bpath containsString:@".appex/"]) return;
        NSDictionary *info=mb.infoDictionary;
        NSString *dispName=info[@"CFBundleDisplayName"]?:info[@"CFBundleName"]?:@"";
        NSString *bidl=bid.lowercaseString;
        // 门控：App 显示名含“河马”，或 bundleId 含常见拼写；TrollFools 只注入选定 App，此为双保险
        BOOL nameOk=[dispName containsString:@"河马"];
        BOOL bidOk=([bidl containsString:@"hema"]||[bidl containsString:@"hmjc"]||[bidl containsString:@"hemojc"]);
        if (!nameOk && !bidOk) return;

        Dl_info di; memset(&di,0,sizeof(di));
        if (dladdr((void*)&hmprobe_entry,&di)&&di.dli_fbase) {
            const struct mach_header_64 *mh=(const struct mach_header_64*)di.dli_fbase;
            uintptr_t base=(uintptr_t)di.dli_fbase;
            const struct load_command *lc=(const struct load_command*)((const uint8_t*)mh+sizeof(struct mach_header_64));
            for (uint32_t i=0;i<mh->ncmds;i++,lc=(const void*)((const uint8_t*)lc+lc->cmdsize))
                if (lc->cmd==LC_SEGMENT_64) {
                    const struct segment_command_64 *seg=(const struct segment_command_64*)lc;
                    if (strncmp(seg->segname,"__TEXT",6)==0){g_ownLow=base;g_ownHigh=base+seg->vmsize;}
                }
        }

        g_records=[NSMutableArray arrayWithCapacity:kTargetCount];
        g_vendorHit=[NSMutableDictionary dictionary];
        g_events=[NSMutableArray array]; g_evByKey=[NSMutableDictionary dictionary];
        g_markers=[NSMutableArray array];
        g_deepDone=[NSMutableSet set]; g_deepInv=[NSMutableArray array];
        g_udSeen=[NSMutableDictionary dictionary]; g_kcSeen=[NSMutableDictionary dictionary];
        g_fileSeen=[NSMutableDictionary dictionary]; g_cFileSeen=[NSMutableDictionary dictionary];
        snprintf(g_homeC,sizeof(g_homeC),"%s",[NSHomeDirectory() UTF8String]);
        for (int i=0;i<kTargetCount;i++) {
            NSMutableDictionary *r=[NSMutableDictionary dictionary];
            r[@"clsName"]=[NSString stringWithUTF8String:kTargets[i].cls];
            r[@"selName"]=[NSString stringWithUTF8String:kTargets[i].sel];
            r[@"preferClass"]=@(kTargets[i].preferClass);
            r[@"group"]=[NSString stringWithUTF8String:kTargets[i].group];
            r[@"hits"]=@0; r[@"sampled"]=@NO; r[@"status"]=@"待安装";
            [g_records addObject:r];
            g_hookSlots[i].targetSel = sel_registerName(kTargets[i].sel);
            atomic_store_explicit(&g_hookSlots[i].aliasSel, NULL, memory_order_relaxed);
            atomic_store_explicit(&g_hookSlots[i].installedClass, NULL, memory_order_relaxed);
        }
        atomic_store_explicit(&g_slotCount, kTargetCount, memory_order_release);
        // v3：constructor(pre-main) 同步装一轮；所有类簇/深度 Hook 共享一次类列表扫描。
        hm_runtimeScanOnce();
        hm_pass();
        // 晚加载的类/镜像（Flutter、广告 SDK 等）仍由主队列重试覆盖 30s
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.3*NSEC_PER_SEC)),dispatch_get_main_queue(),^{hm_deepScanPass();});
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(2.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{hm_census();});
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(8.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{hm_census();});
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{hm_float();});
    }
}
