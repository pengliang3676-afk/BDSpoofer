//
//  BDDiagCoh.m —— 百度极速版「三层设备身份对质」只读探针
//
//  目的：卐解(BDSpoofer)伪装后，验证百度实际读到的三层是否为同一台设备：
//    A. 公共层：UIDevice / NSProcessInfo / sysctl(hw.machine,hw.memsize) / UIScreen / IDFV
//    B. 百度内部层：13+ 个内部接口（Hook 记录 + 报告时主动直采一次，拿到强类型值）
//    C. UA/网络层：NSMutableURLRequest 与 WKWebView 实际携带的 User-Agent
//  报告开头给出【对质表】，每个维度自动判 MATCH / MISMATCH / 数据不足。
//
//  安全原则（沿用 BDDiag2 v4 已复审框架）：
//   1. 运行时确认类/selector 与真实签名，白名单 ABI 才 Hook，绝不猜 ABI；
//   2. 所有 Hook 先调原实现、只做安全摘要、原值原样返回；
//   3. 对象返回仅支持 0~2 个对象参数；CGSize 只读 trampoline 仅用于 getScreenResolution；
//      新增 void 返回 trampoline 仅用于抓取 UA 设置（1~2 个对象参数）；
//   4. 每方法只采 1 次样本+短栈，UA 去重后最多 8 条，之后仅计数；
//   5. _Thread_local 递归抑制；类晚加载则 0.5s 重试、最多 30s；
//   6. 手机号/UUID/token 脱敏，IDFV 仅留前 8 位用于一致性比对；
//   7. 全程只读，不改任何返回值、不写 App 数据。
//
//  注入顺序：TrollFools 先注入 BDSpoofer（伪装），再注入本探针（观测最终值）。
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
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <ctype.h>

// ============================== 对象返回目标（内部层 Hook） ==============================
typedef struct { const char *cls; const char *sel; int preferClass; const char *group; } BDTarget;
static const BDTarget kTargets[] = {
    {"BaiduMobStatDeviceInfo", "getScreenResolution",                         1, "内部-屏幕指纹"},
    {"UIDevice",               "bp_resolution",                               1, "内部-屏幕指纹"},
    {"BDPTalosBaseInfo",       "platformInfo",                                1, "内部-Talos"},
    {"BDPTalosBaseInfo",       "getBasicPlatformInfo",                        1, "内部-Talos"},
    {"BBASMPlugin",            "getConstantSystemInfoDictionary",             1, "内部-小程序"},
    {"BBASMPlugin",            "getSystemInfoWithAppID:cardID:",              1, "内部-小程序"},
    {"BDPDeviceUtility",       "getIDFV",                                     1, "内部-设备主SDK"},
    {"BDPDeviceUtility",       "getSystemVersion",                            1, "内部-设备主SDK"},
    {"BDPDeviceInfoFactory",   "createDeviceInfosWithOptions:privacyStatus:", 1, "内部-设备主SDK"},
    {"BDPDeviceInfoMappingManager","deviceInfosWithOptions:",                 0, "内部-设备主SDK"},
    {"BDPUserAgent",           "composeUserAgentParameterWithOrigin:shouldEncodeURI:", 0, "内部-UA"},
    {"BDPUserAgent",           "useagent_getDeviceInfo",                      0, "内部-UA"},
    {"NetworkInfoManager",     "networkInfo",                                 0, "内部-网络"},
    {"DMDeviceInfoWrapper",    "systemVersion",                               1, "内部-版本"},
    {"BDPDynamicParameters",   "init",                                        0, "内部-上报参数"},
    {"BPushRequest",           "generalParamString",                          0, "内部-Push"},
    {"BPushBindRequest",       "HttpBody",                                    0, "内部-Push"},
};
static const int kTargetCount = sizeof(kTargets)/sizeof(kTargets[0]);

// ============================== void 返回目标（UA 网络层抓取） ==============================
typedef struct { const char *cls; const char *sel; int argc; const char *group; } BDVoidTarget;
static const BDVoidTarget kVoidTargets[] = {
    {"NSMutableURLRequest", "setValue:forHTTPHeaderField:", 2, "UA网络层"},
    {"WKWebView",           "setCustomUserAgent:",          1, "UA网络层"},
};
static const int kVoidTargetCount = sizeof(kVoidTargets)/sizeof(kVoidTargets[0]);

// ============================== 全局状态 ==============================
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;
static NSMutableArray<NSMutableDictionary *> *g_records = nil;
static NSMutableDictionary<NSString *, NSMutableArray *> *g_bySel = nil;
static _Thread_local int t_suppress = 0;
static uintptr_t g_ownLow = 0, g_ownHigh = 0;
static BOOL bdd_inSelf(uintptr_t p){ return p>=g_ownLow && p<g_ownHigh; }

static char bdd_typeKind(const char *enc) {
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
static void bdd_ensureRx(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_phoneRx = [NSRegularExpression regularExpressionWithPattern:@"1[3-9]\\d{9}" options:0 error:nil];
        g_uuidRx  = [NSRegularExpression regularExpressionWithPattern:@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" options:0 error:nil];
        g_tokenRx = [NSRegularExpression regularExpressionWithPattern:@"[A-Za-z0-9_\\-]{24,}" options:0 error:nil];
    });
}
static BOOL bdd_sensitiveKey(NSString *k) {
    NSString *x = k.lowercaseString;
    NSString *compact = [[[x stringByReplacingOccurrencesOfString:@"_" withString:@""]
                            stringByReplacingOccurrencesOfString:@"-" withString:@""]
                            stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSArray *bad = @[@"cookie",@"token",@"session",@"pass",@"pwd",@"secret",
                     @"account",@"idfa",@"idfv",@"auth",@"ticket"];
    for (NSString *b in bad) if ([x containsString:b]) return YES;
    NSArray *phoneKeys = @[@"phonenumber", @"mobilephonenumber", @"mobilenumber",
                           @"telephonenumber", @"telnumber", @"msisdn"];
    for (NSString *b in phoneKeys) if ([compact containsString:b]) return YES;
    if ([compact isEqualToString:@"phone"] || [compact isEqualToString:@"mobile"] ||
        [compact isEqualToString:@"telephone"] || [compact isEqualToString:@"tel"]) return YES;
    return NO;
}
static NSString *bdd_maskString(NSString *s) {
    if (!s) return nil;
    bdd_ensureRx();
    NSString *out = [g_phoneRx stringByReplacingMatchesInString:s options:0 range:NSMakeRange(0,s.length) withTemplate:@"1XX****XXXX"];
    out = [g_uuidRx stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0,out.length) withTemplate:@"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"];
    out = [g_tokenRx stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0,out.length) withTemplate:@"token***"];
    if (out.length > 300) out = [[out substringToIndex:300] stringByAppendingString:@"…(截断)"];
    return out;
}
// 对质表用：仅保留前 8 位用于判断是否同一 ID
static NSString *bdd_idPrefix(id v) {
    if (!v) return nil;
    NSString *s = nil;
    if ([v isKindOfClass:NSString.class]) s = (NSString *)v;
    else if ([v isKindOfClass:NSUUID.class]) s = ((NSUUID *)v).UUIDString;
    else return nil;
    s = [s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    if (s.length < 8) return s.length ? [s substringToIndex:s.length] : nil;
    return [[s substringToIndex:8] stringByAppendingString:@"…(脱敏)"];
}

// ============================== 安全摘要 ==============================
static NSString *bdd_summary(id v, int depth, NSString *keyHint) {
    if (!v) return @"nil";
    Class c = [v class];
    if ([v isKindOfClass:NSString.class]) {
        if (keyHint && bdd_sensitiveKey(keyHint)) return [NSString stringWithFormat:@"<NSString len=%lu 已脱敏>",(unsigned long)((NSString*)v).length];
        return [NSString stringWithFormat:@"NSString: %@", bdd_maskString((NSString*)v)];
    }
    if ([v isKindOfClass:NSNumber.class]) return [NSString stringWithFormat:@"%@: %@", NSStringFromClass(c), v];
    if ([v isKindOfClass:NSUUID.class])
        return [NSString stringWithFormat:@"NSUUID: %@", bdd_maskString([(NSUUID*)v UUIDString])];
    if ([v isKindOfClass:NSDate.class]) return [NSString stringWithFormat:@"NSDate: %@", v];
    if ([v isKindOfClass:NSData.class]) return [NSString stringWithFormat:@"<NSData len=%lu>",(unsigned long)((NSData*)v).length];
    if ([v isKindOfClass:NSURL.class]) return [NSString stringWithFormat:@"NSURL(scheme/host): %@://%@", ((NSURL*)v).scheme?:@"", ((NSURL*)v).host?:@""];
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
            if (bdd_sensitiveKey(ks)) vs = [NSString stringWithFormat:@"<%@ 已脱敏>", NSStringFromClass([val class])];
            else if ([val isKindOfClass:NSDictionary.class] || [val isKindOfClass:NSArray.class]) vs = bdd_summary(val, depth+1, ks);
            else if ([val isKindOfClass:NSString.class]) vs = [NSString stringWithFormat:@"NSString(值=%@)", bdd_maskString((NSString*)val)];
            else if ([val isKindOfClass:NSNumber.class]) vs = [NSString stringWithFormat:@"%@(值=%@)", NSStringFromClass([val class]), val];
            else vs = NSStringFromClass([val class]) ?: @"?";
            [parts addObject:[NSString stringWithFormat:@"%@=%@", ks, vs]];
        }
        return [NSString stringWithFormat:@"{NSDictionary count=%lu keys: [%@]}",(unsigned long)snap.count,[parts componentsJoinedByString:@", "]];
    }
    return [NSString stringWithFormat:@"<%@>", NSStringFromClass(c)];
}

static NSString *bdd_shortStack(void) {
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

// ============================== 记录查找 ==============================
static NSMutableDictionary *bdd_findRec(id self, SEL _cmd) {
    NSString *selName = NSStringFromSelector(_cmd);
    NSMutableArray *cands;
    os_unfair_lock_lock(&g_lock);
    cands = [g_bySel[selName] copy];
    os_unfair_lock_unlock(&g_lock);
    if (cands.count == 1) return cands[0];
    Class selfCls = object_getClass(self);
    for (NSMutableDictionary *r in cands) {
        Class installed = r[@"installedClass"];
        if (installed && (installed == selfCls || [self isKindOfClass:installed])) return r;
    }
    return cands.firstObject;
}

// ============================== 对象 Hook 观测 ==============================
static void bdd_observe(NSMutableDictionary *rec, id ret, NSArray *args) {
    if (!rec || t_suppress) return;
    BOOL needSample = NO;
    os_unfair_lock_lock(&g_lock);
    rec[@"hits"] = @([rec[@"hits"] unsignedLongValue] + 1);
    if (![rec[@"sampled"] boolValue]) { rec[@"sampled"] = @YES; needSample = YES; }
    os_unfair_lock_unlock(&g_lock);
    if (!needSample) return;
    NSString *retSum=nil, *stack=nil; NSMutableArray *argSum=nil;
    t_suppress++;
    @try {
        retSum = bdd_summary(ret, 0, nil);
        argSum = [NSMutableArray array];
        if (args) for (id a in args) [argSum addObject:bdd_summary(a, 0, nil)];
        stack = bdd_shortStack();
    } @catch (NSException *e) {
        os_unfair_lock_lock(&g_lock); rec[@"sampled"]=@NO; os_unfair_lock_unlock(&g_lock);
        retSum = [NSString stringWithFormat:@"<采样异常: %@>", e.name];
    } @finally { t_suppress--; }
    os_unfair_lock_lock(&g_lock);
    rec[@"sampleReturn"] = retSum ?: @"nil";
    if (argSum.count) rec[@"sampleArgs"] = argSum;
    rec[@"sampleStack"] = stack ?: @"";
    os_unfair_lock_unlock(&g_lock);
}

static id bdd_call0(id s, SEL sel){ return ((id(*)(id,SEL))objc_msgSend)(s,sel); }
static id bdd_call1(id s, SEL sel,id a){ return ((id(*)(id,SEL,id))objc_msgSend)(s,sel,a); }
static id bdd_call2(id s, SEL sel,id a,id b){ return ((id(*)(id,SEL,id,id))objc_msgSend)(s,sel,a,b); }

static id bdd_tramp0(id self, SEL _cmd) {
    NSMutableDictionary *r = bdd_findRec(self,_cmd);
    NSString *an = r[@"aliasSel"]; if (!an) return nil;
    id ret = bdd_call0(self, NSSelectorFromString(an));
    bdd_observe(r, ret, nil);
    return ret;
}
static id bdd_tramp1(id self, SEL _cmd, id a0) {
    NSMutableDictionary *r = bdd_findRec(self,_cmd);
    NSString *an = r[@"aliasSel"]; if (!an) return a0;
    id ret = bdd_call1(self, NSSelectorFromString(an), a0);
    bdd_observe(r, ret, @[a0 ?: [NSNull null]]);
    return ret;
}
static id bdd_tramp2(id self, SEL _cmd, id a0, id a1) {
    NSMutableDictionary *r = bdd_findRec(self,_cmd);
    NSString *an = r[@"aliasSel"]; if (!an) return nil;
    id ret = bdd_call2(self, NSSelectorFromString(an), a0, a1);
    bdd_observe(r, ret, @[a0 ?: [NSNull null], a1 ?: [NSNull null]]);
    return ret;
}

// ============================== CGSize 只读 trampoline ==============================
static void bdd_observeCGSize(NSMutableDictionary *rec, CGSize sz) {
    if (!rec || t_suppress) return;
    BOOL needSample = NO;
    os_unfair_lock_lock(&g_lock);
    rec[@"hits"] = @([rec[@"hits"] unsignedLongValue] + 1);
    if (![rec[@"sampled"] boolValue]) { rec[@"sampled"]=@YES; needSample=YES; }
    os_unfair_lock_unlock(&g_lock);
    if (!needSample) return;
    NSString *sum=nil, *stack=nil;
    t_suppress++;
    @try {
        sum = [NSString stringWithFormat:@"CGSize(只读,原值返回): .width=%.2f .height=%.2f", sz.width, sz.height];
        stack = bdd_shortStack();
    } @catch (NSException *e) {
        os_unfair_lock_lock(&g_lock); rec[@"sampled"]=@NO; os_unfair_lock_unlock(&g_lock);
        sum = [NSString stringWithFormat:@"<CGSize采样异常: %@>", e.name];
    } @finally { t_suppress--; }
    os_unfair_lock_lock(&g_lock);
    rec[@"sampleReturn"] = sum ?: @"nil";
    rec[@"sampleStack"] = stack ?: @"";
    os_unfair_lock_unlock(&g_lock);
}
static CGSize bdd_tramp_cgsize(id self, SEL _cmd) {
    NSMutableDictionary *r = bdd_findRec(self,_cmd);
    NSString *an = r[@"aliasSel"];
    SEL aliasSel = an ? NSSelectorFromString(an) : NULL;
    if (!aliasSel) return CGSizeZero;
    CGSize ret = ((CGSize(*)(id,SEL))objc_msgSend)(self, aliasSel);
    bdd_observeCGSize(r, ret);
    return ret;
}

// ============================== void UA 抓取 trampoline（1/2 个对象参数） ==============================
static void bdd_observeVoid(NSMutableDictionary *rec, NSArray *args, id reqSelf) {
    if (!rec || t_suppress) return;
    NSString *ua = nil, *host = nil;
    t_suppress++;
    @try {
        NSString *selName = rec[@"selName"];
        if ([selName isEqualToString:@"setValue:forHTTPHeaderField:"]) {
            if (args.count < 2) return;
            id nameObj = args[1];
            if (![nameObj isKindOfClass:NSString.class]) return;
            if (![(NSString *)nameObj.lowercaseString isEqualToString:@"user-agent"]) return; // 只看 UA 头
            id v = args[0];
            if ([v isKindOfClass:NSString.class]) ua = (NSString *)v;
            if ([reqSelf respondsToSelector:@selector(URL)]) {
                NSURL *u = ((NSURLRequest *)reqSelf).URL;
                host = u.host;
            }
        } else { // setCustomUserAgent:
            id v = args.firstObject;
            if ([v isKindOfClass:NSString.class]) ua = (NSString *)v;
        }
    } @catch (__unused NSException *e) { ua = nil; }
    @finally { t_suppress--; }
    if (!ua.length) return;

    NSString *line = [NSString stringWithFormat:@"%@ | %@", host ?: @"(WKWebView)", bdd_maskString(ua)];
    os_unfair_lock_lock(&g_lock);
    rec[@"hits"] = @([rec[@"hits"] unsignedLongValue] + 1);
    NSMutableArray *samples = rec[@"uaSamples"];
    if (!samples) { samples = [NSMutableArray array]; rec[@"uaSamples"] = samples; }
    if (![samples containsObject:line] && samples.count < 8) {
        [samples addObject:line];
        if (![rec[@"sampled"] boolValue]) {
            rec[@"sampled"] = @YES;
            rec[@"sampleStack"] = bdd_shortStack() ?: @"";
        }
    }
    os_unfair_lock_unlock(&g_lock);
}
static void bdd_vtramp1(id self, SEL _cmd, id a0) {
    NSMutableDictionary *r = bdd_findRec(self,_cmd);
    NSString *an = r[@"aliasSel"];
    if (an) ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(an), a0);
    bdd_observeVoid(r, @[a0 ?: [NSNull null]], self);
}
static void bdd_vtramp2(id self, SEL _cmd, id a0, id a1) {
    NSMutableDictionary *r = bdd_findRec(self,_cmd);
    NSString *an = r[@"aliasSel"];
    if (an) ((void(*)(id,SEL,id,id))objc_msgSend)(self, NSSelectorFromString(an), a0, a1);
    bdd_observeVoid(r, @[a0 ?: [NSNull null], a1 ?: [NSNull null]], self);
}

// ============================== 对象方法安装 ==============================
static void bdd_tryInstall(NSMutableDictionary *rec, int index) {
    if ([rec[@"status"] isEqualToString:@"hooked"] || [rec[@"final"] boolValue]) return;
    NSString *clsName = rec[@"clsName"];
    NSString *selName = rec[@"selName"];
    Class appCls = NSClassFromString(clsName);
    if (!appCls) { rec[@"status"] = @"未找到（类尚未加载）"; return; }
    BOOL preferClass = [rec[@"preferClass"] boolValue];
    Class meta = object_getClass(appCls);
    Class hookCls = preferClass ? meta : appCls;
    Method m = class_getInstanceMethod(hookCls, NSSelectorFromString(selName));
    BOOL isClass = preferClass;
    if (!m) { hookCls = preferClass ? appCls : meta; m = class_getInstanceMethod(hookCls, NSSelectorFromString(selName)); isClass = !preferClass; }
    if (!m) { rec[@"status"] = @"未找到（selector 不存在）"; return; }
    if ([selName hasPrefix:@"init"]) {
        rec[@"kind"] = isClass ? @"+(类方法)" : @"-(实例方法)";
        rec[@"encoding"] = [NSString stringWithUTF8String:method_getTypeEncoding(m) ?: "?"];
        rec[@"status"] = @"未Hook(init方法族)"; rec[@"final"]=@YES; return;
    }
    const char *types = method_getTypeEncoding(m) ?: "?";
    char rbuf[8]={0}; method_getReturnType(m, rbuf, sizeof(rbuf));
    char retKind = bdd_typeKind(rbuf);
    unsigned narg = method_getNumberOfArguments(m);
    int userArgc = (int)narg - 2;
    NSMutableArray *argKinds = [NSMutableArray array];
    BOOL argsSafe = YES;
    for (unsigned i=2; i<narg; i++) {
        char abuf[16]={0}; method_getArgumentType(m, i, abuf, sizeof(abuf));
        char k = bdd_typeKind(abuf);
        [argKinds addObject:[NSString stringWithFormat:@"%c",k]];
        if (!(k=='@' || k=='#')) argsSafe = NO;
    }
    rec[@"kind"] = isClass ? @"+(类方法)" : @"-(实例方法)";
    rec[@"encoding"] = [NSString stringWithUTF8String:types];
    rec[@"retType"] = [NSString stringWithFormat:@"%c",retKind];
    rec[@"argc"] = @(userArgc);
    rec[@"argTypes"] = argKinds;

    if (retKind=='{' && userArgc==0 && strncmp(types,"{CGSize",7)==0) {
        IMP tramp = (IMP)bdd_tramp_cgsize;
        NSString *alias = [NSString stringWithFormat:@"bddcoh_orig_%d", index];
        SEL aliasSel = sel_registerName(alias.UTF8String);
        SEL targetSel = NSSelectorFromString(selName);
        IMP origImp = method_getImplementation(m);
        BOOL addAlias = class_addMethod(hookCls, aliasSel, tramp, types);
        class_addMethod(hookCls, targetSel, origImp, types);
        Method targetM = class_getInstanceMethod(hookCls, targetSel);
        Method aliasM  = class_getInstanceMethod(hookCls, aliasSel);
        if (!addAlias || !targetM || !aliasM) { rec[@"status"]=@"未Hook(CGSize swizzle失败)"; rec[@"final"]=@YES; return; }
        os_unfair_lock_lock(&g_lock);
        rec[@"aliasSel"]=alias; rec[@"installedClass"]=hookCls;
        os_unfair_lock_unlock(&g_lock);
        method_exchangeImplementations(targetM, aliasM);
        rec[@"status"]=@"已Hook(CGSize只读)"; rec[@"final"]=@YES; return;
    }
    if (retKind != '@') { rec[@"status"]=[NSString stringWithFormat:@"未Hook(返回类型%c非对象)",retKind]; rec[@"final"]=@YES; return; }
    if (userArgc < 0 || userArgc > 2) { rec[@"status"]=[NSString stringWithFormat:@"未Hook(参数数%d超出0~2)",userArgc]; rec[@"final"]=@YES; return; }
    if (!argsSafe) { rec[@"status"]=[NSString stringWithFormat:@"未Hook(含非对象参数:%@)",argKinds]; rec[@"final"]=@YES; return; }
    IMP tramp = (userArgc==0)?(IMP)bdd_tramp0 : (userArgc==1)?(IMP)bdd_tramp1 : (IMP)bdd_tramp2;
    NSString *alias = [NSString stringWithFormat:@"bddcoh_orig_%d%@", index,
                       userArgc==0?@"":(userArgc==1?@":":@"::")];
    SEL aliasSel = sel_registerName(alias.UTF8String);
    SEL targetSel = NSSelectorFromString(selName);
    IMP origImp = method_getImplementation(m);
    BOOL addAlias = class_addMethod(hookCls, aliasSel, tramp, types);
    class_addMethod(hookCls, targetSel, origImp, types);
    Method targetM = class_getInstanceMethod(hookCls, targetSel);
    Method aliasM  = class_getInstanceMethod(hookCls, aliasSel);
    if (!addAlias || !targetM || !aliasM) { rec[@"status"]=@"未Hook(swizzle失败)"; rec[@"final"]=@YES; return; }
    os_unfair_lock_lock(&g_lock);
    rec[@"aliasSel"] = alias; rec[@"installedClass"] = hookCls;
    os_unfair_lock_unlock(&g_lock);
    method_exchangeImplementations(targetM, aliasM);
    rec[@"status"] = @"已Hook"; rec[@"final"] = @YES;
}

// ============================== void 方法安装 ==============================
static void bdd_tryInstallVoid(NSMutableDictionary *rec, int expectArgc) {
    if ([rec[@"status"] isEqualToString:@"hooked"] || [rec[@"final"] boolValue]) return;
    Class hookCls = NSClassFromString(rec[@"clsName"]);
    if (!hookCls) { rec[@"status"] = @"未找到（类尚未加载）"; return; }
    SEL targetSel = NSSelectorFromString(rec[@"selName"]);
    Method m = class_getInstanceMethod(hookCls, targetSel); // 这两个都是实例方法
    if (!m) { rec[@"status"] = @"未找到（selector 不存在）"; return; }
    const char *types = method_getTypeEncoding(m) ?: "?";
    char rbuf[8]={0}; method_getReturnType(m, rbuf, sizeof(rbuf));
    if (bdd_typeKind(rbuf) != 'v') { rec[@"status"]=[NSString stringWithFormat:@"未Hook(返回非void:%s)",rbuf]; rec[@"final"]=@YES; return; }
    unsigned narg = method_getNumberOfArguments(m);
    int userArgc = (int)narg - 2;
    if (userArgc != expectArgc) { rec[@"status"]=[NSString stringWithFormat:@"未Hook(参数数%d≠%d)",userArgc,expectArgc]; rec[@"final"]=@YES; return; }
    for (unsigned i=2; i<narg; i++) {
        char abuf[16]={0}; method_getArgumentType(m,i,abuf,sizeof(abuf));
        char k=bdd_typeKind(abuf);
        if (k!='@' && k!='#') { rec[@"status"]=[NSString stringWithFormat:@"未Hook(参数%u非对象:%c)",i,k]; rec[@"final"]=@YES; return; }
    }
    rec[@"kind"]=@"-(实例方法)"; rec[@"encoding"]=[NSString stringWithUTF8String:types];
    rec[@"retType"]=@"v"; rec[@"argc"]=@(userArgc);
    IMP tramp = (userArgc==1)?(IMP)bdd_vtramp1 : (IMP)bdd_vtramp2;
    NSString *alias = [NSString stringWithFormat:@"bddcoh_void_%d%@", (int)[rec[@"index"] intValue],
                       userArgc==1?@":":@"::"];
    SEL aliasSel = sel_registerName(alias.UTF8String);
    IMP origImp = method_getImplementation(m);
    BOOL addAlias = class_addMethod(hookCls, aliasSel, tramp, types);
    class_addMethod(hookCls, targetSel, origImp, types);
    Method targetM = class_getInstanceMethod(hookCls, targetSel);
    Method aliasM  = class_getInstanceMethod(hookCls, aliasSel);
    if (!addAlias || !targetM || !aliasM) { rec[@"status"]=@"未Hook(swizzle失败)"; rec[@"final"]=@YES; return; }
    os_unfair_lock_lock(&g_lock);
    rec[@"aliasSel"]=alias; rec[@"installedClass"]=hookCls;
    os_unfair_lock_unlock(&g_lock);
    method_exchangeImplementations(targetM, aliasM);
    rec[@"status"]=@"已Hook(void-UA只读)"; rec[@"final"]=@YES;
}

static int g_tries = 0;
static void bdd_pass(void) {
    BOOL allDone = YES;
    for (int i=0;i<(int)g_records.count;i++) {
        NSMutableDictionary *r;
        os_unfair_lock_lock(&g_lock); r = g_records[i]; os_unfair_lock_unlock(&g_lock);
        if ([r[@"pipe"] isEqualToString:@"void"]) bdd_tryInstallVoid(r, [r[@"expectArgc"] intValue]);
        else bdd_tryInstall(r, i);
        if (![r[@"final"] boolValue]) allDone = NO;
    }
    g_tries++;
    if (!allDone && g_tries < 60) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ bdd_pass(); });
    } else {
        os_unfair_lock_lock(&g_lock);
        for (NSMutableDictionary *r in g_records)
            if (![r[@"final"] boolValue]) { r[@"status"]=@"未找到(30s内未加载)"; r[@"final"]=@YES; }
        os_unfair_lock_unlock(&g_lock);
    }
}

// ============================== 公共层直采 ==============================
static NSString *bdd_sysctlStr(const char *name) {
    size_t len=0;
    if (sysctlbyname(name,NULL,&len,NULL,0)!=0 || !len) return nil;
    char *buf=(char*)malloc(len);
    if (sysctlbyname(name,buf,&len,NULL,0)!=0) { free(buf); return nil; }
    NSString *s=[NSString stringWithUTF8String:buf]; free(buf); return s;
}
static uint64_t bdd_sysctlU64(const char *name) {
    uint64_t v=0; size_t len=sizeof(v);
    if (sysctlbyname(name,&v,&len,NULL,0)!=0) return 0; return v;
}
static NSDictionary *bdd_publicSnapshot(void) {
    NSMutableDictionary *p=[NSMutableDictionary dictionary];
    t_suppress++;
    @try {
        UIDevice *d=UIDevice.currentDevice;
        p[@"UIDevice.model"]=d.model ?: @"";
        p[@"UIDevice.localizedModel"]=d.localizedModel ?: @"";
        p[@"UIDevice.name"]=bdd_maskString(d.name ?: @"");
        p[@"UIDevice.systemName"]=d.systemName ?: @"";
        p[@"UIDevice.systemVersion"]=d.systemVersion ?: @"";
        p[@"IDFV前缀"]=bdd_idPrefix(d.identifierForVendor) ?: @"nil";
        UIScreen *s=UIScreen.mainScreen;
        CGRect b=s.bounds, nb=s.nativeBounds;
        p[@"UIScreen.bounds(点)"]=NSStringFromCGRect(b);
        p[@"UIScreen.scale"]=@(s.scale);
        p[@"UIScreen.nativeBounds(像素)"]=NSStringFromCGRect(nb);
        p[@"UIScreen.nativeScale"]=@(s.nativeScale);
        NSProcessInfo *pi=NSProcessInfo.processInfo;
        NSOperatingSystemVersion ov=pi.operatingSystemVersion;
        p[@"NSProcessInfo.OS"]=[NSString stringWithFormat:@"%zd.%zd.%zd",ov.majorVersion,ov.minorVersion,ov.patchVersion];
        p[@"NSProcessInfo.OSString"]=bdd_maskString(pi.operatingSystemVersionString ?: @"");
        p[@"sysctl hw.machine"]=bdd_sysctlStr("hw.machine") ?: @"读取失败";
        p[@"sysctl hw.model"]=bdd_sysctlStr("hw.model") ?: @"读取失败";
        uint64_t mem=bdd_sysctlU64("hw.memsize");
        p[@"sysctl hw.memsize(GB)"]=mem?[NSString stringWithFormat:@"%.2f",mem/1024.0/1024.0/1024.0]:@"读取失败";
        struct utsname un; memset(&un,0,sizeof(un));
        if (uname(&un)==0) p[@"uname.machine"]=[NSString stringWithUTF8String:un.machine] ?: @"";
        NSError *fe=nil;
        NSDictionary *fa=[NSFileManager.defaultManager attributesOfFileSystemForPath:NSHomeDirectory() error:&fe];
        if (fa) {
            double total=[fa[NSFileSystemSize] unsignedLongLongValue]/1.0/1024/1024/1024;
            double free=[fa[NSFileSystemFreeSize] unsignedLongLongValue]/1.0/1024/1024/1024;
            p[@"文件系统 总/剩(GB)"]=[NSString stringWithFormat:@"%.2f / %.2f",total,free];
        } else p[@"文件系统"]=[NSString stringWithFormat:@"读取失败:%@",fe.domain];
        NSBundle *mb=NSBundle.mainBundle;
        p[@"BundleID"]=mb.bundleIdentifier ?: @"";
        p[@"App版本"]=[mb.infoDictionary[@"CFBundleShortVersionString"] description] ?: @"";
    } @finally { t_suppress--; }
    return p;
}

// 主动调用一个类方法（走完整 swizzle 链，读到的是百度最终拿到的值）
static id bdd_directClassObj(const char *cls, const char *selName) {
    Class c=NSClassFromString([NSString stringWithUTF8String:cls]);
    SEL sel=NSSelectorFromString([NSString stringWithUTF8String:selName]);
    if (!c || ![c respondsToSelector:sel]) return nil;
    t_suppress++;
    id v=nil;
    @try { v=((id(*)(id,SEL))objc_msgSend)(c,sel); } @catch (__unused NSException *e) { v=nil; }
    @finally { t_suppress--; }
    return v;
}
static CGSize bdd_directClassCGSize(const char *cls, const char *selName, BOOL *ok) {
    *ok=NO; CGSize z=CGSizeZero;
    Class c=NSClassFromString([NSString stringWithUTF8String:cls]);
    SEL sel=NSSelectorFromString([NSString stringWithUTF8String:selName]);
    if (!c || ![c respondsToSelector:sel]) return z;
    t_suppress++;
    @try { z=((CGSize(*)(id,SEL))objc_msgSend)(c,sel); *ok=YES; } @catch (__unused NSException *e) {}
    @finally { t_suppress--; }
    return z;
}

// ============================== 归一化与对质 ==============================
static NSString *bdd_firstMatch(NSString *s, NSString *pat) {
    if (![s isKindOfClass:NSString.class] || !s.length) return nil;
    static NSMutableDictionary *cache=nil; static dispatch_once_t once; static os_unfair_lock rl;
    dispatch_once(&once, ^{ cache=[NSMutableDictionary dictionary]; rl=OS_UNFAIR_LOCK_INIT; });
    NSRegularExpression *rx;
    os_unfair_lock_lock(&rl); rx=cache[pat]; if(!rx){ rx=[NSRegularExpression regularExpressionWithPattern:pat options:0 error:nil]; cache[pat]=rx; } os_unfair_lock_unlock(&rl);
    NSTextCheckingResult *m=[rx firstMatchInString:s options:0 range:NSMakeRange(0,s.length)];
    return m?[s substringWithRange:m.range]:nil;
}
static NSString *bdd_normMachine(id v) {
    NSString *s=[v isKindOfClass:NSString.class]?v:([v respondsToSelector:@selector(stringValue)]?[v stringValue]:nil);
    NSString *t=bdd_firstMatch(s, @"(?i)iphone\\s*(\\d+,\\d+)");
    if (!t) return nil;
    return [[t stringByReplacingOccurrencesOfString:@" " withString:@""] uppercaseString];
}
static NSString *bdd_normiOS(id v) {
    NSString *s=[v isKindOfClass:NSString.class]?v:([v respondsToSelector:@selector(stringValue)]?[v stringValue]:nil);
    // 只比 主版本.次版本，忽略补丁号差异（26.6 与 26.6.0 视为一致），_ 与 . 都做分隔符
    NSString *t=bdd_firstMatch(s, @"(\\d+)[_\\.](\\d+)");
    if (!t) return nil;
    NSArray *parts=[t componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"_."]];
    if (parts.count<2) return nil;
    return [NSString stringWithFormat:@"%@.%@",parts[0],parts[1]];
}
// 多个 (label,value) 对，按归一化值分组判一致
static NSString *bdd_verdict(NSArray<NSArray *> *pairs, NSString *(^norm)(id)) {
    NSMutableDictionary<NSString *,NSMutableArray<NSString *>*> *groups=[NSMutableDictionary dictionary];
    for (NSArray *pair in pairs) {
        NSString *label=pair[0]; id raw=pair[1];
        NSString *nv=norm?norm(raw):([raw isKindOfClass:NSString.class]?raw:[raw description]);
        if (![nv isKindOfClass:NSString.class] || !nv.length) continue;
        NSMutableArray *labs=groups[nv]; if(!labs){labs=[NSMutableArray array];groups[nv]=labs;}
        [labs addObject:label];
    }
    if (!groups.count) return @"数据不足（本次没有任何出口读数，多操作一会儿再导出）";
    if (groups.count==1) { NSString *v=groups.allKeys.firstObject; return [NSString stringWithFormat:@"MATCH 全部一致 → %@",v]; }
    NSMutableArray *parts=[NSMutableArray array];
    [groups enumerateKeysAndObjectsUsingBlock:^(NSString *v, NSMutableArray *labs, BOOL *stop){
        [parts addObject:[NSString stringWithFormat:@"%@=[%@]",v,[labs componentsJoinedByString:@","]]];
    }];
    return [NSString stringWithFormat:@"MISMATCH 存在矛盾：%@",[parts componentsJoinedByString:@" ｜ "]];
}

static NSString *bdd_buildContradiction(NSDictionary *pub) {
    NSMutableString *s=[NSMutableString string];
    [s appendString:@"================ 三层身份对质表 ================\n"];

    // 直采内部对象
    id talos = bdd_directClassObj("BDPTalosBaseInfo","platformInfo");
    id bbasmc = bdd_directClassObj("BBASMPlugin","getConstantSystemInfoDictionary");
    id dmSys = bdd_directClassObj("DMDeviceInfoWrapper","systemVersion");
    id bdpSys = bdd_directClassObj("BDPDeviceUtility","getSystemVersion");
    id bdpIdfv = bdd_directClassObj("BDPDeviceUtility","getIDFV");
    id bpRes = bdd_directClassObj("UIDevice","bp_resolution");
    BOOL cgOK=NO; CGSize cg=bdd_directClassCGSize("BaiduMobStatDeviceInfo","getScreenResolution",&cgOK);
    NSDictionary *talosD=[talos isKindOfClass:NSDictionary.class]?talos:nil;
    NSDictionary *bbasmD=[bbasmc isKindOfClass:NSDictionary.class]?bbasmc:nil;
    NSDictionary *scr=talosD[@"screenInfo"]; if(![scr isKindOfClass:NSDictionary.class]) scr=nil;

    // 1) 系统版本
    NSMutableArray *iosPairs=[NSMutableArray array];
    [iosPairs addObject:@[@"公共-UIDevice", pub[@"UIDevice.systemVersion"]]];
    [iosPairs addObject:@[@"公共-NSProcessInfo", pub[@"NSProcessInfo.OS"]]];
    if (dmSys) [iosPairs addObject:@[@"内部-DMDeviceInfoWrapper", dmSys]];
    if (bdpSys) [iosPairs addObject:@[@"内部-BDPDeviceUtility", bdpSys]];
    if (talosD[@"osVersion"]) [iosPairs addObject:@[@"内部-Talos.osVersion", talosD[@"osVersion"]]];
    if (bbasmD[@"system"]) [iosPairs addObject:@[@"内部-BBASM.system", bbasmD[@"system"]]];
    [s appendFormat:@"【系统版本】%@\n", bdd_verdict(iosPairs, ^NSString *(id v){ return bdd_normiOS(v); })];

    // 2) 机型标识
    NSMutableArray *macPairs=[NSMutableArray array];
    [macPairs addObject:@[@"公共-sysctl hw.machine", pub[@"sysctl hw.machine"]]];
    [macPairs addObject:@[@"公共-uname.machine", pub[@"uname.machine"]]];
    if (talosD[@"phoneModel"]) [macPairs addObject:@[@"内部-Talos.phoneModel", talosD[@"phoneModel"]]];
    if (bbasmD[@"model"]) [macPairs addObject:@[@"内部-BBASM.model", bbasmD[@"model"]]];
    [s appendFormat:@"【机型标识】%@\n", bdd_verdict(macPairs, ^NSString *(id v){ return bdd_normMachine(v); })];

    // 3) 物理分辨率（归一为 小边×大边 像素对）
    NSMutableDictionary<NSString*,NSString*> *res=[NSMutableDictionary dictionary];
    CGRect nb=UIScreen.mainScreen.nativeBounds;
    res[@"公共-nativeBounds"]=[NSString stringWithFormat:@"%.0fx%.0f",CGRectGetWidth(nb),CGRectGetHeight(nb)];
    if (cgOK) res[@"内部-getScreenResolution"]=[NSString stringWithFormat:@"%.0fx%.0f",cg.width,cg.height];
    if ([bpRes isKindOfClass:NSString.class]) { // "1334_750" = 高_宽
        NSArray *t=[(NSString*)bpRes componentsSeparatedByString:@"_"];
        if (t.count==2) res[@"内部-bp_resolution"]=[NSString stringWithFormat:@"%@x%@",t[1],t[0]];
    }
    if (scr) {
        double w=[scr[@"width"] doubleValue], h=[scr[@"height"] doubleValue], sc=[scr[@"scale"] doubleValue];
        if (w>0&&h>0&&sc>0) res[@"内部-Talos.screenInfo"]=[NSString stringWithFormat:@"%.0fx%.0f",w*sc,h*sc];
    }
    NSMutableArray *resPairs=[NSMutableArray array];
    [res enumerateKeysAndObjectsUsingBlock:^(NSString *l, NSString *v, BOOL *stop){
        NSArray *t=[v componentsSeparatedByString:@"x"];
        if (t.count==2) {
            double a=[t[0] doubleValue], b=[t[1] doubleValue];
            [resPairs addObject:@[l, [NSString stringWithFormat:@"%.0fx%.0f",MIN(a,b),MAX(a,b)]]];
        }
    }];
    [s appendFormat:@"【物理分辨率(像素,小×大)】%@\n", bdd_verdict(resPairs, nil)];

    // 4) IDFV
    NSMutableArray *idPairs=[NSMutableArray array];
    [idPairs addObject:@[@"公共-identifierForVendor", pub[@"IDFV前缀"]]];
    if (bdpIdfv) [idPairs addObject:@[@"内部-BDPDeviceUtility.getIDFV", bdd_idPrefix(bdpIdfv)]];
    [s appendFormat:@"【IDFV(脱敏前8位)】%@\n", bdd_verdict(idPairs, nil)];

    // 5) UA 里的 iOS 版本（来自实际网络请求）
    NSMutableArray *uaPairs=[NSMutableArray array];
    [uaPairs addObject:@[@"伪装目标系统版本", pub[@"UIDevice.systemVersion"]]];
    for (NSMutableDictionary *r in g_records) {
        NSArray *samples=r[@"uaSamples"];
        for (NSString *line in samples) {
            NSString *uaiOS=bdd_firstMatch(line, @"iPhone OS (\\d+[_\\.]\\d+(?:[_\\.]\\d+)?)");
            if (uaiOS) [uaPairs addObject:@[@"实际请求UA", [uaiOS stringByReplacingOccurrencesOfString:@"_" withString:@"."]]];
        }
    }
    [s appendFormat:@"【UA中的iOS版本】%@\n", bdd_verdict(uaPairs, ^NSString *(id v){ return bdd_normiOS(v); })];

    [s appendString:@"（MATCH=所有出口读数一致；MISMATCH=括号内列出每个值来自哪些出口；数据不足=对应出口本次没被调用，请多操作目标页面后再导出）\n\n"];

    [s appendString:@"---- 内部层主动直采（强类型值，报告时刻）----\n"];
    [s appendFormat:@"Talos.platformInfo: %@\n", talos?bdd_summary(talos,0,nil):@"类/方法未找到"];
    [s appendFormat:@"BBASM.getConstantSystemInfoDictionary: %@\n", bbasmc?bdd_summary(bbasmc,0,nil):@"类/方法未找到"];
    [s appendFormat:@"DMDeviceInfoWrapper.systemVersion: %@\n", dmSys?bdd_summary(dmSys,0,nil):@"未找到"];
    [s appendFormat:@"BDPDeviceUtility.getSystemVersion: %@\n", bdpSys?bdd_summary(bdpSys,0,nil):@"未找到"];
    [s appendFormat:@"BDPDeviceUtility.getIDFV: %@\n", bdpIdfv?bdd_idPrefix(bdpIdfv):@"未找到"];
    [s appendFormat:@"UIDevice.bp_resolution: %@\n", bpRes?bdd_summary(bpRes,0,nil):@"未找到"];
    [s appendFormat:@"BaiduMobStatDeviceInfo.getScreenResolution: %@\n\n", cgOK?[NSString stringWithFormat:@"CGSize %.2f×%.2f",cg.width,cg.height]:@"未找到"];
    return s;
}

// ============================== 报告 / 浮窗 / 分享 ==============================
@interface BDDiagCohStore : NSObject
+ (NSString *)buildReport;
+ (void)share;
@end
@interface BDDiagCohWindow : UIWindow @end
@implementation BDDiagCohWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *h=[super hitTest:point withEvent:event];
    return (h==self || h==self.rootViewController.view)?nil:h;
}
@end
@interface UIButton (BDDiagCohDrag) - (void)bdc_drag:(UIPanGestureRecognizer*)g; @end

@implementation BDDiagCohStore
+ (NSString *)buildReport {
    NSDictionary *pub;
    NSArray *snap;
    t_suppress++;
    @try {
        pub=bdd_publicSnapshot();
        os_unfair_lock_lock(&g_lock);
        snap=[[NSArray alloc] initWithArray:g_records copyItems:YES];
        os_unfair_lock_unlock(&g_lock);
    } @finally { t_suppress--; }

    NSMutableString *s=[NSMutableString string];
    [s appendString:@"BDDiagCoh 百度三层设备身份对质探针报告（只读）\n"];
    [s appendFormat:@"生成时间: %@\n\n",[NSDate date]];
    [s appendString:bdd_buildContradiction(pub)];

    [s appendString:@"================ 公共层直采（报告时刻） ================\n"];
    NSArray *order=@[@"UIDevice.model",@"UIDevice.localizedModel",@"UIDevice.name",@"UIDevice.systemName",
                     @"UIDevice.systemVersion",@"IDFV前缀",@"UIScreen.bounds(点)",@"UIScreen.scale",
                     @"UIScreen.nativeBounds(像素)",@"UIScreen.nativeScale",@"NSProcessInfo.OS",@"NSProcessInfo.OSString",
                     @"sysctl hw.machine",@"sysctl hw.model",@"sysctl hw.memsize(GB)",@"uname.machine",
                     @"文件系统 总/剩(GB)",@"BundleID",@"App版本"];
    for (NSString *k in order) if (pub[k]) [s appendFormat:@"  %@ = %@\n",k,pub[k]];
    [s appendString:@"\n"];

    [s appendString:@"================ UA/网络层实际抓取 ================\n"];
    BOOL anyUA=NO;
    for (NSDictionary *r in snap) {
        NSArray *samples=r[@"uaSamples"];
        if (samples.count) {
            anyUA=YES;
            [s appendFormat:@"[%@] %@ (UA命中%@次)\n",r[@"group"],r[@"selName"],r[@"hits"]?:@0];
            for (NSString *line in samples) [s appendFormat:@"    %@\n",line];
        }
    }
    if (!anyUA) [s appendString:@"本次未抓到任何 User-Agent 设置（请走到加载内容/发起网络请求的页面后再导出）\n"];
    [s appendString:@"\n"];

    [s appendString:@"================ 内部层 Hook 明细 ================\n"];
    [s appendFormat:@"目标方法: %lu 个（对象%lu + void%lu）\n\n",(unsigned long)snap.count,(unsigned long)kTargetCount,(unsigned long)kVoidTargetCount];
    for (NSDictionary *r in snap) {
        [s appendFormat:@"[%@] %@ %@ %@\n", r[@"group"], r[@"kind"]?:@"?", r[@"clsName"], r[@"selName"]];
        [s appendFormat:@"  状态: %@  命中: %@\n", r[@"status"], r[@"hits"]?:@0];
        if (r[@"encoding"])
            [s appendFormat:@"  签名: %@ | 返回=%@ | 参数数=%@ 类型=[%@]\n",
             r[@"encoding"], r[@"retType"], r[@"argc"],
             [(NSArray*)r[@"argTypes"] componentsJoinedByString:@","]];
        if (r[@"sampleArgs"]) [s appendFormat:@"  入参样本: %@\n", r[@"sampleArgs"]];
        if (r[@"sampleReturn"]) [s appendFormat:@"  返回样本: %@\n", r[@"sampleReturn"]];
        if (r[@"uaSamples"]) for (NSString *line in r[@"uaSamples"]) [s appendFormat:@"  UA样本: %@\n",line];
        if ([(NSString*)r[@"sampleStack"] length]) [s appendFormat:@"  短栈:\n%@\n", r[@"sampleStack"]];
        [s appendString:@"\n"];
    }
    return s;
}

+ (void)share {
    t_suppress++;
    NSString *report=nil, *path=nil; NSError *e=nil;
    @try {
        report=[self buildReport];
        UIPasteboard.generalPasteboard.string=report;
        NSString *docs=NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES).firstObject;
        NSDateFormatter *f=[NSDateFormatter new]; f.dateFormat=@"yyyy-MM-dd_HH_mm_ss_ZZZ";
        path=[docs stringByAppendingPathComponent:[NSString stringWithFormat:@"BDDiagCoh_log_%@.txt",[f stringFromDate:[NSDate date]]]];
        [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&e];
    } @finally { t_suppress--; }
    NSURL *url=(e||!path)?nil:[NSURL fileURLWithPath:path];
    dispatch_async(dispatch_get_main_queue(), ^{
        t_suppress++;
        @try {
            UIViewController *vc=nil;
            for (UIScene *sc in UIApplication.sharedApplication.connectedScenes)
                if ([sc isKindOfClass:UIWindowScene.class] && sc.activationState==UISceneActivationStateForegroundActive)
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

static BDDiagCohWindow *g_win=nil;
static int g_floatTries=0;
static void bdd_float(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_win) return;
        UIWindowScene *scene=nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes)
            if ([s isKindOfClass:UIWindowScene.class] && s.activationState==UISceneActivationStateForegroundActive){scene=(UIWindowScene*)s;break;}
        if (!scene){ if(++g_floatTries<=10) dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{bdd_float();}); return;}
        t_suppress++;
        @try {
            BDDiagCohWindow *w=[[BDDiagCohWindow alloc] initWithWindowScene:scene];
            w.frame=UIScreen.mainScreen.bounds; w.windowLevel=UIWindowLevelAlert+100;
            UIViewController *vc=[UIViewController new]; vc.view.backgroundColor=UIColor.clearColor; w.rootViewController=vc;
            UIButton *b=[UIButton buttonWithType:UIButtonTypeSystem];
            b.frame=CGRectMake(8,220,132,42); b.backgroundColor=[[UIColor blackColor]colorWithAlphaComponent:0.72];
            [b setTitle:@"三层对质 导出" forState:UIControlStateNormal]; b.titleLabel.font=[UIFont systemFontOfSize:13];
            [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; b.layer.cornerRadius=8;
            [b addGestureRecognizer:[[UIPanGestureRecognizer alloc]initWithTarget:b action:@selector(bdc_drag:)]];
            [b addTarget:BDDiagCohStore.class action:@selector(share) forControlEvents:UIControlEventTouchUpInside];
            [vc.view addSubview:b]; w.hidden=NO; g_win=w;
        } @finally { t_suppress--; }
    });
}
@implementation UIButton (BDDiagCohDrag)
- (void)bdc_drag:(UIPanGestureRecognizer*)g {
    UIView *sup=self.superview; CGPoint t=[g translationInView:sup];
    CGPoint c=self.center; c.x+=t.x; c.y+=t.y; self.center=c; [g setTranslation:CGPointZero inView:sup];
}
@end

// ============================== 入口 ==============================
__attribute__((constructor)) static void bddcoh_entry(void) {
    @autoreleasepool {
        NSBundle *mb=NSBundle.mainBundle;
        NSString *bid=mb.bundleIdentifier ?: @"";
        NSString *bpath=mb.bundlePath ?: @"";
        if ([bpath containsString:@".appex/"]) return;
        if (![bid isEqualToString:@"com.baidu.BaiduMobileInfo"]) return;

        Dl_info di; memset(&di,0,sizeof(di));
        if (dladdr((void*)&bddcoh_entry,&di) && di.dli_fbase) {
            const struct mach_header_64 *mh=(const struct mach_header_64*)di.dli_fbase;
            uintptr_t base=(uintptr_t)di.dli_fbase;
            const struct load_command *lc=(const struct load_command*)((const uint8_t*)mh+sizeof(struct mach_header_64));
            for (uint32_t i=0;i<mh->ncmds;i++,lc=(const void*)((const uint8_t*)lc+lc->cmdsize))
                if (lc->cmd==LC_SEGMENT_64) {
                    const struct segment_command_64 *seg=(const struct segment_command_64*)lc;
                    if (strncmp(seg->segname,"__TEXT",6)==0){g_ownLow=base;g_ownHigh=base+seg->vmsize;}
                }
        }

        g_records=[NSMutableArray array];
        g_bySel=[NSMutableDictionary dictionary];
        for (int i=0;i<kTargetCount;i++) {
            NSMutableDictionary *r=[NSMutableDictionary dictionary];
            r[@"pipe"]=@"obj"; r[@"index"]=@(i);
            r[@"clsName"]=[NSString stringWithUTF8String:kTargets[i].cls];
            r[@"selName"]=[NSString stringWithUTF8String:kTargets[i].sel];
            r[@"preferClass"]=@(kTargets[i].preferClass);
            r[@"group"]=[NSString stringWithUTF8String:kTargets[i].group];
            r[@"hits"]=@0; r[@"sampled"]=@NO; r[@"status"]=@"待安装";
            [g_records addObject:r];
            NSString *sn=r[@"selName"];
            if(!g_bySel[sn]) g_bySel[sn]=[NSMutableArray array];
            [g_bySel[sn] addObject:r];
        }
        for (int i=0;i<kVoidTargetCount;i++) {
            NSMutableDictionary *r=[NSMutableDictionary dictionary];
            r[@"pipe"]=@"void"; r[@"index"]=@(1000+i); r[@"expectArgc"]=@(kVoidTargets[i].argc);
            r[@"clsName"]=[NSString stringWithUTF8String:kVoidTargets[i].cls];
            r[@"selName"]=[NSString stringWithUTF8String:kVoidTargets[i].sel];
            r[@"preferClass"]=@NO;
            r[@"group"]=[NSString stringWithUTF8String:kVoidTargets[i].group];
            r[@"hits"]=@0; r[@"sampled"]=@NO; r[@"status"]=@"待安装";
            [g_records addObject:r];
            NSString *sn=r[@"selName"];
            if(!g_bySel[sn]) g_bySel[sn]=[NSMutableArray array];
            [g_bySel[sn] addObject:r];
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.1*NSEC_PER_SEC)),dispatch_get_main_queue(),^{bdd_pass();});
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{bdd_float();});
    }
}
