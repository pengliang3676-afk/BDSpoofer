//
//  BDDiag2.m —— 百度极速版 定向设备信息方法 只读探针 v3
//
//  v3 变更（仅两处，其余与 v2 一致、仍全程只读不改值）：
//   a. getScreenResolution 返回 {CGSize=dd}：新增只读 CGSize trampoline，调原实现→记录 .width/.height→原值返回；
//   b. 字典内 NSNumber 字段直接带出真实数值（width/height/scale 等，非敏感），用于确认点/像素单位与一致性。
//  原则（发现方法 → 记录真实签名 → 白名单才 Hook → 调原实现 → 安全摘要返回值 → 原值返回）：
//   1. 运行时确认 类/selector 真实存在，记录 +/-、完整 type encoding、返回类型、参数数量与类型；
//   2. 仅当【返回对象 且 0~2 个对象参数】才安装 Hook；结构体/浮点/指针/复杂参数一律“未 Hook”，绝不按 id 强调；
//   3. 所有 Hook 先调用原实现，再做安全摘要，原值原样返回；init 以原实现返回值为准，不假设 self；
//   4. 每个方法只采 1 次返回样本 + 1 次短栈，之后仅累计次数；
//   5. _Thread_local 递归抑制，摘要/description 触发的二次调用不进入探针；
//   6. 类可能晚加载：每 0.5s 重试、最多 30s；未找到只记录，不影响 App 启动；
//   7. 字典只记“键/值类型/数组数量”，Cookie/Token/账号/手机号脱敏；NSString 前 300 字，NSData 只记长度。
//
//  本文件只读、不改任何返回值。编译：arm64 + arm64e 通用 dylib，TrollFools 注入。
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

// ============================== 目标清单（kind: 1=类方法 0=实例方法；运行时仍会双向确认） ==============================
typedef struct { const char *cls; const char *sel; int preferClass; const char *group; } BDTarget;
static const BDTarget kTargets[] = {
    {"BaiduMobStatDeviceInfo", "getScreenResolution",                              1, "屏幕指纹"},
    {"UIDevice",               "bp_resolution",                                    1, "屏幕指纹"}, // 必须按类方法
    {"BDPTalosBaseInfo",       "platformInfo",                                     1, "屏幕指纹"},
    {"BDPTalosBaseInfo",       "getBasicPlatformInfo",                             1, "屏幕指纹"},
    {"BBASMPlugin",            "getConstantSystemInfoDictionary",                  1, "小程序信息"},
    {"BBASMPlugin",            "getSystemInfoWithAppID:cardID:",                   1, "小程序信息"},
    {"BDPDeviceUtility",       "getIDFV",                                          1, "设备主SDK"},
    {"BDPDeviceUtility",       "getSystemVersion",                                 1, "设备主SDK"},
    {"BDPDeviceInfoFactory",   "createDeviceInfosWithOptions:privacyStatus:",      1, "设备主SDK"},
    {"BDPDeviceInfoMappingManager","deviceInfosWithOptions:",                      0, "设备主SDK"},
    {"BDPUserAgent",           "composeUserAgentParameterWithOrigin:shouldEncodeURI:", 0, "版本UA"},
    {"BDPUserAgent",           "useagent_getDeviceInfo",                           0, "版本UA"},
    {"NetworkInfoManager",     "networkInfo",                                      0, "版本UA"},
    {"DMDeviceInfoWrapper",    "systemVersion",                                    1, "版本UA"},
    {"BDPDynamicParameters",   "init",                                             0, "上报参数"},
    {"BPushRequest",           "generalParamString",                               0, "设备名/推送"},
    {"BPushBindRequest",       "HttpBody",                                         0, "设备名/推送"}, // 保持原始大小写
};
static const int kTargetCount = sizeof(kTargets)/sizeof(kTargets[0]);

// ============================== 全局状态 ==============================
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;
static NSMutableArray<NSMutableDictionary *> *g_records = nil;     // 与 kTargets 顺序一致
static NSMutableDictionary<NSString *, NSMutableArray *> *g_bySel = nil; // selName -> records
static _Thread_local int t_suppress = 0;                          // 当前线程递归抑制（只挡 trampoline 记录，不挡摘要）
static uintptr_t g_ownLow = 0, g_ownHigh = 0;                     // 本 dylib 镜像区间，用于剔除自身栈帧
static BOOL bdd_inSelf(uintptr_t p){ return p>=g_ownLow && p<g_ownHigh; }

// 跳过类型编码里的数字与限定符 r/n/N/o/O/R/V，取真实类型首字符
static char bdd_typeKind(const char *enc) {
    if (!enc) return '?';
    while (*enc) {
        char c = *enc;
        if (isdigit(c)||c=='r'||c=='n'||c=='N'||c=='o'||c=='O'||c=='R'||c=='V') { enc++; continue; }
        return c;
    }
    return '?';
}

// ============================== 敏感信息脱敏 ==============================
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
    NSArray *bad = @[@"cookie",@"token",@"session",@"pass",@"pwd",@"secret",
                     @"phone",@"mobile",@"account",@"idfa",@"idfv",@"auth",@"ticket"];
    for (NSString *b in bad) if ([x containsString:b]) return YES;
    return NO;
}
static NSString *bdd_maskString(NSString *s) {
    if (!s) return nil;
    bdd_ensureRx();
    NSString *out = [g_phoneRx stringByReplacingMatchesInString:s options:0 range:NSMakeRange(0,s.length) withTemplate:@"1XX****XXXX"];
    out = [g_uuidRx stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0,out.length)
                                        withTemplate:@"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"];
    out = [g_tokenRx stringByReplacingMatchesInString:out options:0 range:NSMakeRange(0,out.length)
                                         withTemplate:@"token***"];
    if (out.length > 300) out = [[out substringToIndex:300] stringByAppendingString:@"…(截断)"];
    return out;
}

// 安全摘要：只对 Foundation 安全类取值，其余只记类名，不调自定义 description
static NSString *bdd_summary(id v, int depth, NSString *keyHint) {
    if (!v) return @"nil";
    Class c = [v class];
    if ([v isKindOfClass:NSString.class]) {
        if (keyHint && bdd_sensitiveKey(keyHint)) return [NSString stringWithFormat:@"<NSString len=%lu 已脱敏>",(unsigned long)((NSString*)v).length];
        return [NSString stringWithFormat:@"NSString: %@", bdd_maskString((NSString*)v)];
    }
    if ([v isKindOfClass:NSNumber.class]) return [NSString stringWithFormat:@"%@: %@", NSStringFromClass(c), v];
    if ([v isKindOfClass:NSUUID.class])
        return [NSString stringWithFormat:@"NSUUID: %@", bdd_maskString([(NSUUID*)v UUIDString])]; // 结构保留、值脱敏
    if ([v isKindOfClass:NSDate.class])
        return [NSString stringWithFormat:@"NSDate: %@", v];
    if ([v isKindOfClass:NSData.class]) return [NSString stringWithFormat:@"<NSData len=%lu>",(unsigned long)((NSData*)v).length];
    if ([v isKindOfClass:NSURL.class]) return [NSString stringWithFormat:@"NSURL(scheme/host): %@://%@", ((NSURL*)v).scheme?:@"", ((NSURL*)v).host?:@""];
    if ([v isKindOfClass:NSArray.class]) {
        NSArray *snap = nil;
        @try { snap = [[NSArray alloc] initWithArray:(NSArray*)v copyItems:NO]; } // 浅拷贝快照，防枚举时被改
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
            else if ([val isKindOfClass:NSNumber.class]) vs = [NSString stringWithFormat:@"%@(值=%@)", NSStringFromClass([val class]), val]; // v3: 数字字段带出真实数值（非敏感）
            else vs = NSStringFromClass([val class]) ?: @"?";
            [parts addObject:[NSString stringWithFormat:@"%@=%@", ks, vs]];
        }
        return [NSString stringWithFormat:@"{NSDictionary count=%lu keys: [%@]}",(unsigned long)snap.count,[parts componentsJoinedByString:@", "]];
    }
    return [NSString stringWithFormat:@"<%@>", NSStringFromClass(c)]; // 其他对象只记类名
}

// 一次短栈：按本 dylib 镜像区间剔除自身帧（不依赖固定帧数）
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

// 观测：首次采样（摘要+短栈），之后仅计数
static void bdd_observe(NSMutableDictionary *rec, id ret, NSArray *args) {
    if (!rec) return;
    if (t_suppress) return;                 // 采样期间触发的重入调用，不再记录（防递归）
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
        os_unfair_lock_lock(&g_lock); rec[@"sampled"]=@NO; os_unfair_lock_unlock(&g_lock); // 失败允许下次重采
        retSum = [NSString stringWithFormat:@"<采样异常: %@>", e.name];
    } @finally {
        t_suppress--;
    }

    os_unfair_lock_lock(&g_lock);
    rec[@"sampleReturn"] = retSum ?: @"nil";
    if (argSum.count) rec[@"sampleArgs"] = argSum;
    rec[@"sampleStack"] = stack ?: @"";
    os_unfair_lock_unlock(&g_lock);
}

// 通过 objc_msgSend 调原实现（交换后的 aliasSel），PAC 安全；不直接调 IMP
static id bdd_call0(id s, SEL sel){ return ((id(*)(id,SEL))objc_msgSend)(s,sel); }
static id bdd_call1(id s, SEL sel,id a){ return ((id(*)(id,SEL,id))objc_msgSend)(s,sel,a); }
static id bdd_call2(id s, SEL sel,id a,id b){ return ((id(*)(id,SEL,id,id))objc_msgSend)(s,sel,a,b); }

// ============================== 三个安全 trampoline（仅对象返回、0~2 对象参数） ==============================
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

// ============================== v3：只读 CGSize 结构体 trampoline（仅 getScreenResolution） ==============================
// arm64 下 CGSize=两个 double，经 d0/d1 返回；objc_msgSend 即可承载（arm64 无 stret）。只记录、原值原样返回。
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
    CGSize ret = ((CGSize(*)(id,SEL))objc_msgSend)(self, aliasSel); // 调原实现
    bdd_observeCGSize(r, ret);                                       // 只记录
    return ret;                                                      // 原值原样返回
}

// ============================== 安装：验证存在 → 验签 → 安全 swizzle ==============================
static void bdd_tryInstall(NSMutableDictionary *rec, int index) {
    if ([rec[@"status"] isEqualToString:@"hooked"] || [rec[@"final"] boolValue]) return;
    NSString *clsName = rec[@"clsName"];
    NSString *selName = rec[@"selName"];
    Class appCls = NSClassFromString(clsName);
    if (!appCls) { rec[@"status"] = @"未找到（类尚未加载）"; return; }

    BOOL preferClass = [rec[@"preferClass"] boolValue];
    Class meta = object_getClass(appCls);
    // 运行时双向确认：先偏好类型，找不到再换另一类型
    Class hookCls = preferClass ? meta : appCls;
    Method m = class_getInstanceMethod(hookCls, NSSelectorFromString(selName));
    BOOL isClass = preferClass;
    if (!m) { hookCls = preferClass ? appCls : meta; m = class_getInstanceMethod(hookCls, NSSelectorFromString(selName)); isClass = !preferClass; }
    if (!m) { rec[@"status"] = @"未找到（selector 不存在）"; return; }

    // init 方法族有 ns_consumes_self / ns_returns_retained 所有权语义，通用 id trampoline 不匹配，直接跳过
    if ([selName hasPrefix:@"init"]) {
        rec[@"kind"] = isClass ? @"+(类方法)" : @"-(实例方法)";
        rec[@"encoding"] = [NSString stringWithUTF8String:method_getTypeEncoding(m) ?: "?"];
        rec[@"status"] = @"未Hook(init方法族,需专用所有权trampoline)"; rec[@"final"]=@YES; return;
    }

    // 真实签名（用 bdd_typeKind 跳过限定符，取真实类型字符）
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

    // 白名单：返回必须是对象 @；用户参数 0~2 个且全为对象
    // v3 特例：0 参数、返回 {CGSize=dd} 的方法（getScreenResolution），用只读结构体 trampoline 取样
    if (retKind=='{' && userArgc==0 && strncmp(types,"{CGSize",7)==0) {
        IMP tramp = (IMP)bdd_tramp_cgsize;
        NSString *alias = [NSString stringWithFormat:@"bddiag2_orig_%d", index]; // 0 参数无冒号
        SEL aliasSel = sel_registerName(alias.UTF8String);
        SEL targetSel = NSSelectorFromString(selName);
        IMP origImp = method_getImplementation(m);
        BOOL addAlias = class_addMethod(hookCls, aliasSel, tramp, types);
        BOOL addedOwn = class_addMethod(hookCls, targetSel, origImp, types);
        Method targetM = class_getInstanceMethod(hookCls, targetSel);
        Method aliasM  = class_getInstanceMethod(hookCls, aliasSel);
        if (!addAlias || !targetM || !aliasM) {
            os_unfair_lock_lock(&g_lock); rec[@"status"]=@"未Hook(CGSize swizzle失败)"; rec[@"final"]=@YES; os_unfair_lock_unlock(&g_lock); return;
        }
        os_unfair_lock_lock(&g_lock);
        rec[@"aliasSel"]=alias; rec[@"installedClass"]=hookCls;
        os_unfair_lock_unlock(&g_lock);
        method_exchangeImplementations(targetM, aliasM);
        (void)addedOwn;
        os_unfair_lock_lock(&g_lock);
        rec[@"status"]=@"已Hook(CGSize只读)"; rec[@"final"]=@YES;
        os_unfair_lock_unlock(&g_lock);
        return;
    }
    if (retKind != '@') { os_unfair_lock_lock(&g_lock); rec[@"status"]=[NSString stringWithFormat:@"未Hook(返回类型%c非对象)",retKind]; rec[@"final"]=@YES; os_unfair_lock_unlock(&g_lock); return; }
    if (userArgc < 0 || userArgc > 2) { os_unfair_lock_lock(&g_lock); rec[@"status"]=[NSString stringWithFormat:@"未Hook(参数数%d超出0~2)",userArgc]; rec[@"final"]=@YES; os_unfair_lock_unlock(&g_lock); return; }
    if (!argsSafe) { os_unfair_lock_lock(&g_lock); rec[@"status"]=[NSString stringWithFormat:@"未Hook(含非对象参数:%@)",argKinds]; rec[@"final"]=@YES; os_unfair_lock_unlock(&g_lock); return; }

    // 选 trampoline 与带对应冒号数的唯一 alias selector
    IMP tramp = (userArgc==0)?(IMP)bdd_tramp0 : (userArgc==1)?(IMP)bdd_tramp1 : (IMP)bdd_tramp2;
    NSString *alias = [NSString stringWithFormat:@"bddiag2_orig_%d%@", index,
                       userArgc==0?@"":(userArgc==1?@":":@"::")];
    SEL aliasSel = sel_registerName(alias.UTF8String);
    SEL targetSel = NSSelectorFromString(selName);
    IMP origImp = method_getImplementation(m);

    // 1) 把 trampoline 以【原签名】挂到 alias
    BOOL addAlias = class_addMethod(hookCls, aliasSel, tramp, types);
    // 2) 若目标方法来自父类，先在本类落地一份原实现，避免改到父类
    BOOL addedOwn = class_addMethod(hookCls, targetSel, origImp, types);
    Method targetM = class_getInstanceMethod(hookCls, targetSel);
    Method aliasM  = class_getInstanceMethod(hookCls, aliasSel);
    if (!addAlias || !targetM || !aliasM) { os_unfair_lock_lock(&g_lock); rec[@"status"]=@"未Hook(swizzle失败)"; rec[@"final"]=@YES; os_unfair_lock_unlock(&g_lock); return; }
    // 3) 交换【之前】先一次性发布元数据，消除“已进 trampoline 但 aliasSel 还没写”的并发窗口
    os_unfair_lock_lock(&g_lock);
    rec[@"aliasSel"] = alias;
    rec[@"installedClass"] = hookCls;
    os_unfair_lock_unlock(&g_lock);
    method_exchangeImplementations(targetM, aliasM);
    (void)addedOwn;

    os_unfair_lock_lock(&g_lock);
    rec[@"status"] = @"已Hook";
    rec[@"final"] = @YES;
    os_unfair_lock_unlock(&g_lock);
}

static int g_tries = 0;
static void bdd_pass(void) {
    BOOL allDone = YES;
    for (int i=0;i<kTargetCount;i++) {
        NSMutableDictionary *r;
        os_unfair_lock_lock(&g_lock); r = g_records[i]; os_unfair_lock_unlock(&g_lock);
        bdd_tryInstall(r, i);
        if (![r[@"final"] boolValue]) allDone = NO;   // 已Hook/拒绝=final；类未加载则继续重试
    }
    g_tries++;
    if (!allDone && g_tries < 60) { // 0.5s * 60 = 30s
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ bdd_pass(); });
    } else {
        os_unfair_lock_lock(&g_lock);
        for (NSMutableDictionary *r in g_records)
            if (![r[@"final"] boolValue]) { r[@"status"]=@"未找到(30s内未加载)"; r[@"final"]=@YES; }
        os_unfair_lock_unlock(&g_lock);
    }
}

// ============================== 报告 / 浮窗 / 分享 ==============================
@interface BDDiag2Store : NSObject
+ (NSString *)buildReport;
+ (void)share;
@end

@interface BDDiag2Window : UIWindow @end
@implementation BDDiag2Window
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *h = [super hitTest:point withEvent:event];
    return (h == self || h == self.rootViewController.view) ? nil : h;
}
@end
@interface UIButton (BDDiag2Drag) - (void)bd2_drag:(UIPanGestureRecognizer*)g; @end

@implementation BDDiag2Store
+ (NSString *)buildReport {
    os_unfair_lock_lock(&g_lock);
    NSArray *snap = [[NSArray alloc] initWithArray:g_records copyItems:YES];
    os_unfair_lock_unlock(&g_lock);
    NSMutableString *s = [NSMutableString string];
    [s appendString:@"BDDiag2 定向设备方法只读探针报告\n"];
    [s appendFormat:@"生成时间: %@\n", [NSDate date]];
    [s appendFormat:@"目标方法: %lu 个\n\n",(unsigned long)snap.count];
    for (NSDictionary *r in snap) {
        [s appendFormat:@"[%@] %@ %@ %@\n", r[@"group"], r[@"kind"]?:@"?", r[@"clsName"], r[@"selName"]];
        [s appendFormat:@"  状态: %@  命中: %@\n", r[@"status"], r[@"hits"]?:@0];
        if (r[@"encoding"])
            [s appendFormat:@"  签名: %@ | 返回=%@ | 参数数=%@ 类型=[%@]\n",
             r[@"encoding"], r[@"retType"], r[@"argc"],
             [(NSArray*)r[@"argTypes"] componentsJoinedByString:@","]];
        if (r[@"sampleArgs"]) [s appendFormat:@"  入参样本: %@\n", r[@"sampleArgs"]];
        if (r[@"sampleReturn"]) [s appendFormat:@"  返回样本: %@\n", r[@"sampleReturn"]];
        if ([(NSString*)r[@"sampleStack"] length]) [s appendFormat:@"  短栈:\n%@\n", r[@"sampleStack"]];
        [s appendString:@"\n"];
    }
    return s;
}

+ (void)share {
    t_suppress++;
    NSString *report=nil; NSString *path=nil; NSError *e=nil;
    @try {
        report = [self buildReport];
        UIPasteboard.generalPasteboard.string = report;
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSDateFormatter *f = [NSDateFormatter new]; f.dateFormat = @"yyyy-MM-dd_HH_mm_ss_ZZZ";
        path = [docs stringByAppendingPathComponent:[NSString stringWithFormat:@"BDDiag2_log_%@.txt",[f stringFromDate:[NSDate date]]]];
        [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&e];
    } @finally { t_suppress--; }
    NSURL *url = (e || !path) ? nil : [NSURL fileURLWithPath:path];
    dispatch_async(dispatch_get_main_queue(), ^{
        t_suppress++;
        @try {
            UIViewController *vc = nil;
            for (UIScene *sc in UIApplication.sharedApplication.connectedScenes)
                if ([sc isKindOfClass:UIWindowScene.class] && sc.activationState==UISceneActivationStateForegroundActive)
                    for (UIWindow *x in ((UIWindowScene*)sc).windows) { UIViewController *t=x.rootViewController; if(t){vc=t;break;} }
            if (!vc) return;
            UIActivityViewController *ac = [[UIActivityViewController alloc] initWithActivityItems:(url?@[url,report]:@[report]) applicationActivities:nil];
            UIViewController *top = vc;
            while (top.presentedViewController) top = top.presentedViewController;
            ac.popoverPresentationController.sourceView = top.view;
            [top presentViewController:ac animated:YES completion:nil];
        } @finally { t_suppress--; }
    });
}
@end

static BDDiag2Window *g_win = nil;
static int g_floatTries = 0;
static void bdd_float(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_win) return;
        UIWindowScene *scene=nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes)
            if ([s isKindOfClass:UIWindowScene.class] && s.activationState==UISceneActivationStateForegroundActive){scene=(UIWindowScene*)s;break;}
        if (!scene){ if (++g_floatTries <= 10) dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{bdd_float();}); return;}
        t_suppress++;
        @try {
            BDDiag2Window *w=[[BDDiag2Window alloc] initWithWindowScene:scene];
            w.frame=UIScreen.mainScreen.bounds; w.windowLevel=UIWindowLevelAlert+100;
            UIViewController *vc=[UIViewController new]; vc.view.backgroundColor=UIColor.clearColor; w.rootViewController=vc;
            UIButton *b=[UIButton buttonWithType:UIButtonTypeSystem];
            b.frame=CGRectMake(8,220,120,40); b.backgroundColor=[[UIColor blackColor]colorWithAlphaComponent:0.72];
            [b setTitle:@"BDDiag2 导出" forState:UIControlStateNormal]; b.titleLabel.font=[UIFont systemFontOfSize:13];
            [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal]; b.layer.cornerRadius=8;
            [b addGestureRecognizer:[[UIPanGestureRecognizer alloc]initWithTarget:b action:@selector(bd2_drag:)]];
            [b addTarget:BDDiag2Store.class action:@selector(share) forControlEvents:UIControlEventTouchUpInside];
            [vc.view addSubview:b]; w.hidden=NO; g_win=w;
        } @finally { t_suppress--; }
    });
}
@implementation UIButton (BDDiag2Drag)
- (void)bd2_drag:(UIPanGestureRecognizer*)g {
    UIView *sup=self.superview; CGPoint t=[g translationInView:sup];
    CGPoint c=self.center; c.x+=t.x; c.y+=t.y; self.center=c; [g setTranslation:CGPointZero inView:sup];
}
@end

// ============================== 入口 ==============================
__attribute__((constructor)) static void bddiag2_entry(void) {
    @autoreleasepool {
        // 主进程门控：只在百度极速主 App 运行，跳过扩展/其他 App
        NSBundle *mb = NSBundle.mainBundle;
        NSString *bid = mb.bundleIdentifier ?: @"";
        NSString *bpath = mb.bundlePath ?: @"";
        if ([bpath containsString:@".appex/"]) return;
        if (![bid isEqualToString:@"com.baidu.BaiduMobileInfo"]) return;

        // 计算本 dylib 的 __TEXT 段区间，用于短栈剔除自身帧（__TEXT 首段即镜像基址）
        Dl_info di; memset(&di,0,sizeof(di));
        if (dladdr((void*)&bddiag2_entry, &di) && di.dli_fbase) {
            const struct mach_header_64 *mh = (const struct mach_header_64 *)di.dli_fbase;
            uintptr_t base = (uintptr_t)di.dli_fbase;
            const struct load_command *lc = (const struct load_command *)((const uint8_t*)mh + sizeof(struct mach_header_64));
            for (uint32_t i=0; i<mh->ncmds; i++, lc=(const void*)((const uint8_t*)lc+lc->cmdsize)) {
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *seg=(const struct segment_command_64*)lc;
                    if (strncmp(seg->segname,"__TEXT",6)==0) { g_ownLow=base; g_ownHigh=base+seg->vmsize; }
                }
            }
        }

        g_records = [NSMutableArray arrayWithCapacity:kTargetCount];
        g_bySel = [NSMutableDictionary dictionary];
        for (int i=0;i<kTargetCount;i++) {
            NSMutableDictionary *r = [NSMutableDictionary dictionary];
            r[@"clsName"]=[NSString stringWithUTF8String:kTargets[i].cls];
            r[@"selName"]=[NSString stringWithUTF8String:kTargets[i].sel];
            r[@"preferClass"]=@(kTargets[i].preferClass);
            r[@"group"]=[NSString stringWithUTF8String:kTargets[i].group];
            r[@"hits"]=@0; r[@"sampled"]=@NO; r[@"status"]=@"待安装";
            [g_records addObject:r];
            NSString *sn=r[@"selName"];
            if (!g_bySel[sn]) g_bySel[sn]=[NSMutableArray array];
            [g_bySel[sn] addObject:r];
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.1*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ bdd_pass(); });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ bdd_float(); });
    }
}
