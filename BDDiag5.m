//
//  BDDiag5.m —— 百度极速版 7.14.0 登录 DI 型号定点只读探针
//
//  仅挂接已由 7.14.0 解密主程序确认存在的 SAPI 短信登录入口、基础参数构造和
//  SAPIHTTPRequest 请求构造边界。探针不修改参数、返回值、请求或响应。
//
//  隐私边界：手机号、验证码、captcha、Cookie、BDUSS、token、签名和各类设备 ID
//  永不写明文；普通参数只记录键名/类型/长度，只有设备型号、平台、系统版本和 UA
//  这类非账号字段记录脱敏后的短值。
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
#import <stdatomic.h>
#import <string.h>
#import <ctype.h>

static os_unfair_lock g_b4Lock = OS_UNFAIR_LOCK_INIT;
static os_unfair_lock g_b4InstallLock = OS_UNFAIR_LOCK_INIT;
static NSMutableArray<NSDictionary *> *g_b4Events = nil;
static NSMutableSet<NSString *> *g_b4Installed = nil;
static NSMutableArray<NSString *> *g_b4InstallNotes = nil;
static _Atomic(BOOL) g_b4Capturing = NO;
static _Atomic(unsigned) g_b4Generation = 0;
static _Atomic(unsigned) g_b4EventCount = 0;
static _Atomic(BOOL) g_b4EventCapReached = NO;
static _Atomic(BOOL) g_b4InstallPending = NO;
static _Thread_local int t_b4Suppress = 0;
static _Thread_local int t_b4LoginDepth = 0;
static _Thread_local int t_b4DIDepth = 0;
static NSTimeInterval g_b4StartAt = 0;
static uintptr_t g_b4OwnLow = 0, g_b4OwnHigh = 0;
static UILabel *g_b4StatusLabel = nil;
static const unsigned kB4MaxEvents = 240;

static BOOL b4_inSelf(uintptr_t p) { return p >= g_b4OwnLow && p < g_b4OwnHigh; }

static char b4_typeKind(const char *encoding) {
    if (!encoding) return '?';
    while (*encoding) {
        char c = *encoding;
        if (isdigit((unsigned char)c) || c == 'r' || c == 'n' || c == 'N' || c == 'o' ||
            c == 'O' || c == 'R' || c == 'V') {
            encoding++;
            continue;
        }
        return c;
    }
    return '?';
}

static BOOL b4_isCapturing(void) {
    return atomic_load_explicit(&g_b4Capturing, memory_order_acquire);
}

static NSString *b4_normalizedKey(NSString *key) {
    NSString *x = key.lowercaseString ?: @"";
    NSCharacterSet *drop = [[NSCharacterSet alphanumericCharacterSet] invertedSet];
    return [[x componentsSeparatedByCharactersInSet:drop] componentsJoinedByString:@""];
}

static BOOL b4_sensitiveKey(NSString *key) {
    NSString *x = b4_normalizedKey(key);
    for (NSString *term in @[@"phone", @"mobile", @"sms", @"verifycode", @"captcha",
                              @"password", @"passwd", @"pwd", @"cookie", @"bduss",
                              @"stoken", @"ptoken", @"token", @"secret", @"account",
                              @"username", @"auth", @"ticket", @"sign", @"encrypted",
                              @"cuid", @"idfa", @"idfv", @"deviceid", @"uuid", @"uid",
                              @"session", @"accesskey", @"apikey"])
        if ([x containsString:term]) return YES;
    return NO;
}

static BOOL b4_deviceValueKey(NSString *key) {
    if (b4_sensitiveKey(key)) return NO;
    NSString *x = b4_normalizedKey(key);
    for (NSString *term in @[@"model", @"machine", @"platform", @"terminal", @"brand",
                              @"product", @"hardware", @"devicename", @"phonetype",
                              @"phonemodel", @"osversion", @"systemversion", @"ostype",
                              @"clienttype", @"useragent"])
        if ([x containsString:term]) return YES;
    return [x isEqualToString:@"ua"];
}

static NSString *b4_safeShortString(NSString *value) {
    if (![value isKindOfClass:NSString.class]) return @"<not-string>";
    NSMutableString *out = [NSMutableString stringWithCapacity:MIN(value.length, (NSUInteger)180)];
    NSUInteger limit = MIN(value.length, (NSUInteger)180);
    for (NSUInteger i = 0; i < limit; i++) {
        unichar c = [value characterAtIndex:i];
        [out appendFormat:@"%C", (c < 0x20 && c != '\t') ? ' ' : c];
    }
    if (value.length > limit) [out appendString:@"…"];
    return out;
}

static NSString *b4_shape(id value) {
    if (!value || value == (id)kCFNull) return @"nil";
    if ([value isKindOfClass:NSString.class])
        return [NSString stringWithFormat:@"NSString(len=%lu)", (unsigned long)[(NSString *)value length]];
    if ([value isKindOfClass:NSData.class])
        return [NSString stringWithFormat:@"NSData(len=%lu)", (unsigned long)[(NSData *)value length]];
    if ([value isKindOfClass:NSArray.class])
        return [NSString stringWithFormat:@"NSArray(count=%lu)", (unsigned long)[(NSArray *)value count]];
    if ([value isKindOfClass:NSDictionary.class])
        return [NSString stringWithFormat:@"NSDictionary(count=%lu)", (unsigned long)[(NSDictionary *)value count]];
    if ([value isKindOfClass:NSNumber.class]) return @"NSNumber";
    return NSStringFromClass([value class]) ?: @"?";
}

static NSString *b4_deviceScalar(id value) {
    if ([value isKindOfClass:NSString.class])
        return [NSString stringWithFormat:@"%@(%@)", b4_shape(value), b4_safeShortString(value)];
    if ([value isKindOfClass:NSNumber.class])
        return [NSString stringWithFormat:@"NSNumber(%@)", value];
    return b4_shape(value);
}

static NSString *b4_dictionarySummary(NSDictionary *dictionary, NSUInteger depth) {
    if (![dictionary isKindOfClass:NSDictionary.class]) return b4_shape(dictionary);
    NSDictionary *snapshot = nil;
    @try { snapshot = [[NSDictionary alloc] initWithDictionary:dictionary copyItems:NO]; }
    @catch (__unused NSException *e) { return @"NSDictionary(<snapshot-failed>)"; }

    NSArray *keys = [[snapshot allKeys] sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
        return [[a description] compare:[b description]];
    }];
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    NSUInteger seen = 0;
    for (id rawKey in keys) {
        if (seen++ >= 80) { [parts addObject:@"…(keys capped)"]; break; }
        NSString *key = [rawKey isKindOfClass:NSString.class] ? rawKey : [rawKey description];
        key = b4_safeShortString(key ?: @"?");
        id value = snapshot[rawKey];
        NSString *summary = nil;
        if (b4_sensitiveKey(key)) {
            summary = [NSString stringWithFormat:@"<redacted %@>", b4_shape(value)];
        } else if (b4_deviceValueKey(key)) {
            summary = b4_deviceScalar(value);
        } else if (depth < 1 && [value isKindOfClass:NSDictionary.class]) {
            summary = b4_dictionarySummary(value, depth + 1);
        } else {
            summary = b4_shape(value);
        }
        [parts addObject:[NSString stringWithFormat:@"%@=%@", key, summary ?: @"?"]];
    }
    return [NSString stringWithFormat:@"NSDictionary(count=%lu){%@}",
            (unsigned long)snapshot.count, [parts componentsJoinedByString:@", "]];
}

static NSString *b4_urlSummary(id candidate) {
    NSURL *url = nil;
    if ([candidate isKindOfClass:NSURL.class]) url = candidate;
    else if ([candidate isKindOfClass:NSString.class]) url = [NSURL URLWithString:candidate];
    if (!url) return b4_shape(candidate);
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    NSMutableArray<NSString *> *names = [NSMutableArray array];
    for (NSURLQueryItem *item in components.queryItems ?: @[]) {
        if (names.count >= 80) { [names addObject:@"…"]; break; }
        if (item.name.length) [names addObject:b4_safeShortString(item.name)];
    }
    return [NSString stringWithFormat:@"%@://%@%@ queryKeys=[%@]",
            url.scheme ?: @"", url.host ?: @"", url.path ?: @"",
            [names componentsJoinedByString:@", "]];
}

static NSString *b4_headerSummary(NSDictionary *headers) {
    if (![headers isKindOfClass:NSDictionary.class]) return b4_shape(headers);
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    NSArray *keys = [[headers allKeys] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    for (id rawKey in keys) {
        NSString *key = [rawKey isKindOfClass:NSString.class] ? rawKey : [rawKey description];
        id value = headers[rawKey];
        if (b4_sensitiveKey(key))
            [parts addObject:[NSString stringWithFormat:@"%@=<redacted %@>", key, b4_shape(value)]];
        else if ([key caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame ||
                 [key caseInsensitiveCompare:@"Content-Type"] == NSOrderedSame)
            [parts addObject:[NSString stringWithFormat:@"%@=%@", key,
                              [value isKindOfClass:NSString.class] ? b4_safeShortString(value) : b4_shape(value)]];
        else
            [parts addObject:[NSString stringWithFormat:@"%@=%@", key, b4_shape(value)]];
    }
    return [NSString stringWithFormat:@"{%@}", [parts componentsJoinedByString:@", "]];
}

static NSString *b4_formKeySummary(NSData *body) {
    if (![body isKindOfClass:NSData.class]) return b4_shape(body);
    if (body.length == 0 || body.length > 131072)
        return [NSString stringWithFormat:@"NSData(len=%lu)", (unsigned long)body.length];
    NSString *text = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (!text) return [NSString stringWithFormat:@"NSData(len=%lu non-UTF8)", (unsigned long)body.length];
    NSMutableOrderedSet<NSString *> *keys = [NSMutableOrderedSet orderedSet];
    for (NSString *piece in [text componentsSeparatedByString:@"&"]) {
        NSString *key = [[piece componentsSeparatedByString:@"="] firstObject];
        key = [key stringByRemovingPercentEncoding] ?: key;
        if (key.length) [keys addObject:b4_safeShortString(key)];
        if (keys.count >= 100) break;
    }
    return [NSString stringWithFormat:@"NSData(len=%lu formKeys=[%@])",
            (unsigned long)body.length, [[keys array] componentsJoinedByString:@", "]];
}

static NSString *b4_requestSummary(id request) {
    if (![request isKindOfClass:NSURLRequest.class]) return b4_shape(request);
    NSURLRequest *r = request;
    return [NSString stringWithFormat:@"method=%@ url={%@} headers=%@ body=%@",
            r.HTTPMethod ?: @"", b4_urlSummary(r.URL), b4_headerSummary(r.allHTTPHeaderFields),
            b4_formKeySummary(r.HTTPBody)];
}

static NSString *b4_stack(void) {
    void *frames[14];
    int count = backtrace(frames, 14);
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    for (int i = 0; i < count && lines.count < 8; i++) {
        if (b4_inSelf((uintptr_t)frames[i])) continue;
        Dl_info info;
        memset(&info, 0, sizeof(info));
        if (!dladdr(frames[i], &info)) continue;
        const char *image = info.dli_fname ? strrchr(info.dli_fname, '/') : NULL;
        image = image ? image + 1 : (info.dli_fname ?: "?");
        uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
        NSString *symbol = info.dli_sname ? [NSString stringWithUTF8String:info.dli_sname] : @"";
        [lines addObject:[NSString stringWithFormat:@"    %s+0x%lx %@", image,
                          (unsigned long)offset, symbol ?: @""]];
    }
    return [lines componentsJoinedByString:@"\n"];
}

static void b4_updateStatusAsync(void) {
    unsigned count = atomic_load_explicit(&g_b4EventCount, memory_order_acquire);
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_b4StatusLabel && b4_isCapturing())
            g_b4StatusLabel.text = [NSString stringWithFormat:@"采集中…事件%u", count];
    });
}

static void b4_record(NSString *type, NSString *source, NSString *detail) {
    if (t_b4Suppress || !b4_isCapturing()) return;
    unsigned old = atomic_fetch_add_explicit(&g_b4EventCount, 1, memory_order_acq_rel);
    if (old >= kB4MaxEvents) {
        atomic_store_explicit(&g_b4EventCapReached, YES, memory_order_release);
        return;
    }
    NSTimeInterval relative = [NSDate date].timeIntervalSince1970 - g_b4StartAt;
    NSString *stack = nil;
    t_b4Suppress++;
    @try { stack = b4_stack(); }
    @catch (__unused NSException *e) { stack = @"<stack-failed>"; }
    @finally { t_b4Suppress--; }

    NSDictionary *event = @{ @"type": type ?: @"?", @"source": source ?: @"?",
                              @"detail": detail ?: @"", @"stack": stack ?: @"",
                              @"relative": @(relative) };
    os_unfair_lock_lock(&g_b4Lock);
    @try { [g_b4Events addObject:event]; }
    @finally { os_unfair_lock_unlock(&g_b4Lock); }
    b4_updateStatusAsync();
}

static void b4_recordNoThrow(NSString *type, NSString *source, NSString *detail) {
    @try { b4_record(type, source, detail); }
    @catch (__unused NSException *e) { }
}

static NSString *b4_source(id self, SEL command) {
    return [NSString stringWithFormat:@"%c[%@ %@]", object_isClass(self) ? '+' : '-',
            NSStringFromClass(object_isClass(self) ? self : [self class]), NSStringFromSelector(command)];
}

static BOOL b4_pathLooksLikeLogin(id path) {
    NSString *x = [[path description] lowercaseString];
    for (NSString *term in @[@"sms", @"login", @"dpass", @"captcha", @"verify", @"phone"])
        if ([x containsString:term]) return YES;
    return NO;
}

static NSString *b4_privateArgument(NSString *name, id value) {
    return [NSString stringWithFormat:@"%@=<redacted %@>", name, b4_shape(value)];
}

static NSUInteger b4_textLength(id value) {
    return [value isKindOfClass:NSString.class] ? [(NSString *)value length] : 0;
}

static id b4_originalDeviceModel(id helperClass) {
    SEL alias = sel_registerName("bd5orig_deviceModel");
    if (![helperClass respondsToSelector:alias]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(helperClass, alias);
}

// ---- exact SAPI service/manager entry wrappers ----
static void b4_sendSms(id self, SEL command, id country, id phone, id captcha, id extra,
                       id success, id failure) {
    BOOL active = b4_isCapturing();
    if (active) {
        @try {
            NSString *detail = [NSString stringWithFormat:@"country=%@; %@; %@; extraParams=%@; callbacks=%@/%@",
                                b4_deviceScalar(country), b4_privateArgument(@"phone", phone),
                                b4_privateArgument(@"captcha", captcha), b4_dictionarySummary(extra, 0),
                                b4_shape(success), b4_shape(failure)];
            b4_recordNoThrow(@"FLOW_SEND_SMS", b4_source(self, command), detail);
        } @catch (__unused NSException *e) { }
        t_b4LoginDepth++;
    }
    @try {
        SEL alias = sel_registerName("bd5orig_sendSmsCodeWithCountryCode:phoneNumber:captcha:extraParams:success:failure:");
        ((void (*)(id, SEL, id, id, id, id, id, id))objc_msgSend)
            (self, alias, country, phone, captcha, extra, success, failure);
    } @finally { if (active) t_b4LoginDepth--; }
}

static void b4_smsLogin(id self, SEL command, id country, id phone, id smsCode, id encryptedId,
                        id extra, id success, id verify, id failure) {
    BOOL active = b4_isCapturing();
    if (active) {
        @try {
            NSString *detail = [NSString stringWithFormat:@"country=%@; %@; %@; %@; extraParams=%@; callbacks=%@/%@/%@",
                                b4_deviceScalar(country), b4_privateArgument(@"phone", phone),
                                b4_privateArgument(@"smsCode", smsCode),
                                b4_privateArgument(@"encryptedId", encryptedId),
                                b4_dictionarySummary(extra, 0), b4_shape(success), b4_shape(verify), b4_shape(failure)];
            b4_recordNoThrow(@"FLOW_SMS_LOGIN", b4_source(self, command), detail);
        } @catch (__unused NSException *e) { }
        t_b4LoginDepth++;
    }
    @try {
        SEL alias = sel_registerName("bd5orig_smsLoginWithCountryCode:phoneNumber:smsCode:encryptedId:extraParams:success:verify:failure:");
        ((void (*)(id, SEL, id, id, id, id, id, id, id, id))objc_msgSend)
            (self, alias, country, phone, smsCode, encryptedId, extra, success, verify, failure);
    } @finally { if (active) t_b4LoginDepth--; }
}

static void b4_getDpass(id self, SEL command, id mobile, id captcha, id extra, id success, id failure) {
    BOOL active = b4_isCapturing();
    if (active) {
        @try {
            b4_recordNoThrow(@"FLOW_GET_DPASS", b4_source(self, command),
                [NSString stringWithFormat:@"%@; %@; extraParams=%@; callbacks=%@/%@",
                 b4_privateArgument(@"mobile", mobile), b4_privateArgument(@"captcha", captcha),
                 b4_dictionarySummary(extra, 0), b4_shape(success), b4_shape(failure)]);
        } @catch (__unused NSException *e) { }
        t_b4LoginDepth++;
    }
    @try {
        SEL alias = sel_registerName("bd5orig_getDpassWithMobile:captcha:extraParams:success:failure:");
        ((void (*)(id, SEL, id, id, id, id, id))objc_msgSend)
            (self, alias, mobile, captcha, extra, success, failure);
    } @finally { if (active) t_b4LoginDepth--; }
}

static void b4_loginWithMobile(id self, SEL command, id mobile, id dpass, id extra, id success, id failure) {
    BOOL active = b4_isCapturing();
    if (active) {
        @try {
            b4_recordNoThrow(@"FLOW_LOGIN_MOBILE", b4_source(self, command),
                [NSString stringWithFormat:@"%@; %@; extraParams=%@; callbacks=%@/%@",
                 b4_privateArgument(@"mobile", mobile), b4_privateArgument(@"dpass", dpass),
                 b4_dictionarySummary(extra, 0), b4_shape(success), b4_shape(failure)]);
        } @catch (__unused NSException *e) { }
        t_b4LoginDepth++;
    }
    @try {
        SEL alias = sel_registerName("bd5orig_loginWithMobile:dpass:extraParams:success:failure:");
        ((void (*)(id, SEL, id, id, id, id, id))objc_msgSend)
            (self, alias, mobile, dpass, extra, success, failure);
    } @finally { if (active) t_b4LoginDepth--; }
}

static id b4_baseParams(id self, SEL command, id interfaceName) {
    SEL alias = sel_registerName("bd5orig_baseParamsForSMSLoginWithInterface:");
    id result = ((id (*)(id, SEL, id))objc_msgSend)(self, alias, interfaceName);
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"SMS_BASE_PARAMS", b4_source(self, command),
            [NSString stringWithFormat:@"interface=%@; result=%@",
             [interfaceName isKindOfClass:NSString.class] ? b4_safeShortString(interfaceName) : b4_shape(interfaceName),
             b4_dictionarySummary(result, 0)]);
    } @catch (__unused NSException *e) { }
    return result;
}

// ---- exact SAPI device-info pipeline wrappers ----
// The plaintext DI is never emitted.  We only compare it with the independently
// returned deviceModel string and record lengths/booleans.
static id b5_deviceModel(id self, SEL command) {
    SEL alias = sel_registerName("bd5orig_deviceModel");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing() && t_b4DIDepth > 0) @try {
        NSString *shown = [result isKindOfClass:NSString.class] ? b4_safeShortString(result) : b4_shape(result);
        b4_recordNoThrow(@"DI_DEVICE_MODEL", b4_source(self, command),
                         [NSString stringWithFormat:@"value=%@; DIdepth=%d", shown, t_b4DIDepth]);
    } @catch (__unused NSException *e) { }
    return result;
}

static BOOL b5_notAllowedGetDI(id self, SEL command, NSUInteger index) {
    SEL alias = sel_registerName("bd5orig_notAllowedGetDI:");
    BOOL result = ((BOOL (*)(id, SEL, NSUInteger))objc_msgSend)(self, alias, index);
    if (b4_isCapturing() && t_b4DIDepth > 0 && index == 3) @try {
        b4_recordNoThrow(@"DI_MODEL_EXCLUSION", b4_source(self, command),
                         [NSString stringWithFormat:@"index=3(deviceModel); excluded=%@", result ? @"YES" : @"NO"]);
    } @catch (__unused NSException *e) { }
    return result;
}

static id b5_plainDeviceInfo(id self, SEL command, id interfaceName) {
    BOOL active = b4_isCapturing();
    if (active) t_b4DIDepth++;
    id result = nil;
    @try {
        SEL alias = sel_registerName("bd5orig_plainDeviceInfoWithInterface:");
        result = ((id (*)(id, SEL, id))objc_msgSend)(self, alias, interfaceName);
    } @finally { if (active) t_b4DIDepth--; }
    if (active) @try {
        id model = b4_originalDeviceModel(self);
        BOOL comparable = [result isKindOfClass:NSString.class] && [model isKindOfClass:NSString.class] &&
                          [(NSString *)model length] > 0;
        BOOL contains = comparable && [(NSString *)result rangeOfString:(NSString *)model].location != NSNotFound;
        b4_recordNoThrow(@"DI_PLAIN_MODEL_CHECK", b4_source(self, command),
            [NSString stringWithFormat:@"interface=%@; plainLen=%lu; model=%@; comparable=%@; containsModel=%@; plaintext=<not logged>",
             [interfaceName isKindOfClass:NSString.class] ? b4_safeShortString(interfaceName) : b4_shape(interfaceName),
             (unsigned long)b4_textLength(result),
             [model isKindOfClass:NSString.class] ? b4_safeShortString(model) : b4_shape(model),
             comparable ? @"YES" : @"NO", contains ? @"YES" : @"NO"]);
    } @catch (__unused NSException *e) { }
    return result;
}

static id b5_generateDeviceInfo(id self, SEL command, id plainString) {
    SEL alias = sel_registerName("bd5orig_generateDeviceInfoWithPlainString:");
    id result = ((id (*)(id, SEL, id))objc_msgSend)(self, alias, plainString);
    if (b4_isCapturing()) @try {
        id model = b4_originalDeviceModel(self);
        BOOL comparable = [plainString isKindOfClass:NSString.class] && [model isKindOfClass:NSString.class] &&
                          [(NSString *)model length] > 0;
        BOOL contains = comparable && [(NSString *)plainString rangeOfString:(NSString *)model].location != NSNotFound;
        b4_recordNoThrow(@"DI_PRE_ENCRYPT", b4_source(self, command),
            [NSString stringWithFormat:@"plainLen=%lu; model=%@; containsModel=%@; encodedLen=%lu; plaintext=<not logged>",
             (unsigned long)b4_textLength(plainString),
             [model isKindOfClass:NSString.class] ? b4_safeShortString(model) : b4_shape(model),
             contains ? @"YES" : @"NO", (unsigned long)b4_textLength(result)]);
    } @catch (__unused NSException *e) { }
    return result;
}

static id b5_deviceInfoString(id self, SEL command, id interfaceName) {
    BOOL active = b4_isCapturing();
    if (active) t_b4DIDepth++;
    id result = nil;
    @try {
        SEL alias = sel_registerName("bd5orig_deviceInfoStringWithInterface:");
        result = ((id (*)(id, SEL, id))objc_msgSend)(self, alias, interfaceName);
    } @finally { if (active) t_b4DIDepth--; }
    if (active) @try {
        b4_recordNoThrow(@"DI_ENCODED", b4_source(self, command),
            [NSString stringWithFormat:@"interface=%@; encodedLen=%lu; value=<not logged>",
             [interfaceName isKindOfClass:NSString.class] ? b4_safeShortString(interfaceName) : b4_shape(interfaceName),
             (unsigned long)b4_textLength(result)]);
    } @catch (__unused NSException *e) { }
    return result;
}

static id b5_interfaceForLogin(id self, SEL command) {
    SEL alias = sel_registerName("bd5orig_interfaceForLogin");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"DI_LOGIN_INTERFACE", b4_source(self, command),
            [result isKindOfClass:NSString.class] ? b4_safeShortString(result) : b4_shape(result));
    } @catch (__unused NSException *e) { }
    return result;
}

static id b5_deviceInfoForLogin(id self, SEL command) {
    SEL alias = sel_registerName("bd5orig_deviceInfoForLogin");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"DI_FOR_LOGIN", b4_source(self, command),
            [NSString stringWithFormat:@"encodedLen=%lu; value=<not logged>", (unsigned long)b4_textLength(result)]);
    } @catch (__unused NSException *e) { }
    return result;
}

// ---- exact pre-encoding request construction wrappers ----
static id b4_request3(id self, SEL command, id method, id path, id parameters) {
    BOOL relevant = b4_isCapturing() && (t_b4LoginDepth > 0 || b4_pathLooksLikeLogin(path));
    NSString *before = nil;
    if (relevant) {
        t_b4Suppress++;
        @try {
            before = [NSString stringWithFormat:@"method=%@; path=%@; parameters=%@",
                      [method isKindOfClass:NSString.class] ? b4_safeShortString(method) : b4_shape(method),
                      b4_urlSummary(path), b4_dictionarySummary(parameters, 0)];
        } @catch (__unused NSException *e) { before = @"<pre-summary-failed>"; }
          @finally { t_b4Suppress--; }
    }
    SEL alias = sel_registerName("bd5orig_requestWithMethod:path:parameters:");
    id result = ((id (*)(id, SEL, id, id, id))objc_msgSend)(self, alias, method, path, parameters);
    if (relevant)
        @try { b4_recordNoThrow(@"REQUEST_PRE_ENCODE", b4_source(self, command),
            [NSString stringWithFormat:@"%@; builtRequest={%@}", before ?: @"", b4_requestSummary(result)]); }
        @catch (__unused NSException *e) { }
    return result;
}

static id b4_request4(id self, SEL command, id method, id path, double timeout, id parameters) {
    BOOL relevant = b4_isCapturing() && (t_b4LoginDepth > 0 || b4_pathLooksLikeLogin(path));
    NSString *before = nil;
    if (relevant) {
        t_b4Suppress++;
        @try {
            before = [NSString stringWithFormat:@"method=%@; path=%@; timeout=%.2f; parameters=%@",
                      [method isKindOfClass:NSString.class] ? b4_safeShortString(method) : b4_shape(method),
                      b4_urlSummary(path), timeout, b4_dictionarySummary(parameters, 0)];
        } @catch (__unused NSException *e) { before = @"<pre-summary-failed>"; }
          @finally { t_b4Suppress--; }
    }
    SEL alias = sel_registerName("bd5orig_requestWithMethod:path:timeout:parameters:");
    id result = ((id (*)(id, SEL, id, id, double, id))objc_msgSend)
        (self, alias, method, path, timeout, parameters);
    if (relevant)
        @try { b4_recordNoThrow(@"REQUEST_PRE_ENCODE", b4_source(self, command),
            [NSString stringWithFormat:@"%@; builtRequest={%@}", before ?: @"", b4_requestSummary(result)]); }
        @catch (__unused NSException *e) { }
    return result;
}

static id b4_smsLoginURL(id self, SEL command) {
    SEL alias = sel_registerName("bd5orig_smsLoginURLString");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"SMS_URL", b4_source(self, command), b4_urlSummary(result));
    } @catch (__unused NSException *e) { }
    return result;
}

static id b4_smsGetLoginURL(id self, SEL command) {
    SEL alias = sel_registerName("bd5orig_smsGetLoginURL");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"SMS_URL", b4_source(self, command), b4_urlSummary(result));
    } @catch (__unused NSException *e) { }
    return result;
}

static void b4_noteInstall(NSString *note) {
    os_unfair_lock_lock(&g_b4Lock);
    @try { [g_b4InstallNotes addObject:note ?: @"?"]; }
    @finally { os_unfair_lock_unlock(&g_b4Lock); }
}

static BOOL b4_installExact(const char *className, BOOL classMethod, const char *selectorName,
                            const char *aliasName, IMP replacement, char expectedReturn,
                            const char *expectedArgs) {
    os_unfair_lock_lock(&g_b4InstallLock);
    @try {
        NSString *key = [NSString stringWithFormat:@"%c[%s %s]", classMethod ? '+' : '-', className, selectorName];
        os_unfair_lock_lock(&g_b4Lock);
        BOOL already = NO;
        @try { already = [g_b4Installed containsObject:key]; }
        @finally { os_unfair_lock_unlock(&g_b4Lock); }
        if (already) return YES;

        Class cls = objc_getClass(className);
        if (!cls) return NO;
        Class target = classMethod ? object_getClass(cls) : cls;
        SEL selector = sel_registerName(selectorName);
        Method method = class_getInstanceMethod(target, selector);
        if (!method) { b4_noteInstall([key stringByAppendingString:@" missing"]); return NO; }

        const char *types = method_getTypeEncoding(method);
        char ret[32] = {0};
        method_getReturnType(method, ret, sizeof(ret));
        size_t expectedCount = strlen(expectedArgs);
        if (b4_typeKind(ret) != expectedReturn || method_getNumberOfArguments(method) != expectedCount + 2) {
            b4_noteInstall([key stringByAppendingFormat:@" ABI rejected (%s)", types ?: "?"]);
            return NO;
        }
        for (size_t i = 0; i < expectedCount; i++) {
            char arg[64] = {0};
            method_getArgumentType(method, (unsigned)i + 2, arg, sizeof(arg));
            if (b4_typeKind(arg) != expectedArgs[i]) {
                b4_noteInstall([key stringByAppendingFormat:@" ABI rejected (%s)", types ?: "?"]);
                return NO;
            }
        }

        SEL alias = sel_registerName(aliasName);
        IMP original = method_getImplementation(method);
        if (!class_addMethod(target, alias, original, types)) {
            b4_noteInstall([key stringByAppendingString:@" alias exists; not replaced"]);
            return NO;
        }
        class_replaceMethod(target, selector, replacement, types);
        os_unfair_lock_lock(&g_b4Lock);
        @try { [g_b4Installed addObject:key]; }
        @finally { os_unfair_lock_unlock(&g_b4Lock); }
        b4_noteInstall([key stringByAppendingFormat:@" installed (%s)", types ?: "?"]);
        return YES;
    } @finally { os_unfair_lock_unlock(&g_b4InstallLock); }
}

static void b4_installAll(void) {
    b4_installExact("SAPILoginService", NO,
        "sendSmsCodeWithCountryCode:phoneNumber:captcha:extraParams:success:failure:",
        "bd5orig_sendSmsCodeWithCountryCode:phoneNumber:captcha:extraParams:success:failure:",
        (IMP)b4_sendSms, 'v', "@@@@@@");
    b4_installExact("SAPILoginService", NO,
        "smsLoginWithCountryCode:phoneNumber:smsCode:encryptedId:extraParams:success:verify:failure:",
        "bd5orig_smsLoginWithCountryCode:phoneNumber:smsCode:encryptedId:extraParams:success:verify:failure:",
        (IMP)b4_smsLogin, 'v', "@@@@@@@@");
    b4_installExact("SAPILoginService", NO,
        "baseParamsForSMSLoginWithInterface:", "bd5orig_baseParamsForSMSLoginWithInterface:",
        (IMP)b4_baseParams, '@', "@");

    const char *loginClasses[] = {"SAPILoginService", "SAPILoginManager"};
    for (size_t i = 0; i < sizeof(loginClasses) / sizeof(loginClasses[0]); i++) {
        const char *name = loginClasses[i];
        b4_installExact(name, NO, "getDpassWithMobile:captcha:extraParams:success:failure:",
            "bd5orig_getDpassWithMobile:captcha:extraParams:success:failure:",
            (IMP)b4_getDpass, 'v', "@@@@@");
        b4_installExact(name, NO, "loginWithMobile:dpass:extraParams:success:failure:",
            "bd5orig_loginWithMobile:dpass:extraParams:success:failure:",
            (IMP)b4_loginWithMobile, 'v', "@@@@@");
    }

    b4_installExact("SAPIHTTPRequest", YES, "requestWithMethod:path:parameters:",
        "bd5orig_requestWithMethod:path:parameters:", (IMP)b4_request3, '@', "@@@");
    b4_installExact("SAPIHTTPRequest", YES, "requestWithMethod:path:timeout:parameters:",
        "bd5orig_requestWithMethod:path:timeout:parameters:", (IMP)b4_request4, '@', "@@d@");
    b4_installExact("SAPIURLHelper", YES, "smsLoginURLString", "bd5orig_smsLoginURLString",
        (IMP)b4_smsLoginURL, '@', "");
    b4_installExact("SAPIURLHelper", YES, "smsGetLoginURL", "bd5orig_smsGetLoginURL",
        (IMP)b4_smsGetLoginURL, '@', "");

    b4_installExact("SAPIDeviceInfoHelper", YES, "deviceModel", "bd5orig_deviceModel",
        (IMP)b5_deviceModel, '@', "");
    b4_installExact("SAPIDeviceInfoHelper", YES, "notAllowedGetDI:", "bd5orig_notAllowedGetDI:",
        (IMP)b5_notAllowedGetDI, 'B', "Q");
    b4_installExact("SAPIDeviceInfoHelper", YES, "plainDeviceInfoWithInterface:",
        "bd5orig_plainDeviceInfoWithInterface:", (IMP)b5_plainDeviceInfo, '@', "@");
    b4_installExact("SAPIDeviceInfoHelper", YES, "generateDeviceInfoWithPlainString:",
        "bd5orig_generateDeviceInfoWithPlainString:", (IMP)b5_generateDeviceInfo, '@', "@");
    b4_installExact("SAPIDeviceInfoHelper", YES, "deviceInfoStringWithInterface:",
        "bd5orig_deviceInfoStringWithInterface:", (IMP)b5_deviceInfoString, '@', "@");
    b4_installExact("SAPIDeviceInfoHelper", YES, "interfaceForLogin", "bd5orig_interfaceForLogin",
        (IMP)b5_interfaceForLogin, '@', "");
    b4_installExact("SAPIDeviceInfoHelper", YES, "deviceInfoForLogin", "bd5orig_deviceInfoForLogin",
        (IMP)b5_deviceInfoForLogin, '@', "");
}

static void b4_imageAdded(const struct mach_header *header, intptr_t slide) {
    (void)header; (void)slide;
    if (atomic_exchange_explicit(&g_b4InstallPending, YES, memory_order_acq_rel)) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        atomic_store_explicit(&g_b4InstallPending, NO, memory_order_release);
        b4_installAll();
    });
}

static NSString *b4_mainExecutableUUID(void) {
    NSString *executable = NSBundle.mainBundle.infoDictionary[@"CFBundleExecutable"];
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (!imageName || ![[[NSString stringWithUTF8String:imageName] lastPathComponent] isEqualToString:executable]) continue;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        const struct load_command *command = (const struct load_command *)((const uint8_t *)header + sizeof(*header));
        for (uint32_t j = 0; j < header->ncmds; j++) {
            if (command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
                const struct uuid_command *uuid = (const struct uuid_command *)command;
                const uint8_t *u = uuid->uuid;
                return [NSString stringWithFormat:@"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                        u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]];
            }
            command = (const struct load_command *)((const uint8_t *)command + command->cmdsize);
        }
    }
    return @"unknown";
}

@interface BDDiag5Store : NSObject
+ (void)startCapture;
+ (void)stopCapture;
+ (void)exportReport;
+ (NSString *)buildReport;
@end

@interface BDDiag5Window : UIWindow @end
@implementation BDDiag5Window
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    return (hit == self || hit == self.rootViewController.view) ? nil : hit;
}
@end

@implementation BDDiag5Store
+ (void)startCapture {
    dispatch_async(dispatch_get_main_queue(), ^{
        b4_installAll();
        unsigned generation;
        os_unfair_lock_lock(&g_b4Lock);
        @try {
            atomic_store_explicit(&g_b4Capturing, NO, memory_order_release);
            generation = atomic_fetch_add_explicit(&g_b4Generation, 1, memory_order_acq_rel) + 1;
            [g_b4Events removeAllObjects];
            atomic_store_explicit(&g_b4EventCount, 0, memory_order_release);
            atomic_store_explicit(&g_b4EventCapReached, NO, memory_order_release);
            g_b4StartAt = [NSDate date].timeIntervalSince1970;
            atomic_store_explicit(&g_b4Capturing, YES, memory_order_release);
        } @finally { os_unfair_lock_unlock(&g_b4Lock); }
        g_b4StatusLabel.text = [NSString stringWithFormat:@"采集中…已挂%lu", (unsigned long)g_b4Installed.count];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(120 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            BOOL stopped = NO;
            os_unfair_lock_lock(&g_b4Lock);
            @try {
                if (generation == atomic_load_explicit(&g_b4Generation, memory_order_relaxed))
                    stopped = atomic_exchange_explicit(&g_b4Capturing, NO, memory_order_acq_rel);
            } @finally { os_unfair_lock_unlock(&g_b4Lock); }
            if (stopped && g_b4StatusLabel)
                g_b4StatusLabel.text = @"已自动停(120s)，点导出";
        });
    });
}

+ (void)stopCapture {
    os_unfair_lock_lock(&g_b4Lock);
    @try { atomic_store_explicit(&g_b4Capturing, NO, memory_order_release); }
    @finally { os_unfair_lock_unlock(&g_b4Lock); }
    if (g_b4StatusLabel)
        g_b4StatusLabel.text = [NSString stringWithFormat:@"采集结束 事件%u 点导出",
                                MIN(atomic_load_explicit(&g_b4EventCount, memory_order_acquire), kB4MaxEvents)];
}

+ (NSString *)buildReport {
    NSArray<NSDictionary *> *events;
    NSArray<NSString *> *installNotes;
    os_unfair_lock_lock(&g_b4Lock);
    @try {
        events = [[NSArray alloc] initWithArray:g_b4Events copyItems:YES];
        installNotes = [g_b4InstallNotes copy];
    } @finally { os_unfair_lock_unlock(&g_b4Lock); }

    NSBundle *bundle = NSBundle.mainBundle;
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"BDDiag5 百度极速版登录 DI 型号定点只读探针报告\n"];
    [out appendFormat:@"生成时间: %@\n", [NSDate date]];
    [out appendFormat:@"Bundle ID: %@\n", bundle.bundleIdentifier ?: @""];
    [out appendFormat:@"App 版本: %@ (build %@)\n",
        bundle.infoDictionary[@"CFBundleShortVersionString"] ?: @"",
        bundle.infoDictionary[@"CFBundleVersion"] ?: @""];
    [out appendFormat:@"主程序 LC_UUID: %@\n", b4_mainExecutableUUID()];
    [out appendFormat:@"已安装精确 Hook: %lu | 采集事件: %lu | 事件封顶: %@\n",
        (unsigned long)g_b4Installed.count, (unsigned long)events.count,
        atomic_load_explicit(&g_b4EventCapReached, memory_order_acquire) ? @"是" : @"否"];
    [out appendString:@"隐私说明: 手机号/验证码/captcha/Cookie/BDUSS/token/签名/设备ID和 DI 明文均不记录。\n\n"];
    [out appendString:@"========== Hook 安装结果 ==========\n"];
    for (NSString *note in installNotes) [out appendFormat:@"%@\n", note];
    [out appendString:@"\n========== 采集事件（按时间顺序） ==========\n"];
    NSUInteger index = 0;
    for (NSDictionary *event in events) {
        [out appendFormat:@"\n[%03lu] +%.3fs %@ %@\n", (unsigned long)++index,
            [event[@"relative"] doubleValue], event[@"type"], event[@"source"]];
        [out appendFormat:@"  %@\n", event[@"detail"] ?: @""];
        if ([event[@"stack"] length]) [out appendFormat:@"  短栈:\n%@\n", event[@"stack"]];
    }
    if (events.count == 0)
        [out appendString:@"（采集窗口内未命中定点方法；请确认是在 7.14.0 中完成发送验证码或短信登录。）\n"];
    return out;
}

+ (void)exportReport {
    [self stopCapture];
    t_b4Suppress++;
    @try {
        NSString *report = [self buildReport];
        UIPasteboard.generalPasteboard.string = report;
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.dateFormat = @"yyyy-MM-dd_HH_mm_ss_ZZZ";
        NSString *path = [docs stringByAppendingPathComponent:
            [NSString stringWithFormat:@"BDDiag5_log_%@.txt", [formatter stringFromDate:[NSDate date]]]];
        NSError *error = nil;
        [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error];

        UIViewController *root = nil;
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:UIWindowScene.class] || scene.activationState != UISceneActivationStateForegroundActive) continue;
            for (UIWindow *window in ((UIWindowScene *)scene).windows)
                if (window.rootViewController) { root = window.rootViewController; break; }
            if (root) break;
        }
        if (!root) return;
        NSArray *items = (!error && path) ? @[[NSURL fileURLWithPath:path], report] : @[report];
        UIActivityViewController *activity = [[UIActivityViewController alloc] initWithActivityItems:items applicationActivities:nil];
        UIViewController *top = root;
        while (top.presentedViewController) top = top.presentedViewController;
        activity.popoverPresentationController.sourceView = top.view;
        [top presentViewController:activity animated:YES completion:nil];
    } @finally { t_b4Suppress--; }
}
@end

static BDDiag5Window *g_b4Window = nil;
static int g_b4FloatTries = 0;

@interface UIView (BD4Drag)
- (void)bd4_drag:(UIPanGestureRecognizer *)gesture;
@end
@implementation UIView (BD4Drag)
- (void)bd4_drag:(UIPanGestureRecognizer *)gesture {
    CGPoint delta = [gesture translationInView:self.superview];
    self.center = CGPointMake(self.center.x + delta.x, self.center.y + delta.y);
    [gesture setTranslation:CGPointZero inView:self.superview];
}
@end

static void b4_float(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_b4Window) return;
        UIWindowScene *windowScene = nil;
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes)
            if ([scene isKindOfClass:UIWindowScene.class] && scene.activationState == UISceneActivationStateForegroundActive) {
                windowScene = (UIWindowScene *)scene; break;
            }
        if (!windowScene) {
            if (++g_b4FloatTries <= 12)
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ b4_float(); });
            return;
        }
        t_b4Suppress++;
        @try {
            BDDiag5Window *window = [[BDDiag5Window alloc] initWithWindowScene:windowScene];
            window.frame = UIScreen.mainScreen.bounds;
            window.windowLevel = UIWindowLevelAlert + 100;
            UIViewController *controller = [UIViewController new];
            controller.view.backgroundColor = UIColor.clearColor;
            window.rootViewController = controller;

            UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(6, 220, 178, 108)];
            panel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.80];
            panel.layer.cornerRadius = 10;
            UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(8, 6, 162, 20)];
            status.textColor = UIColor.whiteColor;
            status.font = [UIFont systemFontOfSize:11];
            status.text = [NSString stringWithFormat:@"BDDiag5 待采集 已挂%lu", (unsigned long)g_b4Installed.count];
            g_b4StatusLabel = status;
            [panel addSubview:status];

            UIButton *start = [UIButton buttonWithType:UIButtonTypeSystem];
            start.frame = CGRectMake(8, 30, 78, 34);
            start.backgroundColor = [[UIColor systemGreenColor] colorWithAlphaComponent:0.9];
            [start setTitle:@"开始采集" forState:UIControlStateNormal];
            [start setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            start.titleLabel.font = [UIFont boldSystemFontOfSize:13];
            start.layer.cornerRadius = 7;
            [start addTarget:BDDiag5Store.class action:@selector(startCapture) forControlEvents:UIControlEventTouchUpInside];

            UIButton *export = [UIButton buttonWithType:UIButtonTypeSystem];
            export.frame = CGRectMake(92, 30, 78, 34);
            export.backgroundColor = [[UIColor systemBlueColor] colorWithAlphaComponent:0.9];
            [export setTitle:@"结束导出" forState:UIControlStateNormal];
            [export setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            export.titleLabel.font = [UIFont boldSystemFontOfSize:13];
            export.layer.cornerRadius = 7;
            [export addTarget:BDDiag5Store.class action:@selector(exportReport) forControlEvents:UIControlEventTouchUpInside];

            UILabel *tip = [[UILabel alloc] initWithFrame:CGRectMake(8, 68, 162, 34)];
            tip.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.82];
            tip.font = [UIFont systemFontOfSize:9];
            tip.numberOfLines = 2;
            tip.text = @"开始后发送验证码并登录；120秒自动停";
            [panel addSubview:tip];
            [panel addSubview:start];
            [panel addSubview:export];
            [panel addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:panel action:@selector(bd4_drag:)]];
            [controller.view addSubview:panel];
            window.hidden = NO;
            g_b4Window = window;
        } @finally { t_b4Suppress--; }
    });
}

__attribute__((constructor)) static void bddiag5_entry(void) {
    @autoreleasepool {
        NSBundle *bundle = NSBundle.mainBundle;
        NSString *bundleID = bundle.bundleIdentifier ?: @"";
        if ([bundle.bundlePath containsString:@".appex/"] ||
            ![bundleID isEqualToString:@"com.baidu.BaiduMobileInfo"]) return;

        Dl_info info;
        memset(&info, 0, sizeof(info));
        if (dladdr((void *)&bddiag5_entry, &info) && info.dli_fbase) {
            const struct mach_header_64 *header = (const struct mach_header_64 *)info.dli_fbase;
            uintptr_t base = (uintptr_t)info.dli_fbase;
            const struct load_command *command = (const struct load_command *)((const uint8_t *)header + sizeof(*header));
            for (uint32_t i = 0; i < header->ncmds; i++) {
                if (command->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
                    if (strncmp(segment->segname, "__TEXT", 6) == 0) {
                        g_b4OwnLow = base;
                        g_b4OwnHigh = base + segment->vmsize;
                    }
                }
                command = (const struct load_command *)((const uint8_t *)command + command->cmdsize);
            }
        }

        g_b4Events = [NSMutableArray array];
        g_b4Installed = [NSMutableSet set];
        g_b4InstallNotes = [NSMutableArray array];
        _dyld_register_func_for_add_image(b4_imageAdded);
        b4_installAll();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ b4_float(); });
    }
}
