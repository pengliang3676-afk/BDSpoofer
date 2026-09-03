//
//  BDDiag8.m —— 百度极速版 6.96.0 SAPI 设备字段排除链路定点只读探针
//
//  定点观察 SAPI/DI 的 3(deviceModel)、17(deviceType)、27(deviceName) 三个真实槽位、
//  排除数组和登录请求/设备列表响应形状。探针不修改请求或响应。
//
//  隐私边界：手机号、验证码、captcha、Cookie、BDUSS、token、签名和各类设备 ID
//  永不写明文；普通参数只记录键名/类型/长度，只有设备型号、平台、系统版本和 UA
//  这类非账号字段记录脱敏后的短值。
//


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <execinfo.h>
#import <os/lock.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdatomic.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <ctype.h>

static os_unfair_lock g_b4Lock = OS_UNFAIR_LOCK_INIT;
static os_unfair_lock g_b4InstallLock = OS_UNFAIR_LOCK_INIT;
static NSMutableArray<NSDictionary *> *g_b4Events = nil;
static NSMutableSet<NSString *> *g_b4Installed = nil;
static NSMutableArray<NSString *> *g_b4InstallNotes = nil;
static NSMutableSet<NSString *> *g_b6WebSeen = nil;
static _Atomic(BOOL) g_b4Capturing = NO;
static _Atomic(unsigned) g_b4Generation = 0;
static _Atomic(unsigned) g_b4EventCount = 0;
static _Atomic(BOOL) g_b4EventCapReached = NO;
static _Atomic(BOOL) g_b4InstallPending = NO;
static _Atomic(unsigned) g_b8ConfigLoggedGeneration = 0;
static _Atomic(uint64_t) g_b8HashSalt = 0;
static _Thread_local int t_b4Suppress = 0;
static _Thread_local int t_b4LoginDepth = 0;
static _Thread_local int t_b4DIDepth = 0;
static _Thread_local int t_b8ConfigDepth = 0;
static NSTimeInterval g_b4StartAt = 0;
static uintptr_t g_b4OwnLow = 0, g_b4OwnHigh = 0;
static UILabel *g_b4StatusLabel = nil;
static const unsigned kB4MaxEvents = 500;
static const NSTimeInterval kB8CaptureSeconds = 300.0;

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

static NSUInteger b4_installedCount(void) {
    NSUInteger count = 0;
    os_unfair_lock_lock(&g_b4Lock);
    @try { count = g_b4Installed.count; }
    @finally { os_unfair_lock_unlock(&g_b4Lock); }
    return count;
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
        [out appendFormat:@"%C", (unichar)((c < 0x20 && c != '\t') ? ' ' : c)];
    }
    if (value.length > limit) [out appendString:@"…"];
    return out;
}

static NSString *b4_shape(id value);

static NSString *b7_textMarkerSummary(id value) {
    if (![value isKindOfClass:NSString.class]) return b4_shape(value);
    NSString *text = value;
    BOOL machine = [text rangeOfString:@"iPhone[0-9]+,[0-9]+" options:NSRegularExpressionSearch].location != NSNotFound;
    BOOL human = [text rangeOfString:@"iPhone[[:space:]]+[0-9]+" options:NSRegularExpressionSearch].location != NSNotFound;
    return [NSString stringWithFormat:@"NSString(len=%lu; unknownCN=%@; Unknown_iPhone=%@; iPhone12,8=%@; iPhone14,7=%@; machine=%@; human=%@; iPhoneWord=%@)",
            (unsigned long)text.length,
            [text containsString:@"未知设备"] ? @"YES" : @"NO",
            [text containsString:@"Unknown_iPhone"] ? @"YES" : @"NO",
            [text containsString:@"iPhone12,8"] ? @"YES" : @"NO",
            [text containsString:@"iPhone14,7"] ? @"YES" : @"NO",
            machine ? @"YES" : @"NO", human ? @"YES" : @"NO",
            [text rangeOfString:@"iPhone" options:NSCaseInsensitiveSearch].location != NSNotFound ? @"YES" : @"NO"];
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

static NSString *b7_deviceValueSummary(NSString *key, id value) {
    NSString *normalized = b4_normalizedKey(key);
    if ([normalized containsString:@"devicename"] ||
        [normalized containsString:@"useragent"] || [normalized isEqualToString:@"ua"])
        return b7_textMarkerSummary(value);
    return b4_deviceScalar(value);
}

static NSString *b7_safeFieldName(id raw) {
    if (![raw isKindOfClass:NSString.class]) return nil;
    NSString *key = raw;
    if (key.length == 0 || key.length > 64) return nil;
    NSRange match = [key rangeOfString:@"^[A-Za-z_][A-Za-z0-9_.\\-\\[\\]]{0,63}$"
                                options:NSRegularExpressionSearch];
    return (match.location == 0 && match.length == key.length) ? key : nil;
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
            summary = b7_deviceValueSummary(key, value);
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
        NSString *key = b7_safeFieldName(item.name);
        if (key.length) [names addObject:key];
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
        else if ([key caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame)
            [parts addObject:[NSString stringWithFormat:@"%@=%@", key, b7_textMarkerSummary(value)]];
        else if ([key caseInsensitiveCompare:@"Content-Type"] == NSOrderedSame)
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
    id json = [NSJSONSerialization JSONObjectWithData:body options:0 error:nil];
    if ([json isKindOfClass:NSDictionary.class]) {
        for (id rawKey in [(NSDictionary *)json allKeys]) {
            NSString *key = b7_safeFieldName(rawKey);
            if (key.length) [keys addObject:key];
            if (keys.count >= 100) break;
        }
    } else {
        for (NSString *piece in [text componentsSeparatedByString:@"&"]) {
            NSString *key = [[piece componentsSeparatedByString:@"="] firstObject];
            key = [key stringByRemovingPercentEncoding] ?: key;
            key = b7_safeFieldName(key);
            if (key.length) [keys addObject:key];
            if (keys.count >= 100) break;
        }
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

static void b4_recordNoThrow(NSString *type, NSString *source, NSString *detail);

// The injected JavaScript never returns response bodies.  It stores only a
// sanitized URL, status/length and booleans describing device-related markers.
static NSString *b6_webProbeScript(void) {
    static NSString *script;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        script =
        @"(function(){try{"
         @"function safeKey(n){n=String(n||'');return n.length<=64&&/[A-Za-z_]/.test(n)&&/^[A-Za-z0-9_.\\-\\[\\]]+$/.test(n)?n:''}"
         @"function clean(u){try{var x=new URL(String(u||''),location.href),k=[];"
         @"x.searchParams.forEach(function(v,n){n=safeKey(n);if(n&&k.indexOf(n)<0&&k.length<80)k.push(n)});"
         @"return x.origin+x.pathname+(k.length?'?keys='+k.join(','):'')}"
         @"catch(e){return String(u||'').split('?')[0]}}"
         @"function scan(s){s=String(s||'');return {"
         @"unknownCN:s.indexOf('未知设备')>=0,unknownIPhone:s.indexOf('Unknown_iPhone')>=0,"
         @"iPhone128:s.indexOf('iPhone12,8')>=0,iPhone147:s.indexOf('iPhone14,7')>=0,"
         @"iPhoneModel:/iPhone[0-9]+,[0-9]+/.test(s),iPhoneHuman:/iPhone\\s+[0-9]+/.test(s),iPhoneWord:/iPhone/i.test(s),"
         @"deviceName:/device[_-]?name/i.test(s),deviceModel:/device[_-]?model/i.test(s),"
         @"deviceType:/device[_-]?type/i.test(s),loginDevice:/login[_-]?device|device[_-]?login/i.test(s),"
         @"currentDevice:s.indexOf('当前设备')>=0}}"
         @"function keysOfBody(body){var out=[],s='',kind=typeof body;try{"
         @"if(body==null)return {kind:'none',len:0,keys:out,markers:scan('')};"
         @"if(typeof body==='string')s=body;else if(window.URLSearchParams&&body instanceof URLSearchParams)s=body.toString();"
         @"else if(window.FormData&&body instanceof FormData){body.forEach(function(v,k){k=safeKey(k);if(k&&out.indexOf(k)<0&&out.length<80)out.push(k)});return {kind:'FormData',len:0,keys:out,markers:scan(out.join(' '))}}"
         @"else return {kind:String(body.constructor&&body.constructor.name||kind),len:Number(body.byteLength||body.size||0),keys:out,markers:scan('')};"
         @"var z=s.length>200000?s.slice(0,200000):s;try{var o=JSON.parse(z);(function walk(v,d){if(!v||d>2)return;if(Array.isArray(v)){v.slice(0,30).forEach(function(x){walk(x,d+1)});return}if(typeof v==='object')Object.keys(v).slice(0,80).forEach(function(k){var q=safeKey(k);if(q&&out.indexOf(q)<0&&out.length<80)out.push(q);walk(v[k],d+1)})})(o,0)}catch(e){z.split('&').slice(0,100).forEach(function(p){var k=p.split('=')[0];try{k=decodeURIComponent(k)}catch(e){}k=safeKey(k);if(k&&out.indexOf(k)<0&&out.length<80)out.push(k)})}"
         @"return {kind:kind,len:s.length,keys:out,markers:scan(z)}}catch(e){return {kind:kind,len:0,keys:out,markers:scan('')}}}"
         @"function deviceRecords(raw,obj){var c={arrays:0,total:0,unknownCN:0,unknownIPhone:0,empty:0,other:0,missing:0};try{if(!obj&&raw)obj=JSON.parse(raw);"
         @"(function walk(v,d){if(!v||d>5)return;if(Array.isArray(v)){v.slice(0,100).forEach(function(x){walk(x,d+1)});return}if(typeof v!=='object')return;Object.keys(v).slice(0,120).forEach(function(k){var x=v[k],nk=String(k).replace(/[^a-z0-9]/ig,'').toLowerCase();if(Array.isArray(x)&&nk.indexOf('devices')>=0){c.arrays++;x.slice(0,100).forEach(function(it){c.total++;if(!it||typeof it!=='object'||!Object.prototype.hasOwnProperty.call(it,'name')){c.missing++;return}var n=it.name;if(n==null||String(n).length===0)c.empty++;else if(String(n).indexOf('未知设备')>=0)c.unknownCN++;else if(String(n).indexOf('Unknown_iPhone')>=0)c.unknownIPhone++;else c.other++})}walk(x,d+1)})})(obj,0)}catch(e){}return c}"
         @"function ua(){var s=String(navigator.userAgent||'');return {len:s.length,unknownIPhone:s.indexOf('Unknown_iPhone')>=0,iPhone128:s.indexOf('iPhone12,8')>=0,iPhone147:s.indexOf('iPhone14,7')>=0,iPhoneModel:/iPhone[0-9]+,[0-9]+/.test(s),iPhoneHuman:/iPhone\\s+[0-9]+/.test(s),iPhoneWord:/iPhone/i.test(s)}}"
         @"if(!window.__bd8){var st={events:[],seen:{},of:window.fetch,xo:null,xs:null};window.__bd8=st;"
         @"st.add=function(kind,url,status,text,obj,req,responseType){try{var u=clean(url),raw=String(text||''),sample=raw.length>2000000?raw.slice(0,2000000):raw,m=scan(sample),dr=deviceRecords(sample,obj),key=kind+'|'+u+'|'+status+'|'+raw.length+'|'+JSON.stringify(m)+'|'+JSON.stringify(req||{});"
         @"if(st.seen[key])return;st.seen[key]=1;st.events.push({kind:kind,url:u,status:Number(status||0),len:raw.length,responseType:String(responseType||''),markers:m,deviceRecords:dr,request:req||{}});"
         @"if(st.events.length>100)st.events.shift()}catch(e){}};"
         @"if(typeof st.of==='function'){window.fetch=function(){var p=st.of.apply(this,arguments);"
         @"var a=arguments[0],o=arguments[1]||{},u=(a&&a.url)||a,m=String(o.method||(a&&a.method)||'GET'),rq=keysOfBody(o.body);rq.method=m;"
         @"Promise.resolve(p).then(function(r){try{var ct=String(r.headers.get('content-type')||'');if(!/json|text|javascript|html|xml/i.test(ct)){st.add('fetch',r.url,r.status,'',null,rq,ct);return;}r.clone().text().then(function(t){var obj=null;try{obj=JSON.parse(t)}catch(e){}st.add('fetch',r.url,r.status,t,obj,rq,ct)}).catch(function(){st.add('fetch',r.url,r.status,'',null,rq,ct)})}catch(e){}});return p}}"
         @"if(window.XMLHttpRequest&&XMLHttpRequest.prototype){st.xo=XMLHttpRequest.prototype.open;st.xs=XMLHttpRequest.prototype.send;"
         @"XMLHttpRequest.prototype.open=function(m,u){this.__bd8u=clean(u);this.__bd8m=String(m||'GET');return st.xo.apply(this,arguments)};"
         @"XMLHttpRequest.prototype.send=function(body){if(!this.__bd8a){this.__bd8a=1;this.__bd8q=keysOfBody(body);this.__bd8q.method=this.__bd8m||'GET';this.addEventListener('loadend',function(){"
         @"var t='',o=null,rt=String(this.responseType||'text');try{if(rt===''||rt==='text')t=String(this.responseText||'');else if(rt==='json'){o=this.response;t=JSON.stringify(o)||''}}catch(e){}st.add('xhr',this.__bd8u||this.responseURL,this.status,t,o,this.__bd8q,rt)})}"
         @"return st.xs.apply(this,arguments)}}"
         @"window.__bd8Restore=function(){try{if(st.of)window.fetch=st.of;if(st.xo)XMLHttpRequest.prototype.open=st.xo;"
         @"if(st.xs)XMLHttpRequest.prototype.send=st.xs;delete window.__bd8;delete window.__bd8Restore}catch(e){}}}"
         @"var bt=document.body?document.body.innerText:'',h=document.documentElement?document.documentElement.innerHTML:'';"
         @"if(bt.length>500000)bt=bt.slice(0,500000);if(h.length>2000000)h=h.slice(0,2000000);var mk=scan(bt+' '+h),rs=[];"
         @"try{(performance.getEntriesByType('resource')||[]).slice(-120).forEach(function(e){rs.push({url:clean(e.name),kind:String(e.initiatorType||'')})})}catch(e){}"
         @"return JSON.stringify({href:clean(location.href),titleLen:String(document.title||'').length,markers:mk,userAgent:ua(),resources:rs,events:window.__bd8.events||[]})"
         @"}catch(e){return JSON.stringify({error:String(e)})}})();";
    });
    return script;
}

static BOOL b6_seenOnce(NSString *key) {
    if (!key.length) return NO;
    BOOL fresh = NO;
    os_unfair_lock_lock(&g_b4Lock);
    @try {
        if (![g_b6WebSeen containsObject:key]) {
            [g_b6WebSeen addObject:key];
            fresh = YES;
        }
    } @finally { os_unfair_lock_unlock(&g_b4Lock); }
    return fresh;
}

static BOOL b6_marker(id markers, NSString *key) {
    return [markers isKindOfClass:NSDictionary.class] && [markers[key] boolValue];
}

static NSString *b6_markerSummary(id markers) {
    return [NSString stringWithFormat:@"unknownCN=%@; Unknown_iPhone=%@; iPhone12,8=%@; iPhone14,7=%@; iPhoneModel=%@; iPhoneHuman=%@; iPhoneWord=%@; device_name=%@; device_model=%@; device_type=%@; login_device=%@; currentDevice=%@",
            b6_marker(markers, @"unknownCN") ? @"YES" : @"NO",
            b6_marker(markers, @"unknownIPhone") ? @"YES" : @"NO",
            b6_marker(markers, @"iPhone128") ? @"YES" : @"NO",
            b6_marker(markers, @"iPhone147") ? @"YES" : @"NO",
            b6_marker(markers, @"iPhoneModel") ? @"YES" : @"NO",
            b6_marker(markers, @"iPhoneHuman") ? @"YES" : @"NO",
            b6_marker(markers, @"iPhoneWord") ? @"YES" : @"NO",
            b6_marker(markers, @"deviceName") ? @"YES" : @"NO",
            b6_marker(markers, @"deviceModel") ? @"YES" : @"NO",
            b6_marker(markers, @"deviceType") ? @"YES" : @"NO",
            b6_marker(markers, @"loginDevice") ? @"YES" : @"NO",
            b6_marker(markers, @"currentDevice") ? @"YES" : @"NO"];
}

static BOOL b6_interestingURL(NSString *url) {
    NSString *x = url.lowercaseString ?: @"";
    for (NSString *term in @[@"device", @"login", @"safe", @"cert", @"account",
                              @"record", @"history", @"passport", @"protect"])
        if ([x containsString:term]) return YES;
    return NO;
}

static void b6_processWebSnapshot(id result) {
    if (!b4_isCapturing() || ![result isKindOfClass:NSString.class]) return;
    @try {
        NSData *data = [(NSString *)result dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *snapshot = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if (![snapshot isKindOfClass:NSDictionary.class]) return;

        NSString *href = [snapshot[@"href"] isKindOfClass:NSString.class] ? snapshot[@"href"] : @"";
        NSDictionary *markers = [snapshot[@"markers"] isKindOfClass:NSDictionary.class] ? snapshot[@"markers"] : @{};
        NSDictionary *ua = [snapshot[@"userAgent"] isKindOfClass:NSDictionary.class] ? snapshot[@"userAgent"] : @{};
        NSString *uaSummary = [NSString stringWithFormat:@"len=%lu; %@", (unsigned long)[ua[@"len"] unsignedIntegerValue], b6_markerSummary(ua)];
        NSString *docKey = [NSString stringWithFormat:@"doc|%@|%@|%@", href, b6_markerSummary(markers), uaSummary];
        if (b6_seenOnce(docKey)) {
            b4_recordNoThrow(@"WEB_DOCUMENT", @"WKWebView DOM snapshot",
                [NSString stringWithFormat:@"url=%@; titleLen=%lu; DOM={%@}; navigator.userAgent={%@}; DOM/HTML/UA text=<not logged>",
                 b4_safeShortString(href), (unsigned long)[snapshot[@"titleLen"] unsignedIntegerValue],
                 b6_markerSummary(markers), uaSummary]);
        }

        for (NSDictionary *item in snapshot[@"resources"] ?: @[]) {
            if (![item isKindOfClass:NSDictionary.class]) continue;
            NSString *url = [item[@"url"] isKindOfClass:NSString.class] ? item[@"url"] : @"";
            NSString *kind = [item[@"kind"] isKindOfClass:NSString.class] ? item[@"kind"] : @"";
            BOOL activeResource = [kind isEqualToString:@"fetch"] || [kind isEqualToString:@"xmlhttprequest"];
            if (!activeResource && !b6_interestingURL(url)) continue;
            NSString *key = [NSString stringWithFormat:@"res|%@|%@", kind, url];
            if (b6_seenOnce(key))
                b4_recordNoThrow(@"WEB_RESOURCE", @"WKWebView performance entries",
                    [NSString stringWithFormat:@"kind=%@; url=%@", b4_safeShortString(kind), b4_safeShortString(url)]);
        }

        for (NSDictionary *item in snapshot[@"events"] ?: @[]) {
            if (![item isKindOfClass:NSDictionary.class]) continue;
            NSString *url = [item[@"url"] isKindOfClass:NSString.class] ? item[@"url"] : @"";
            NSString *kind = [item[@"kind"] isKindOfClass:NSString.class] ? item[@"kind"] : @"";
            NSDictionary *responseMarkers = [item[@"markers"] isKindOfClass:NSDictionary.class] ? item[@"markers"] : @{};
            NSDictionary *request = [item[@"request"] isKindOfClass:NSDictionary.class] ? item[@"request"] : @{};
            NSDictionary *requestMarkers = [request[@"markers"] isKindOfClass:NSDictionary.class] ? request[@"markers"] : @{};
            NSDictionary *records = [item[@"deviceRecords"] isKindOfClass:NSDictionary.class] ? item[@"deviceRecords"] : @{};
            NSArray *requestKeys = [request[@"keys"] isKindOfClass:NSArray.class] ? request[@"keys"] : @[];
            NSString *key = [NSString stringWithFormat:@"net|%@|%@|%@|%@|%@|%@|%@", kind, url,
                             item[@"status"] ?: @0, item[@"len"] ?: @0, b6_markerSummary(responseMarkers),
                             records, requestKeys];
            if (b6_seenOnce(key))
                b4_recordNoThrow(@"WEB_RESPONSE_SHAPE", @"WKWebView fetch/XHR observer",
                    [NSString stringWithFormat:@"kind=%@; url=%@; method=%@; requestBodyKind=%@; requestBodyLen=%@; requestKeys=%@; requestMarkers={%@}; status=%@; responseType=%@; responseLen=%@; responseMarkers={%@}; deviceArrays=%@; deviceTotal=%@; nameUnknownCN=%@; nameUnknownIPhone=%@; nameEmpty=%@; nameOther=%@; nameMissing=%@; request/response body=<not logged>",
                     b4_safeShortString(kind), b4_safeShortString(url), request[@"method"] ?: @"",
                     request[@"kind"] ?: @"", request[@"len"] ?: @0, requestKeys,
                     b6_markerSummary(requestMarkers), item[@"status"] ?: @0,
                     item[@"responseType"] ?: @"", item[@"len"] ?: @0, b6_markerSummary(responseMarkers),
                     records[@"arrays"] ?: @0, records[@"total"] ?: @0,
                     records[@"unknownCN"] ?: @0, records[@"unknownIPhone"] ?: @0,
                     records[@"empty"] ?: @0, records[@"other"] ?: @0, records[@"missing"] ?: @0]);
        }
    } @catch (__unused NSException *e) { }
}

static void b6_collectWebViews(UIView *view, NSMutableArray<WKWebView *> *out) {
    if (!view) return;
    if ([view isKindOfClass:WKWebView.class]) [out addObject:(WKWebView *)view];
    for (UIView *child in view.subviews) b6_collectWebViews(child, out);
}

static NSArray<WKWebView *> *b6_currentWebViews(void) {
    NSMutableArray<WKWebView *> *out = [NSMutableArray array];
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] || scene.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) b6_collectWebViews(window, out);
    }
    return out;
}

static void b6_sampleWebView(WKWebView *webView) {
    if (!b4_isCapturing() || ![webView isKindOfClass:WKWebView.class]) return;
    [webView evaluateJavaScript:b6_webProbeScript() completionHandler:^(id result, NSError *error) {
        if (!error) b6_processWebSnapshot(result);
    }];
}

static void b6_pollWebViews(unsigned generation) {
    if (!b4_isCapturing() || generation != atomic_load_explicit(&g_b4Generation, memory_order_acquire)) return;
    for (WKWebView *webView in b6_currentWebViews()) b6_sampleWebView(webView);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.75 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ b6_pollWebViews(generation); });
}

static void b6_removeWebInstrumentation(void) {
    NSString *cleanup = @"(function(){try{if(window.__bd8Restore)window.__bd8Restore()}catch(e){}})();";
    for (WKWebView *webView in b6_currentWebViews())
        [webView evaluateJavaScript:cleanup completionHandler:nil];
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
    NSUInteger hooks = b4_installedCount();
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!g_b4StatusLabel) return;
        if (b4_isCapturing())
            g_b4StatusLabel.text = [NSString stringWithFormat:@"采集中 H%lu / E%u",
                                    (unsigned long)hooks, MIN(count, kB4MaxEvents)];
        else
            g_b4StatusLabel.text = [NSString stringWithFormat:@"BDDiag8 待采集 H%lu / E%u",
                                    (unsigned long)hooks, MIN(count, kB4MaxEvents)];
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
    for (NSString *term in @[@"sms", @"login", @"dpass", @"captcha", @"verify", @"phone",
                              @"device", @"safe", @"cert", @"account", @"record", @"history"])
        if ([x containsString:term]) return YES;
    return NO;
}

static NSString *b4_privateArgument(NSString *name, id value) {
    return [NSString stringWithFormat:@"%@=<redacted %@>", name, b4_shape(value)];
}

static NSUInteger b4_textLength(id value) {
    return [value isKindOfClass:NSString.class] ? [(NSString *)value length] : 0;
}

static NSString *b7_deviceStringClass(id value) {
    if (![value isKindOfClass:NSString.class]) return b4_shape(value);
    NSString *text = [(NSString *)value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (text.length == 0) return @"empty";
    if ([text isEqualToString:@"未知设备"]) return @"unknown-cn";
    if ([text caseInsensitiveCompare:@"Unknown_iPhone"] == NSOrderedSame) return @"unknown-iphone";
    if ([text caseInsensitiveCompare:@"iPhone"] == NSOrderedSame) return @"generic-iphone";
    if ([text rangeOfString:@"^iPhone[0-9]+,[0-9]+$" options:NSRegularExpressionSearch].location != NSNotFound)
        return @"iphone-machine";
    if ([text rangeOfString:@"^iPhone[[:space:]]+[0-9]+" options:NSRegularExpressionSearch].location != NSNotFound)
        return @"iphone-human";
    if ([text rangeOfString:@"iphone" options:NSCaseInsensitiveSearch].location != NSNotFound)
        return @"iphone-other";
    return @"other-not-logged";
}

static id b4_originalDeviceModel(id helperClass) {
    SEL alias = sel_registerName("bd8orig_deviceModel");
    if (![helperClass respondsToSelector:alias]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(helperClass, alias);
}

static id b6_originalDeviceName(id helperClass) {
    SEL alias = sel_registerName("bd8orig_deviceName");
    if (![helperClass respondsToSelector:alias]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(helperClass, alias);
}

static id b6_originalDeviceType(id helperClass) {
    SEL alias = sel_registerName("bd8orig_deviceType");
    if (![helperClass respondsToSelector:alias]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(helperClass, alias);
}

static NSArray *b8_collectionSnapshot(id value) {
    if ([value isKindOfClass:NSArray.class]) return [(NSArray *)value copy];
    if ([value isKindOfClass:NSSet.class]) return [[(NSSet *)value allObjects] copy];
    return nil;
}

static BOOL b8_decimalString(NSString *value) {
    if (![value isKindOfClass:NSString.class] || value.length == 0) return NO;
    NSCharacterSet *notDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    return [value rangeOfCharacterFromSet:notDigits].location == NSNotFound;
}

static BOOL b8_collectionContainsIndex(id value, NSUInteger index) {
    for (id item in b8_collectionSnapshot(value) ?: @[]) {
        if ([item isKindOfClass:NSNumber.class] && [(NSNumber *)item unsignedIntegerValue] == index) return YES;
        if (b8_decimalString(item) && [(NSString *)item integerValue] == index) return YES;
    }
    return NO;
}

static NSString *b8_indexCollectionSummary(id value) {
    NSArray *items = b8_collectionSnapshot(value);
    if (!items) return [NSString stringWithFormat:@"readable=NO; shape=%@", b4_shape(value)];
    NSMutableArray<NSNumber *> *indexes = [NSMutableArray array];
    NSUInteger otherCount = 0;
    for (id item in items) {
        if ([item isKindOfClass:NSNumber.class]) [indexes addObject:@([(NSNumber *)item unsignedIntegerValue])];
        else if (b8_decimalString(item)) [indexes addObject:@([(NSString *)item integerValue])];
        else otherCount++;
    }
    [indexes sortUsingSelector:@selector(compare:)];
    if (indexes.count > 64) [indexes removeObjectsInRange:NSMakeRange(64, indexes.count - 64)];
    return [NSString stringWithFormat:@"readable=YES; count=%lu; numericIndexes=%@; nonNumericCount=%lu",
            (unsigned long)items.count, indexes, (unsigned long)otherCount];
}

static NSDictionary *b8_readSAPIConfig(void) {
    if (t_b8ConfigDepth > 0) return @{};
    t_b8ConfigDepth++;
    t_b4Suppress++;
    @try {
        Class cls = objc_getClass("SAPILoginParamManager");
        SEL sharedSEL = sel_registerName("sharedInstance");
        id manager = (cls && [cls respondsToSelector:sharedSEL])
            ? ((id (*)(id, SEL))objc_msgSend)(cls, sharedSEL) : nil;
        id except = nil;
        id keys = nil;
        SEL exceptSEL = sel_registerName("deviceInfoExceptIndexArray");
        SEL keysSEL = sel_registerName("loginCookieDeviceInfoKeys");
        if (manager && [manager respondsToSelector:exceptSEL])
            except = ((id (*)(id, SEL))objc_msgSend)(manager, exceptSEL);
        if (manager && [manager respondsToSelector:keysSEL])
            keys = ((id (*)(id, SEL))objc_msgSend)(manager, keysSEL);
        return @{ @"manager": manager ? @"available" : @"missing",
                  @"except": b8_collectionSnapshot(except) ?: NSNull.null,
                  @"keys": b8_collectionSnapshot(keys) ?: NSNull.null };
    } @catch (__unused NSException *e) {
        return @{ @"manager": @"exception", @"except": NSNull.null, @"keys": NSNull.null };
    } @finally {
        t_b4Suppress--;
        t_b8ConfigDepth--;
    }
}

static NSString *b8_keyPresenceSummary(id value) {
    NSArray *items = b8_collectionSnapshot(value);
    if (!items) return [NSString stringWithFormat:@"readable=NO; shape=%@", b4_shape(value)];
    BOOL phoneModel = NO, deviceName = NO;
    NSUInteger nonStringCount = 0;
    for (id item in items) {
        if (![item isKindOfClass:NSString.class]) { nonStringCount++; continue; }
        NSString *key = b4_normalizedKey(item);
        if ([key isEqualToString:@"phonemodel"]) phoneModel = YES;
        if ([key isEqualToString:@"devicename"]) deviceName = YES;
    }
    return [NSString stringWithFormat:@"readable=YES; count=%lu; hasPhoneModel=%@; hasDeviceName=%@; nonStringCount=%lu",
            (unsigned long)items.count, phoneModel ? @"YES" : @"NO", deviceName ? @"YES" : @"NO",
            (unsigned long)nonStringCount];
}

static void b8_recordSAPIConfigOnce(void) {
    if (!b4_isCapturing()) return;
    unsigned generation = atomic_load_explicit(&g_b4Generation, memory_order_acquire);
    if (generation == 0) return;
    unsigned seen = atomic_load_explicit(&g_b8ConfigLoggedGeneration, memory_order_acquire);
    while (seen != generation) {
        if (atomic_compare_exchange_weak_explicit(&g_b8ConfigLoggedGeneration, &seen, generation,
                                                  memory_order_acq_rel, memory_order_acquire)) {
            NSDictionary *config = b8_readSAPIConfig();
            id except = config[@"except"];
            id keys = config[@"keys"];
            b4_recordNoThrow(@"DI_CONFIG_SNAPSHOT", @"SAPILoginParamManager(read-only)",
                [NSString stringWithFormat:@"manager=%@; except={%@}; contains3=%@; contains17=%@; contains27=%@; loginCookieKeys={%@}",
                 config[@"manager"] ?: @"?", b8_indexCollectionSummary(except),
                 b8_collectionContainsIndex(except, 3) ? @"YES" : @"NO",
                 b8_collectionContainsIndex(except, 17) ? @"YES" : @"NO",
                 b8_collectionContainsIndex(except, 27) ? @"YES" : @"NO",
                 b8_keyPresenceSummary(keys)]);
            return;
        }
    }
}

static NSString *b8_sessionHash(id value) {
    if (![value isKindOfClass:NSString.class]) return @"-";
    NSData *data = [(NSString *)value dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
    uint64_t hash = 1469598103934665603ULL ^ atomic_load_explicit(&g_b8HashSalt, memory_order_acquire);
    const uint8_t *bytes = data.bytes;
    for (NSUInteger i = 0; i < data.length; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return [NSString stringWithFormat:@"%016llx", (unsigned long long)hash];
}

static NSString *b8_slotSummary(NSArray<NSString *> *slots, NSUInteger index, id getterValue) {
    BOOL present = index < slots.count;
    id slotValue = present ? slots[index] : nil;
    BOOL slotString = [slotValue isKindOfClass:NSString.class];
    BOOL getterString = [getterValue isKindOfClass:NSString.class];
    BOOL matches = slotString && getterString && [(NSString *)slotValue isEqualToString:(NSString *)getterValue];
    return [NSString stringWithFormat:@"slot%lu={present=%@; len=%lu; empty=%@; hash=%@; getterLen=%lu; getterHash=%@; matchesGetter=%@}",
            (unsigned long)index, present ? @"YES" : @"NO", (unsigned long)b4_textLength(slotValue),
            (slotString && [(NSString *)slotValue length] == 0) ? @"YES" : @"NO", b8_sessionHash(slotValue),
            (unsigned long)b4_textLength(getterValue), b8_sessionHash(getterValue), matches ? @"YES" : @"NO"];
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
        SEL alias = sel_registerName("bd8orig_sendSmsCodeWithCountryCode:phoneNumber:captcha:extraParams:success:failure:");
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
        SEL alias = sel_registerName("bd8orig_smsLoginWithCountryCode:phoneNumber:smsCode:encryptedId:extraParams:success:verify:failure:");
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
        SEL alias = sel_registerName("bd8orig_getDpassWithMobile:captcha:extraParams:success:failure:");
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
        SEL alias = sel_registerName("bd8orig_loginWithMobile:dpass:extraParams:success:failure:");
        ((void (*)(id, SEL, id, id, id, id, id))objc_msgSend)
            (self, alias, mobile, dpass, extra, success, failure);
    } @finally { if (active) t_b4LoginDepth--; }
}

static id b4_baseParams(id self, SEL command, id interfaceName) {
    SEL alias = sel_registerName("bd8orig_baseParamsForSMSLoginWithInterface:");
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
    SEL alias = sel_registerName("bd8orig_deviceModel");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing() && t_b4DIDepth > 0) @try {
        NSString *shown = [result isKindOfClass:NSString.class] ? b4_safeShortString(result) : b4_shape(result);
        b4_recordNoThrow(@"DI_DEVICE_MODEL", b4_source(self, command),
                         [NSString stringWithFormat:@"value=%@; DIdepth=%d", shown, t_b4DIDepth]);
    } @catch (__unused NSException *e) { }
    return result;
}

static id b6_deviceName(id self, SEL command) {
    SEL alias = sel_registerName("bd8orig_deviceName");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing() && t_b4DIDepth > 0) @try {
        b4_recordNoThrow(@"DI_DEVICE_NAME", b4_source(self, command),
            [NSString stringWithFormat:@"length=%lu; class=%@; sessionHash=%@; value=<not logged>",
             (unsigned long)b4_textLength(result), b7_deviceStringClass(result), b8_sessionHash(result)]);
    } @catch (__unused NSException *e) { }
    return result;
}

static id b6_deviceType(id self, SEL command) {
    SEL alias = sel_registerName("bd8orig_deviceType");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing() && t_b4DIDepth > 0) @try {
        b4_recordNoThrow(@"DI_DEVICE_TYPE", b4_source(self, command),
            [NSString stringWithFormat:@"length=%lu; sessionHash=%@; value=<not logged>",
             (unsigned long)b4_textLength(result), b8_sessionHash(result)]);
    } @catch (__unused NSException *e) { }
    return result;
}

static BOOL b5_notAllowedGetDI(id self, SEL command, NSUInteger index) {
    SEL alias = sel_registerName("bd8orig_notAllowedGetDI:");
    BOOL result = ((BOOL (*)(id, SEL, NSUInteger))objc_msgSend)(self, alias, index);
    if (b4_isCapturing() && (index == 3 || index == 17 || index == 27)) @try {
        b8_recordSAPIConfigOnce();
        NSDictionary *config = b8_readSAPIConfig();
        id except = config[@"except"];
        BOOL exceptReadable = b8_collectionSnapshot(except) != nil;
        BOOL exceptContains = b8_collectionContainsIndex(except, index);
        NSString *field = index == 3 ? @"deviceModel" : (index == 17 ? @"deviceType" : @"deviceName");
        NSString *sourceHint = !result ? @"none" : (exceptContains ? @"deviceInfoExceptIndexArray" :
                                    (exceptReadable ? @"dt_params(inferred)" : @"dt_params-or-config-unreadable"));
        b4_recordNoThrow(@"DI_DEVICE_FIELD_EXCLUSION", b4_source(self, command),
                         [NSString stringWithFormat:@"index=%lu(%@); effectiveExcluded=%@; exceptArrayReadable=%@; exceptArrayContains=%@; exclusionSource=%@; DIdepth=%d",
                          (unsigned long)index, field, result ? @"YES" : @"NO",
                          exceptReadable ? @"YES" : @"NO", exceptContains ? @"YES" : @"NO",
                          sourceHint, t_b4DIDepth]);
    } @catch (__unused NSException *e) { }
    return result;
}

static id b8_valueForDI(id self, SEL command, NSUInteger index, id defaultValue) {
    SEL alias = sel_registerName("bd8orig_valueForDIWithIdx:def:");
    id result = ((id (*)(id, SEL, NSUInteger, id))objc_msgSend)(self, alias, index, defaultValue);
    if (b4_isCapturing() && (index == 3 || index == 17 || index == 27)) @try {
        NSString *field = index == 3 ? @"deviceModel" : (index == 17 ? @"deviceType" : @"deviceName");
        b4_recordNoThrow(@"DI_VALUE_FOR_INDEX", b4_source(self, command),
            [NSString stringWithFormat:@"index=%lu(%@); resultLen=%lu; resultEmpty=%@; resultHash=%@; defaultShape=%@; value=<not logged>",
             (unsigned long)index, field, (unsigned long)b4_textLength(result),
             ([result isKindOfClass:NSString.class] && [(NSString *)result length] == 0) ? @"YES" : @"NO",
             b8_sessionHash(result), b4_shape(defaultValue)]);
    } @catch (__unused NSException *e) { }
    return result;
}

static id b5_plainDeviceInfo(id self, SEL command, id interfaceName) {
    BOOL active = b4_isCapturing();
    if (active) t_b4DIDepth++;
    id result = nil;
    @try {
        SEL alias = sel_registerName("bd8orig_plainDeviceInfoWithInterface:");
        result = ((id (*)(id, SEL, id))objc_msgSend)(self, alias, interfaceName);
    } @finally { if (active) t_b4DIDepth--; }
    if (active) @try {
        b8_recordSAPIConfigOnce();
        id model = b4_originalDeviceModel(self);
        id deviceName = b6_originalDeviceName(self);
        id deviceType = b6_originalDeviceType(self);
        BOOL comparable = [result isKindOfClass:NSString.class] && [model isKindOfClass:NSString.class] &&
                          [(NSString *)model length] > 0;
        BOOL contains = comparable && [(NSString *)result rangeOfString:(NSString *)model].location != NSNotFound;
        BOOL containsName = [result isKindOfClass:NSString.class] && [deviceName isKindOfClass:NSString.class] &&
                            [(NSString *)deviceName length] > 0 &&
                            [(NSString *)result rangeOfString:(NSString *)deviceName].location != NSNotFound;
        BOOL containsType = [result isKindOfClass:NSString.class] && [deviceType isKindOfClass:NSString.class] &&
                             [(NSString *)deviceType length] > 0 &&
                             [(NSString *)result rangeOfString:(NSString *)deviceType].location != NSNotFound;
        NSArray<NSString *> *slots = [result isKindOfClass:NSString.class]
            ? [(NSString *)result componentsSeparatedByString:[NSString stringWithFormat:@"%C", (unichar)1]] : @[];
        b4_recordNoThrow(@"DI_PLAIN_DEVICE_CHECK", b4_source(self, command),
            [NSString stringWithFormat:@"interface=%@; plainLen=%lu; slotCount=%lu; model=%@; comparable=%@; containsModel=%@; deviceNameLen=%lu; containsDeviceName=%@; deviceTypeLen=%lu; containsDeviceType=%@; %@; %@; %@; plaintext=<not logged>",
             [interfaceName isKindOfClass:NSString.class] ? b4_safeShortString(interfaceName) : b4_shape(interfaceName),
             (unsigned long)b4_textLength(result), (unsigned long)slots.count,
             [model isKindOfClass:NSString.class] ? b4_safeShortString(model) : b4_shape(model),
             comparable ? @"YES" : @"NO", contains ? @"YES" : @"NO",
             (unsigned long)b4_textLength(deviceName), containsName ? @"YES" : @"NO",
             (unsigned long)b4_textLength(deviceType), containsType ? @"YES" : @"NO",
             b8_slotSummary(slots, 3, model), b8_slotSummary(slots, 17, deviceType),
             b8_slotSummary(slots, 27, deviceName)]);
    } @catch (__unused NSException *e) { }
    return result;
}

static id b5_generateDeviceInfo(id self, SEL command, id plainString) {
    SEL alias = sel_registerName("bd8orig_generateDeviceInfoWithPlainString:");
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
        SEL alias = sel_registerName("bd8orig_deviceInfoStringWithInterface:");
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
    SEL alias = sel_registerName("bd8orig_interfaceForLogin");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"DI_LOGIN_INTERFACE", b4_source(self, command),
            [result isKindOfClass:NSString.class] ? b4_safeShortString(result) : b4_shape(result));
    } @catch (__unused NSException *e) { }
    return result;
}

static id b5_deviceInfoForLogin(id self, SEL command) {
    SEL alias = sel_registerName("bd8orig_deviceInfoForLogin");
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
    SEL alias = sel_registerName("bd8orig_requestWithMethod:path:parameters:");
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
    SEL alias = sel_registerName("bd8orig_requestWithMethod:path:timeout:parameters:");
    id result = ((id (*)(id, SEL, id, id, double, id))objc_msgSend)
        (self, alias, method, path, timeout, parameters);
    if (relevant)
        @try { b4_recordNoThrow(@"REQUEST_PRE_ENCODE", b4_source(self, command),
            [NSString stringWithFormat:@"%@; builtRequest={%@}", before ?: @"", b4_requestSummary(result)]); }
        @catch (__unused NSException *e) { }
    return result;
}

static id b4_smsLoginURL(id self, SEL command) {
    SEL alias = sel_registerName("bd8orig_smsLoginURLString");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"SMS_URL", b4_source(self, command), b4_urlSummary(result));
    } @catch (__unused NSException *e) { }
    return result;
}

static id b4_smsGetLoginURL(id self, SEL command) {
    SEL alias = sel_registerName("bd8orig_smsGetLoginURL");
    id result = ((id (*)(id, SEL))objc_msgSend)(self, alias);
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"SMS_URL", b4_source(self, command), b4_urlSummary(result));
    } @catch (__unused NSException *e) { }
    return result;
}

// ---- public WKWebView navigation wrappers ----
static id b6_webLoadRequest(id self, SEL command, id request) {
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"WEB_LOAD_REQUEST", b4_source(self, command), b4_requestSummary(request));
    } @catch (__unused NSException *e) { }
    SEL alias = sel_registerName("bd8orig_loadRequest:");
    id result = ((id (*)(id, SEL, id))objc_msgSend)(self, alias, request);
    if (b4_isCapturing()) dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.20 * NSEC_PER_SEC)),
                                         dispatch_get_main_queue(), ^{ b6_sampleWebView((WKWebView *)self); });
    return result;
}

static id b6_webLoadHTML(id self, SEL command, id html, id baseURL) {
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"WEB_LOAD_HTML", b4_source(self, command),
            [NSString stringWithFormat:@"htmlLen=%lu; baseURL=%@; HTML=<not logged>",
             (unsigned long)b4_textLength(html), b4_urlSummary(baseURL)]);
    } @catch (__unused NSException *e) { }
    SEL alias = sel_registerName("bd8orig_loadHTMLString:baseURL:");
    id result = ((id (*)(id, SEL, id, id))objc_msgSend)(self, alias, html, baseURL);
    if (b4_isCapturing()) dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.20 * NSEC_PER_SEC)),
                                         dispatch_get_main_queue(), ^{ b6_sampleWebView((WKWebView *)self); });
    return result;
}

static id b6_webReload(id self, SEL command) {
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"WEB_RELOAD", b4_source(self, command),
                         [NSString stringWithFormat:@"url=%@", b4_urlSummary([(WKWebView *)self URL])]);
    } @catch (__unused NSException *e) { }
    SEL alias = sel_registerName("bd8orig_reload");
    return ((id (*)(id, SEL))objc_msgSend)(self, alias);
}

static id b6_webGoBack(id self, SEL command) {
    if (b4_isCapturing()) @try {
        b4_recordNoThrow(@"WEB_GO_BACK", b4_source(self, command),
                         [NSString stringWithFormat:@"fromURL=%@", b4_urlSummary([(WKWebView *)self URL])]);
    } @catch (__unused NSException *e) { }
    SEL alias = sel_registerName("bd8orig_goBack");
    return ((id (*)(id, SEL))objc_msgSend)(self, alias);
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
        b4_updateStatusAsync();
        return YES;
    } @finally { os_unfair_lock_unlock(&g_b4InstallLock); }
}

static void b4_installAll(void) {
    b4_installExact("SAPILoginService", NO,
        "sendSmsCodeWithCountryCode:phoneNumber:captcha:extraParams:success:failure:",
        "bd8orig_sendSmsCodeWithCountryCode:phoneNumber:captcha:extraParams:success:failure:",
        (IMP)b4_sendSms, 'v', "@@@@@@");
    b4_installExact("SAPILoginService", NO,
        "smsLoginWithCountryCode:phoneNumber:smsCode:encryptedId:extraParams:success:verify:failure:",
        "bd8orig_smsLoginWithCountryCode:phoneNumber:smsCode:encryptedId:extraParams:success:verify:failure:",
        (IMP)b4_smsLogin, 'v', "@@@@@@@@");
    b4_installExact("SAPILoginService", NO,
        "baseParamsForSMSLoginWithInterface:", "bd8orig_baseParamsForSMSLoginWithInterface:",
        (IMP)b4_baseParams, '@', "@");

    const char *loginClasses[] = {"SAPILoginService", "SAPILoginManager"};
    for (size_t i = 0; i < sizeof(loginClasses) / sizeof(loginClasses[0]); i++) {
        const char *name = loginClasses[i];
        b4_installExact(name, NO, "getDpassWithMobile:captcha:extraParams:success:failure:",
            "bd8orig_getDpassWithMobile:captcha:extraParams:success:failure:",
            (IMP)b4_getDpass, 'v', "@@@@@");
        b4_installExact(name, NO, "loginWithMobile:dpass:extraParams:success:failure:",
            "bd8orig_loginWithMobile:dpass:extraParams:success:failure:",
            (IMP)b4_loginWithMobile, 'v', "@@@@@");
    }

    b4_installExact("SAPIHTTPRequest", YES, "requestWithMethod:path:parameters:",
        "bd8orig_requestWithMethod:path:parameters:", (IMP)b4_request3, '@', "@@@");
    b4_installExact("SAPIHTTPRequest", YES, "requestWithMethod:path:timeout:parameters:",
        "bd8orig_requestWithMethod:path:timeout:parameters:", (IMP)b4_request4, '@', "@@d@");
    b4_installExact("SAPIURLHelper", YES, "smsLoginURLString", "bd8orig_smsLoginURLString",
        (IMP)b4_smsLoginURL, '@', "");
    b4_installExact("SAPIURLHelper", YES, "smsGetLoginURL", "bd8orig_smsGetLoginURL",
        (IMP)b4_smsGetLoginURL, '@', "");

    b4_installExact("SAPIDeviceInfoHelper", YES, "deviceModel", "bd8orig_deviceModel",
        (IMP)b5_deviceModel, '@', "");
    b4_installExact("SAPIDeviceInfoHelper", YES, "deviceName", "bd8orig_deviceName",
        (IMP)b6_deviceName, '@', "");
    b4_installExact("SAPIDeviceInfoHelper", YES, "deviceType", "bd8orig_deviceType",
        (IMP)b6_deviceType, '@', "");
    b4_installExact("SAPIDeviceInfoHelper", YES, "notAllowedGetDI:", "bd8orig_notAllowedGetDI:",
        (IMP)b5_notAllowedGetDI, 'B', "Q");
    b4_installExact("SAPIDeviceInfoHelper", YES, "valueForDIWithIdx:def:",
        "bd8orig_valueForDIWithIdx:def:", (IMP)b8_valueForDI, '@', "Q@");
    b4_installExact("SAPIDeviceInfoHelper", YES, "plainDeviceInfoWithInterface:",
        "bd8orig_plainDeviceInfoWithInterface:", (IMP)b5_plainDeviceInfo, '@', "@");
    b4_installExact("SAPIDeviceInfoHelper", YES, "generateDeviceInfoWithPlainString:",
        "bd8orig_generateDeviceInfoWithPlainString:", (IMP)b5_generateDeviceInfo, '@', "@");
    b4_installExact("SAPIDeviceInfoHelper", YES, "deviceInfoStringWithInterface:",
        "bd8orig_deviceInfoStringWithInterface:", (IMP)b5_deviceInfoString, '@', "@");
    b4_installExact("SAPIDeviceInfoHelper", YES, "interfaceForLogin", "bd8orig_interfaceForLogin",
        (IMP)b5_interfaceForLogin, '@', "");
    b4_installExact("SAPIDeviceInfoHelper", YES, "deviceInfoForLogin", "bd8orig_deviceInfoForLogin",
        (IMP)b5_deviceInfoForLogin, '@', "");

    b4_installExact("WKWebView", NO, "loadRequest:", "bd8orig_loadRequest:",
        (IMP)b6_webLoadRequest, '@', "@");
    b4_installExact("WKWebView", NO, "loadHTMLString:baseURL:", "bd8orig_loadHTMLString:baseURL:",
        (IMP)b6_webLoadHTML, '@', "@@");
    b4_installExact("WKWebView", NO, "reload", "bd8orig_reload",
        (IMP)b6_webReload, '@', "");
    b4_installExact("WKWebView", NO, "goBack", "bd8orig_goBack",
        (IMP)b6_webGoBack, '@', "");
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

@interface BDDiag8Store : NSObject
+ (void)startCapture;
+ (void)stopCapture;
+ (void)exportReport;
+ (NSString *)buildReport;
@end

@interface BDDiag8Window : UIWindow @end
@implementation BDDiag8Window
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    return (hit == self || hit == self.rootViewController.view) ? nil : hit;
}
@end

@implementation BDDiag8Store
+ (void)startCapture {
    dispatch_async(dispatch_get_main_queue(), ^{
        b4_installAll();
        unsigned generation;
        uint64_t salt = 0;
        arc4random_buf(&salt, sizeof(salt));
        if (salt == 0) salt = 0xbdd1a68069600008ULL;
        os_unfair_lock_lock(&g_b4Lock);
        @try {
            atomic_store_explicit(&g_b4Capturing, NO, memory_order_release);
            generation = atomic_fetch_add_explicit(&g_b4Generation, 1, memory_order_acq_rel) + 1;
            [g_b4Events removeAllObjects];
            [g_b6WebSeen removeAllObjects];
            atomic_store_explicit(&g_b4EventCount, 0, memory_order_release);
            atomic_store_explicit(&g_b4EventCapReached, NO, memory_order_release);
            atomic_store_explicit(&g_b8HashSalt, salt, memory_order_release);
            g_b4StartAt = [NSDate date].timeIntervalSince1970;
            atomic_store_explicit(&g_b4Capturing, YES, memory_order_release);
        } @finally { os_unfair_lock_unlock(&g_b4Lock); }
        b8_recordSAPIConfigOnce();
        b4_updateStatusAsync();
        b6_pollWebViews(generation);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kB8CaptureSeconds * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            BOOL stopped = NO;
            os_unfair_lock_lock(&g_b4Lock);
            @try {
                if (generation == atomic_load_explicit(&g_b4Generation, memory_order_relaxed))
                    stopped = atomic_exchange_explicit(&g_b4Capturing, NO, memory_order_acq_rel);
            } @finally { os_unfair_lock_unlock(&g_b4Lock); }
            if (stopped) {
                b6_removeWebInstrumentation();
                if (g_b4StatusLabel)
                    g_b4StatusLabel.text = [NSString stringWithFormat:@"自动停 H%lu / E%u 点导出",
                        (unsigned long)b4_installedCount(),
                        MIN(atomic_load_explicit(&g_b4EventCount, memory_order_acquire), kB4MaxEvents)];
            }
        });
    });
}

+ (void)stopCapture {
    os_unfair_lock_lock(&g_b4Lock);
    @try { atomic_store_explicit(&g_b4Capturing, NO, memory_order_release); }
    @finally { os_unfair_lock_unlock(&g_b4Lock); }
    if ([NSThread isMainThread]) b6_removeWebInstrumentation();
    else dispatch_async(dispatch_get_main_queue(), ^{ b6_removeWebInstrumentation(); });
    if (g_b4StatusLabel)
        g_b4StatusLabel.text = [NSString stringWithFormat:@"结束 H%lu / E%u 点导出",
                                (unsigned long)b4_installedCount(),
                                MIN(atomic_load_explicit(&g_b4EventCount, memory_order_acquire), kB4MaxEvents)];
}

+ (NSString *)buildReport {
    NSArray<NSDictionary *> *events;
    NSArray<NSString *> *installNotes;
    NSUInteger installedCount = 0;
    os_unfair_lock_lock(&g_b4Lock);
    @try {
        events = [[NSArray alloc] initWithArray:g_b4Events copyItems:YES];
        installNotes = [g_b4InstallNotes copy];
        installedCount = g_b4Installed.count;
    } @finally { os_unfair_lock_unlock(&g_b4Lock); }

    NSBundle *bundle = NSBundle.mainBundle;
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"BDDiag8 百度极速版 6.96.0 SAPI 设备字段排除链路定点只读探针报告\n"];
    [out appendFormat:@"生成时间: %@\n", [NSDate date]];
    [out appendFormat:@"Bundle ID: %@\n", bundle.bundleIdentifier ?: @""];
    [out appendFormat:@"App 版本: %@ (build %@)\n",
        bundle.infoDictionary[@"CFBundleShortVersionString"] ?: @"",
        bundle.infoDictionary[@"CFBundleVersion"] ?: @""];
    [out appendFormat:@"主程序 LC_UUID: %@\n", b4_mainExecutableUUID()];
    [out appendFormat:@"已安装精确 Hook: %lu | 采集事件: %lu | 事件封顶: %@\n",
        (unsigned long)installedCount, (unsigned long)events.count,
        atomic_load_explicit(&g_b4EventCapReached, memory_order_acquire) ? @"是" : @"否"];
    [out appendString:@"隐私说明: 手机号/验证码/Cookie/Token/设备ID、DI 明文、UA 全文、HTML、请求与响应正文均不记录；字段哈希使用每次采集随机盐，仅用于本次日志内比对。\n\n"];
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
        [out appendString:@"（采集窗口内未命中；请先点开始，直接进入登录设备管理和未知设备详情；本轮无需退出或换号。）\n"];
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
            [NSString stringWithFormat:@"BDDiag8_log_%@.txt", [formatter stringFromDate:[NSDate date]]]];
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

static BDDiag8Window *g_b4Window = nil;
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
            BDDiag8Window *window = [[BDDiag8Window alloc] initWithWindowScene:windowScene];
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
            status.text = [NSString stringWithFormat:@"BDDiag8 待采集 H%lu / E%u",
                           (unsigned long)b4_installedCount(),
                           MIN(atomic_load_explicit(&g_b4EventCount, memory_order_acquire), kB4MaxEvents)];
            g_b4StatusLabel = status;
            [panel addSubview:status];

            UIButton *start = [UIButton buttonWithType:UIButtonTypeSystem];
            start.frame = CGRectMake(8, 30, 78, 34);
            start.backgroundColor = [[UIColor systemGreenColor] colorWithAlphaComponent:0.9];
            [start setTitle:@"开始采集" forState:UIControlStateNormal];
            [start setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            start.titleLabel.font = [UIFont boldSystemFontOfSize:13];
            start.layer.cornerRadius = 7;
            [start addTarget:BDDiag8Store.class action:@selector(startCapture) forControlEvents:UIControlEventTouchUpInside];

            UIButton *export = [UIButton buttonWithType:UIButtonTypeSystem];
            export.frame = CGRectMake(92, 30, 78, 34);
            export.backgroundColor = [[UIColor systemBlueColor] colorWithAlphaComponent:0.9];
            [export setTitle:@"结束导出" forState:UIControlStateNormal];
            [export setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            export.titleLabel.font = [UIFont boldSystemFontOfSize:13];
            export.layer.cornerRadius = 7;
            [export addTarget:BDDiag8Store.class action:@selector(exportReport) forControlEvents:UIControlEventTouchUpInside];

            UILabel *tip = [[UILabel alloc] initWithFrame:CGRectMake(8, 68, 162, 34)];
            tip.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.82];
            tip.font = [UIFont systemFontOfSize:9];
            tip.numberOfLines = 2;
            tip.text = @"先开始，直接进设备记录/详情\n本轮无需退出或换号；300秒停";
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

__attribute__((constructor)) static void bddiag8_entry(void) {
    @autoreleasepool {
        NSBundle *bundle = NSBundle.mainBundle;
        NSString *bundleID = bundle.bundleIdentifier ?: @"";
        if ([bundle.bundlePath containsString:@".appex/"] ||
            ![bundleID isEqualToString:@"com.baidu.BaiduMobileInfo"]) return;

        Dl_info info;
        memset(&info, 0, sizeof(info));
        if (dladdr((void *)&bddiag8_entry, &info) && info.dli_fbase) {
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
        g_b6WebSeen = [NSMutableSet set];
        _dyld_register_func_for_add_image(b4_imageAdded);
        b4_installAll();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ b4_float(); });
    }
}
