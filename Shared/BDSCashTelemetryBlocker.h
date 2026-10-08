#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

static NSString * const BDSCashTelemetryHost = @"h2tcbox.baidu.com";
static NSString * const BDSCashTelemetryPath = @"/ztbox";

// 运行期开关。以前拦截逻辑从不回头看开关：装上以后只能重启才能停。
// 现在判定入口每次请求都问一次，关掉立即恢复原上报行为，开也不用重启。
// 用函数指针而不是 extern 全局量，保持这个头文件自包含（管理器也包含它，
// 但不使用拦截功能，两者之间不需要新增链接依赖）。
static BOOL (*BDSCashTelemetrySwitchProvider)(void) = NULL;

static BOOL BDSCashTelemetrySwitchIsOn(void) {
    return BDSCashTelemetrySwitchProvider ? BDSCashTelemetrySwitchProvider() : NO;
}

static BOOL BDSCashTelemetryRequestIsTarget(NSURLRequest *request) {
    if (!BDSCashTelemetrySwitchIsOn()) return NO;
    if (!request.URL || ![request.HTTPMethod.uppercaseString isEqualToString:@"GET"]) return NO;
    if (![request.URL.scheme.lowercaseString isEqualToString:@"https"]) return NO;
    if (![request.URL.host.lowercaseString isEqualToString:BDSCashTelemetryHost]) return NO;
    if (![request.URL.path isEqualToString:BDSCashTelemetryPath]) return NO;

    NSURLComponents *components = [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];
    NSString *action = nil;
    NSString *dataValue = nil;
    for (NSURLQueryItem *item in components.queryItems) {
        if ([item.name isEqualToString:@"action"] && !action) action = item.value;
        if ([item.name isEqualToString:@"data"] && !dataValue) dataValue = item.value;
    }
    if (![action isEqualToString:@"zpblog"] || !dataValue.length) return NO;

    NSData *data = [dataValue dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    if (![json isKindOfClass:NSDictionary.class]) return NO;
    NSDictionary *actionData = json[@"actiondata"];
    NSDictionary *content = [actionData isKindOfClass:NSDictionary.class] ? actionData[@"content"] : nil;
    NSDictionary *ext = [content isKindOfClass:NSDictionary.class] ? content[@"ext"] : nil;
    if (![actionData isKindOfClass:NSDictionary.class] ||
        ![content isKindOfClass:NSDictionary.class] ||
        ![ext isKindOfClass:NSDictionary.class]) return NO;

    id eventID = actionData[@"id"];
    id page = content[@"page"];
    id type = content[@"type"];
    id amount = ext[@"num"];
    BOOL amountTypeOK = [amount isKindOfClass:NSString.class] || [amount isKindOfClass:NSNumber.class];
    return [[eventID description] isEqualToString:@"10290"] &&
           [page isKindOfClass:NSString.class] && [page isEqualToString:@"y_mission_index"] &&
           [type isKindOfClass:NSString.class] && [type isEqualToString:@"c_pv"] &&
           amountTypeOK;
}

// 命中记录的前向声明（实现在文件下方，startLoading 里要用）
static NSString *BDSCashHitLogPath(void);
static NSString *BDSZtboxObsLogPath(void);
static NSString *BDSAllObsLogPath(void);
static NSString *BDSWebProbeLogPath(void);
static void BDSWebProbeStore(NSString *json);
static NSString *BDSCurrentSpoofSystemVersion(void);
static void BDSCashRecordHit(NSString *source, NSString *url);
static void BDSZtboxObserve(NSString *source, NSString *url);
static void BDSAllObserve(NSString *source, NSString *url);
static NSDictionary *BDSZtboxExtract(NSString *url);
static NSArray<NSString *> *BDSAmountLikeNumbers(NSString *url);
static void BDSCashInstallHitHandler(WKUserContentController *ucc);

@interface BDSCashTelemetryBlockProtocol : NSURLProtocol
@end

@implementation BDSCashTelemetryBlockProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    return BDSCashTelemetryRequestIsTarget(request);
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request { return request; }
+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [super requestIsCacheEquivalent:a toRequest:b];
}
- (void)startLoading {
    BDSCashRecordHit(@"native", self.request.URL.absoluteString ?: @"");
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc]
        initWithURL:self.request.URL
        statusCode:204
        HTTPVersion:@"HTTP/1.1"
        headerFields:@{@"Cache-Control": @"no-store", @"Content-Length": @"0"}];
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocolDidFinishLoading:self];
}
- (void)stopLoading {}
@end

// 注入脚本一次性写入，无法撤回，因此它在每次请求时都重新问一遍开关：
// 关掉开关后新发起的上报立即放行，不必重启。
// 判定条件与原生侧完全一致：只拦已核实的那一个金额浏览埋点。
static NSString * const BDSCashTelemetryBlockScript = @
"(function(){"
"if(window.__bdsCashBlockInstalled)return;"
"function __bdsCashHit(u){try{window.webkit.messageHandlers.bdsCashHit.postMessage(u||'');}catch(x){}}"
// 网页侧自检：把网页「真实读到」的值原样回报，用于对比注入是否生效
// 伪装值：由原生通过 window.__bdsWebSpoof 注入（{sv_under, sv_dot}）
"function __bdsRewriteUA(u){"
"try{"
"var s=window.__bdsWebSpoof;"
"if(!s||!s.sv_under||!u)return u;"
"var out=String(u);"
// CPU iPhone OS 16_7_2 like  ->  CPU iPhone OS 16_0 like
"out=out.replace(/CPU iPhone OS [0-9_]+ like/g,'CPU iPhone OS '+s.sv_under+' like');"
// appVersion 里的 OS 16_7_2
"out=out.replace(/CPU iPhone OS [0-9_]+ like/g,'CPU iPhone OS '+s.sv_under+' like');"
// (Baidu; P2 16.7.2)
"if(s.sv_dot){out=out.replace(/\(Baidu; P2 [0-9.]+/g,'(Baidu; P2 '+s.sv_dot);}"
"return out;"
"}catch(x){return u;}"
"}"
"try{"
"var _ua=Object.getOwnPropertyDescriptor(Navigator.prototype,'userAgent');"
"if(_ua&&_ua.get){Object.defineProperty(Navigator.prototype,'userAgent',{get:function(){return __bdsRewriteUA(_ua.get.call(this));},configurable:true});}"
"}catch(x){}"
"try{"
"var _av=Object.getOwnPropertyDescriptor(Navigator.prototype,'appVersion');"
"if(_av&&_av.get){Object.defineProperty(Navigator.prototype,'appVersion',{get:function(){return __bdsRewriteUA(_av.get.call(this));},configurable:true});}"
"}catch(x){}"
// 屏幕「上报值」改写：只动 screen.*，绝不动 window.innerWidth/Height（布局用后者）
"function __bdsDefineScreen(prop,val){"
"try{"
"var d=Object.getOwnPropertyDescriptor(Screen.prototype,prop);"
"if(!d||!d.get)return;"
"Object.defineProperty(Screen.prototype,prop,{get:function(){var s=window.__bdsWebSpoof;if(!s||!s.sw)return d.get.call(this);return val(s);},configurable:true});"
"}catch(x){}"
"}"
"__bdsDefineScreen('width',function(s){return s.sw;});"
"__bdsDefineScreen('height',function(s){return s.sh;});"
"__bdsDefineScreen('availWidth',function(s){return s.sw;});"
"__bdsDefineScreen('availHeight',function(s){return s.sh;});"
"try{"
"var _dpr=Object.getOwnPropertyDescriptor(window,'devicePixelRatio');"
"Object.defineProperty(window,'devicePixelRatio',{get:function(){var s=window.__bdsWebSpoof;if(!s||!s.sc)return _dpr?_dpr.get.call(window):1;return s.sc;},configurable:true});"
"}catch(x){}"
"function __bdsProbeWeb(){"
"try{"
"var o={};"
"o.ua=navigator.userAgent||'';"
"o.appVersion=navigator.appVersion||'';"
"o.spoof=(window.__bdsWebSpoof?JSON.stringify(window.__bdsWebSpoof):'(无)');"
"o.platform=navigator.platform||'';"
"o.screenW=screen.width;o.screenH=screen.height;"
"o.availW=screen.availWidth;o.availH=screen.availHeight;"
"o.dpr=window.devicePixelRatio;"
"o.innerW=window.innerWidth;o.innerH=window.innerHeight;"
"o.href=location.href;"
"window.webkit.messageHandlers.bdsWebProbe.postMessage(JSON.stringify(o));"
"}catch(x){}"
"}"
"try{if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',__bdsProbeWeb);}else{__bdsProbeWeb();}}catch(x){}"
"try{setTimeout(__bdsProbeWeb,1200);}catch(x){}"
"function __bdsObs(u,src){"
"try{"
"var s=String(u&&u.url?u.url:u);"
"if(s.indexOf('baidu')>=0){"
"try{window.webkit.messageHandlers.bdsAllObs.postMessage(src+'|'+s);}catch(x){}"
"}"
"if(s.indexOf('h2tcbox.baidu.com')<0)return;"
"if(s.indexOf('/ztbox')<0)return;"
"var b=hit(s)?'1':'0';"
"window.webkit.messageHandlers.bdsZtboxObs.postMessage(b+'|'+src+'|'+s);"
"}catch(x){}"
"}"
"window.__bdsCashBlockInstalled=true;"
"var blank='data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=';"
"function on(){try{return typeof window.__bdsBlockStatCashTelemetry==='boolean'?window.__bdsBlockStatCashTelemetry:true;}catch(x){return true;}}"
"function hit(v){"
"try{"
"if(!on())return false;"
"var u=v instanceof URL?v:new URL(String(v),document.baseURI);"
"if(u.protocol!=='https:')return false;"
"if(u.hostname.toLowerCase()!=='h2tcbox.baidu.com')return false;"
"if(u.pathname!=='/ztbox')return false;"
"if(u.searchParams.get('action')!=='zpblog')return false;"
"var a=JSON.parse(u.searchParams.get('data')||'null'),ad=a&&a.actiondata,c=ad&&ad.content,e=c&&c.ext;"
"var pid=String(ad&&ad.id),pg=c&&String(c.page),ty=c&&String(c.type);"
"var ok=false;"
// 10290 任务页 / 提现页：type 为 c_pv 开头（含 c_pv / c_pv_mission / c_pv_rule ...）
"if(pid==='10290'&&(pg==='y_mission_index'||pg==='y_mission_withdraw')&&ty&&ty.indexOf('c_pv')===0)ok=true;"
// 17322 活动网页（提现/激励 H5）：整条都拦
"if(pid==='17322')ok=true;"
"if(ok){try{__bdsCashHit(String(v));}catch(x){}}"
"return ok;"
"}catch(x){return false;}"
"}"
"try{"
"var d=Object.getOwnPropertyDescriptor(HTMLImageElement.prototype,'src');"
"if(d&&d.set){"
"var s=d.set;"
"Object.defineProperty(HTMLImageElement.prototype,'src',{get:d.get,set:function(v){"
"try{__bdsObs(v,'img');}catch(x){}"
"try{if(hit(v)){s.call(this,blank);return;}}catch(x){}"
"s.call(this,v);},enumerable:d.enumerable,configurable:d.configurable});"
"}"
"}catch(x){}"
"try{if(navigator.sendBeacon){var sb=navigator.sendBeacon;navigator.sendBeacon=function(u,d){try{__bdsObs(u,'beacon');}catch(x){}try{if(hit(u))return true;}catch(x){}return sb.apply(navigator,arguments);};}}catch(x){}"
"try{if(window.fetch){var f=window.fetch;window.fetch=function(i,o){try{var u=(typeof i==='string'||i instanceof URL)?i:(i&&i.url);__bdsObs(u,'fetch');if(hit(u))return Promise.resolve(new Response('',{status:204,statusText:'No Content'}));}catch(x){}return f.apply(this,arguments);};}}catch(x){}"
"try{var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){try{__bdsObs(u,'xhr');}catch(x){}try{this.__bdsCashHit=hit(u);}catch(x){this.__bdsCashHit=false;}return xo.apply(this,arguments);};"
"var xs=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.send=function(){if(this.__bdsCashHit){try{this.abort();}catch(x){}return;}"
"return xs.apply(this,arguments);};}catch(x){}"
"})();";

static NSString * const BDSCashTelemetryScriptMarker = @"__bdsBlockStatCashTelemetry";

// 脚本开头的 window.xxx=true/false 是开关的“网页侧副本”。
// 同一文档里可能同时存在两份（一份 =true、一份 =false），WKUserScript 按加入顺序
// 执行，后加入的覆盖先加入的，因此最新状态胜出。
// 这里只保证“想要的那一份已经存在”，避免同一配置反复创建 WebView 时无限堆积。
static void BDSEnsureCashTelemetryBlockScript(WKUserContentController *controller, BOOL enabled) {
    if (!controller) return;
    NSString *setting = [NSString stringWithFormat:@"window.%@=%@;", BDSCashTelemetryScriptMarker,
                         enabled ? @"true" : @"false"];
    for (WKUserScript *script in controller.userScripts) {
        if ([script.source hasPrefix:setting]) return;
    }
    NSString *source = [setting stringByAppendingString:BDSCashTelemetryBlockScript];
    WKUserScript *script = [[WKUserScript alloc]
        initWithSource:source
        injectionTime:WKUserScriptInjectionTimeAtDocumentStart
        forMainFrameOnly:NO];
    [controller addUserScript:script];
}

#pragma mark - 金额拦截命中记录

static NSString *BDSCashHitLogPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"bdspoofer_cash_hits.plist"];
}

static NSString *BDSZtboxObsLogPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"bdspoofer_ztbox_obs.plist"];
}

// 从 data= 参数里抠出关心字段（id / page / type / num / ext）
static NSDictionary *BDSZtboxExtract(NSString *url) {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    NSRange r = [url rangeOfString:@"data="];
    if (r.location == NSNotFound) return out;
    NSString *tail = [url substringFromIndex:NSMaxRange(r)];
    NSRange amp = [tail rangeOfString:@"&"];
    if (amp.location != NSNotFound) tail = [tail substringToIndex:amp.location];
    NSString *json = [tail stringByRemovingPercentEncoding] ?: tail;
    NSData *d = [json dataUsingEncoding:NSUTF8StringEncoding];
    id obj = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
    if (![obj isKindOfClass:NSDictionary.class]) {
        out[@"dataRaw"] = json.length > 6000 ? [json substringToIndex:6000] : json;
        return out;
    }
    if (obj[@"cateid"]) out[@"cateid"] = [obj[@"cateid"] description];
    NSDictionary *ad = obj[@"actiondata"];
    if ([ad isKindOfClass:NSDictionary.class]) {
        if (ad[@"id"]) out[@"id"] = [ad[@"id"] description];
        NSDictionary *c = ad[@"content"];
        if ([c isKindOfClass:NSDictionary.class]) {
            if (c[@"page"])  out[@"page"]  = [c[@"page"] description];
            if (c[@"type"])  out[@"type"]  = [c[@"type"] description];
            if (c[@"from"])  out[@"from"]  = [c[@"from"] description];
            if (c[@"value"]) out[@"value"] = [c[@"value"] description];
            NSDictionary *e = c[@"ext"];
            if ([e isKindOfClass:NSDictionary.class]) {
                if (e[@"num"] != nil)  out[@"num"]    = [e[@"num"] description];
                if (e[@"page"])        out[@"extPage"] = [e[@"page"] description];
                NSData *ej = [NSJSONSerialization dataWithJSONObject:e options:0 error:nil];
                if (ej) {
                    NSString *es = [[NSString alloc] initWithData:ej encoding:NSUTF8StringEncoding];
                    if (es.length > 6000) es = [es substringToIndex:6000];
                    out[@"extJSON"] = es ?: @"";
                }
            }
        }
    }
    return out;
}

// 命中判定（与 JS 侧一致）：10290 任务/提现页 c_pv* ，或 17322 活动页
static BOOL BDSZtboxIsTarget(NSDictionary *info) {
    NSString *pid = info[@"id"];
    NSString *pg  = info[@"page"];
    NSString *ty  = info[@"type"];
    if ([pid isEqualToString:@"17322"]) return YES;
    if (![pid isEqualToString:@"10290"]) return NO;
    if (!([pg isEqualToString:@"y_mission_index"] ||
          [pg isEqualToString:@"y_mission_withdraw"])) return NO;
    return ty.length && [ty hasPrefix:@"c_pv"];
}

// 取当前伪装系统版本（配置里的 systemVersion）
static NSString *BDSCurrentSpoofSystemVersion(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *p = [docs stringByAppendingPathComponent:@"bdspoofer_config.plist"];
    NSDictionary *c = [NSDictionary dictionaryWithContentsOfFile:p];
    NSString *v = c[@"systemVersion"];
    return [v isKindOfClass:NSString.class] ? v : nil;
}

static NSString *BDSWebProbeLogPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"bdspoofer_web_probe.plist"];
}

// 网页自检：原样存下网页读到的值（不做任何改写）
static void BDSWebProbeStore(NSString *json) {
    if (!json.length) return;
    static NSLock *lock = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; });
    [lock lock];
    @autoreleasepool {
        NSData *d0 = [json dataUsingEncoding:NSUTF8StringEncoding];
        id obj = d0 ? [NSJSONSerialization JSONObjectWithData:d0 options:0 error:nil] : nil;
        if (![obj isKindOfClass:NSDictionary.class]) { [lock unlock]; return; }
        NSString *p = BDSWebProbeLogPath();
        NSMutableDictionary *d = [NSMutableDictionary dictionaryWithContentsOfFile:p]
                              ?: [NSMutableDictionary dictionary];
        d[@"total"] = @([d[@"total"] integerValue] + 1);
        d[@"last"] = obj;
        d[@"lastTime"] = [NSDate date];
        // 按 ua 去重计数
        NSString *ua = obj[@"ua"];
        if (ua.length) {
            NSMutableDictionary *uas = [d[@"uas"] mutableCopy]
                                    ?: [NSMutableDictionary dictionary];
            NSString *key = ua.length > 160 ? [ua substringToIndex:160] : ua;
            uas[key] = @([uas[key] integerValue] + 1);
            d[@"uas"] = uas;
        }
        [d writeToFile:p atomically:YES];
    }
    [lock unlock];
}

static NSString *BDSAllObsLogPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"bdspoofer_all_obs.plist"];
}

// 从 URL 里挑出「像金额」的数字（小数两位，且不是常见尺寸/版本）
static NSArray<NSString *> *BDSAmountLikeNumbers(NSString *url) {
    NSMutableArray *out = [NSMutableArray array];
    NSError *err = nil;
    NSRegularExpression *rx = [NSRegularExpression
        regularExpressionWithPattern:@"[\"=:%2C,]([0-9]{1,3}\\.[0-9]{2})(?![0-9])"
                             options:0 error:&err];
    if (!rx) return out;
    NSString *dec = [url stringByRemovingPercentEncoding] ?: url;
    for (NSTextCheckingResult *m in [rx matchesInString:dec options:0
                                                  range:NSMakeRange(0, dec.length)]) {
        if (m.numberOfRanges >= 2) {
            NSString *v = [dec substringWithRange:[m rangeAtIndex:1]];
            if (v.length && ![out containsObject:v] && out.count < 8) [out addObject:v];
        }
    }
    return out;
}

// 全网观测：按 host+path 聚合，记录带金额样数字的 URL
static void BDSAllObserve(NSString *source, NSString *url) {
    if (!url.length) return;
    static NSLock *lock = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; });
    [lock lock];
    @autoreleasepool {
        NSString *p = BDSAllObsLogPath();
        NSMutableDictionary *d = [NSMutableDictionary dictionaryWithContentsOfFile:p]
                              ?: [NSMutableDictionary dictionary];
        d[@"total"] = @([d[@"total"] integerValue] + 1);

        // host + path 聚合
        NSURLComponents *c = [NSURLComponents componentsWithString:url];
        NSString *host = c.host ?: @"?";
        NSString *path = c.path ?: @"?";
        NSString *key = [NSString stringWithFormat:@"%@%@", host, path];
        NSMutableDictionary *eps = [d[@"endpoints"] mutableCopy]
                                ?: [NSMutableDictionary dictionary];
        eps[key] = @([eps[key] integerValue] + 1);
        d[@"endpoints"] = eps;

        // 带金额样数字的记下来
        NSArray<NSString *> *nums = BDSAmountLikeNumbers(url);
        if (nums.count) {
            d[@"amountHits"] = @([d[@"amountHits"] integerValue] + 1);
            NSMutableDictionary *an = [d[@"amountEndpoints"] mutableCopy]
                                   ?: [NSMutableDictionary dictionary];
            an[key] = @([an[key] integerValue] + 1);
            d[@"amountEndpoints"] = an;

            NSMutableArray *items = [d[@"amountItems"] mutableCopy] ?: [NSMutableArray array];
            NSMutableDictionary *it = [NSMutableDictionary dictionary];
            it[@"t"] = [NSDate date];
            it[@"src"] = source ?: @"?";
            it[@"endpoint"] = key;
            it[@"nums"] = nums;
            it[@"url"] = url.length > 3000 ? [url substringToIndex:3000] : url;
            [items insertObject:it atIndex:0];
            while (items.count > 40) [items removeLastObject];
            d[@"amountItems"] = items;
        }
        [d writeToFile:p atomically:YES];
    }
    [lock unlock];
}

static void BDSZtboxObserve(NSString *source, NSString *url) {
    if (!url.length) return;
    static NSLock *lock = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; });
    [lock lock];
    @autoreleasepool {
        NSString *p = BDSZtboxObsLogPath();
        NSMutableDictionary *d = [NSMutableDictionary dictionaryWithContentsOfFile:p]
                              ?: [NSMutableDictionary dictionary];
        d[@"total"] = @([d[@"total"] integerValue] + 1);
        NSString *sk = [NSString stringWithFormat:@"src.%@", source ?: @"?"];
        d[sk] = @([d[sk] integerValue] + 1);

        NSDictionary *info = BDSZtboxExtract(url);
        BOOL isTarget = BDSZtboxIsTarget(info);
        NSString *sig = [NSString stringWithFormat:@"%@/%@/%@",
                         info[@"id"] ?: @"?", info[@"page"] ?: @"?", info[@"type"] ?: @"?"];
        NSMutableDictionary *sigs = [d[@"sigs"] mutableCopy] ?: [NSMutableDictionary dictionary];
        sigs[sig] = @([sigs[sig] integerValue] + 1);
        d[@"sigs"] = sigs;
        // 命中条件的签名单独统计 —— 与未命中一眼分开
        if (isTarget) {
            NSMutableDictionary *hitSigs = [d[@"hitSigs"] mutableCopy]
                                        ?: [NSMutableDictionary dictionary];
            hitSigs[sig] = @([hitSigs[sig] integerValue] + 1);
            d[@"hitSigs"] = hitSigs;
            d[@"hitCount"] = @([d[@"hitCount"] integerValue] + 1);
        } else {
            d[@"missCount"] = @([d[@"missCount"] integerValue] + 1);
        }

        NSMutableArray *items = [d[@"items"] mutableCopy] ?: [NSMutableArray array];
        NSMutableDictionary *item = [NSMutableDictionary dictionary];
        item[@"t"] = [NSDate date];
        item[@"src"] = source ?: @"?";
        for (NSString *k in @[@"id", @"page", @"type", @"from", @"value", @"num",
                              @"cateid", @"extPage", @"extJSON", @"dataRaw"]) {
            if (info[k]) item[k] = info[k];
        }
        item[@"blocked"] = isTarget ? @YES : @NO;
        item[@"url"] = url.length > 8000 ? [url substringToIndex:8000] : url;
        [items insertObject:item atIndex:0];
        while (items.count > 30) [items removeLastObject];
        d[@"items"] = items;
        [d writeToFile:p atomically:YES];
    }
    [lock unlock];
}

static void BDSCashRecordHit(NSString *source, NSString *url) {
    static NSLock *lock = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; });
    [lock lock];
    @autoreleasepool {
        NSString *p = BDSCashHitLogPath();
        NSMutableDictionary *d = [NSMutableDictionary dictionaryWithContentsOfFile:p]
                              ?: [NSMutableDictionary dictionary];
        d[@"total"] = @([d[@"total"] integerValue] + 1);
        NSString *k = [NSString stringWithFormat:@"src.%@", source ?: @"?"];
        d[k] = @([d[k] integerValue] + 1);
        d[@"lastTime"] = [NSDate date];
        d[@"lastSource"] = source ?: @"?";
        if (url.length) {
            d[@"lastURL"] = [url length] > 8000 ? [url substringToIndex:8000] : url;
        }
        NSMutableArray *recent = [d[@"recent"] mutableCopy] ?: [NSMutableArray array];
        if (url.length) {
            NSString *u = [url length] > 8000 ? [url substringToIndex:8000] : url;
            [recent insertObject:u atIndex:0];
            while (recent.count > 8) [recent removeLastObject];
        }
        d[@"recent"] = recent;
        [d writeToFile:p atomically:YES];
    }
    [lock unlock];
}

@interface BDSCashHitHandler : NSObject <WKScriptMessageHandler>
@end
@implementation BDSCashHitHandler
- (void)userContentController:(WKUserContentController *)ucc
      didReceiveScriptMessage:(WKScriptMessage *)message {
    (void)ucc;
    NSString *body = [message.body isKindOfClass:NSString.class] ? message.body : @"";
    if ([message.name isEqualToString:@"bdsCashHit"]) {
        BDSCashRecordHit(@"web", body);
        return;
    }
    if ([message.name isEqualToString:@"bdsWebProbe"]) {
        BDSWebProbeStore(body);
        return;
    }
    if ([message.name isEqualToString:@"bdsAllObs"]) {
        NSRange bar = [body rangeOfString:@"|"];
        if (bar.location != NSNotFound) {
            BDSAllObserve([body substringToIndex:bar.location],
                          [body substringFromIndex:NSMaxRange(bar)]);
        }
        return;
    }
    if ([message.name isEqualToString:@"bdsZtboxObs"]) {
        // 格式: blocked(0/1) | source | url
        NSArray<NSString *> *parts = [body componentsSeparatedByString:@"|"];
        if (parts.count >= 3) {
            NSString *src = parts[1];
            NSString *url = [[parts subarrayWithRange:NSMakeRange(2, parts.count - 2)]
                             componentsJoinedByString:@"|"];
            BDSZtboxObserve(src, url);
        } else if (parts.count == 2) {
            BDSZtboxObserve(parts[0], parts[1]);
        }
    }
}
@end

static BDSCashHitHandler *g_cashHitHandler = nil;

static void BDSCashInstallHitHandler(WKUserContentController *ucc) {
    if (!ucc) return;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ g_cashHitHandler = [BDSCashHitHandler new]; });
    @try {
        [ucc addScriptMessageHandler:g_cashHitHandler name:@"bdsCashHit"];
    } @catch (NSException *e) {
        (void)e;   // 同一 controller 重复注册会抛，忽略
    }
    @try {
        [ucc addScriptMessageHandler:g_cashHitHandler name:@"bdsZtboxObs"];
    } @catch (NSException *e) {
        (void)e;
    }
    @try {
        [ucc addScriptMessageHandler:g_cashHitHandler name:@"bdsAllObs"];
    } @catch (NSException *e) {
        (void)e;
    }
    @try {
        [ucc addScriptMessageHandler:g_cashHitHandler name:@"bdsWebProbe"];
    } @catch (NSException *e) {
        (void)e;
    }
}

static IMP g_bdsCashOriginalWKInit = NULL;
static WKWebView *BDSCashWKInit(id self, SEL command, CGRect frame, WKWebViewConfiguration *configuration) {
    // 只在这个钩子确实装上时才会走到这里，也就是开关在启动时是打开的。
    // 新建的 WebView 补一份 =true 的脚本；关掉开关后不新建的页面不受影响，
    // 原生请求那条路由判定入口每次读开关负责，关掉立即放行。
    BDSCashInstallHitHandler(configuration.userContentController);
    // 把当前伪装值写进网页（window.__bdsWebSpoof），供 JS 改写 UA 使用
    {
        NSString *sv = BDSCurrentSpoofSystemVersion();
        if (sv.length) {
            NSString *under = [sv stringByReplacingOccurrencesOfString:@"." withString:@"_"];
            NSString *docs2 = [NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
            NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:
                [docs2 stringByAppendingPathComponent:@"bdspoofer_config.plist"]] ?: @{};
            NSNumber *sw = [cfg[@"screenWidth"] isKindOfClass:NSNumber.class]
                         ? cfg[@"screenWidth"] : nil;
            NSNumber *sh = [cfg[@"screenHeight"] isKindOfClass:NSNumber.class]
                         ? cfg[@"screenHeight"] : nil;
            NSNumber *sc = [cfg[@"screenScale"] isKindOfClass:NSNumber.class]
                         ? cfg[@"screenScale"] : nil;
            NSMutableString *js = [NSMutableString stringWithFormat:
                @"window.__bdsWebSpoof={sv_under:'%@',sv_dot:'%@'", under, sv];
            if (sw && sh) {
                [js appendFormat:@",sw:%@,sh:%@", sw, sh];
            }
            if (sc && sc.doubleValue > 0) {
                [js appendFormat:@",sc:%@", sc];
            }
            [js appendString:@"};"];
            WKUserScript *s = [[WKUserScript alloc]
                initWithSource:js
                injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                forMainFrameOnly:NO];
            [configuration.userContentController addUserScript:s];
        }
    }
    BDSEnsureCashTelemetryBlockScript(configuration.userContentController, YES);
    WKWebView *(*original)(id, SEL, CGRect, WKWebViewConfiguration *) = (void *)g_bdsCashOriginalWKInit;
    return original(self, command, frame, configuration);
}

static IMP g_bdsCashOriginalSessionWithDelegate = NULL;
static IMP g_bdsCashOriginalSession = NULL;
static void BDSInjectCashTelemetryProtocol(NSURLSessionConfiguration *configuration) {
    if (!configuration || !BDSCashTelemetryBlockProtocol.class) return;
    NSArray *classes = configuration.protocolClasses ?: @[];
    if ([classes containsObject:BDSCashTelemetryBlockProtocol.class]) return;
    // 追加在系统与 App 自带协议之后，不抢占它们的优先级。
    configuration.protocolClasses = [classes arrayByAddingObject:BDSCashTelemetryBlockProtocol.class];
}
static NSURLSession *BDSCashSessionWithDelegate(Class receiver, SEL command,
    NSURLSessionConfiguration *configuration, id<NSURLSessionDelegate> delegate, NSOperationQueue *queue) {
    BDSInjectCashTelemetryProtocol(configuration);
    NSURLSession *(*original)(Class, SEL, NSURLSessionConfiguration *, id<NSURLSessionDelegate>, NSOperationQueue *) =
        (void *)g_bdsCashOriginalSessionWithDelegate;
    return original(receiver, command, configuration, delegate, queue);
}
static NSURLSession *BDSCashSession(Class receiver, SEL command, NSURLSessionConfiguration *configuration) {
    BDSInjectCashTelemetryProtocol(configuration);
    NSURLSession *(*original)(Class, SEL, NSURLSessionConfiguration *) = (void *)g_bdsCashOriginalSession;
    return original(receiver, command, configuration);
}

// 只在启动时开关为“开”的情况下才会被调用（与 9.28-03 一致：
// 开关关闭时完全不安装任何拦截）。类替换用 dispatch_once 保证幂等。
static void BDSInstallCashTelemetryBlocking(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        BDSCashRecordHit(@"install", @"金额拦截已安装");
        [NSURLProtocol registerClass:BDSCashTelemetryBlockProtocol.class];
        Class sessionClass = NSURLSession.class;
        Method withDelegate = class_getClassMethod(sessionClass, @selector(sessionWithConfiguration:delegate:delegateQueue:));
        if (withDelegate) {
            g_bdsCashOriginalSessionWithDelegate = method_getImplementation(withDelegate);
            method_setImplementation(withDelegate, (IMP)BDSCashSessionWithDelegate);
        }
        Method withoutDelegate = class_getClassMethod(sessionClass, @selector(sessionWithConfiguration:));
        if (withoutDelegate) {
            g_bdsCashOriginalSession = method_getImplementation(withoutDelegate);
            method_setImplementation(withoutDelegate, (IMP)BDSCashSession);
        }
        Class webViewClass = WKWebView.class;
        Method initializer = class_getInstanceMethod(webViewClass, @selector(initWithFrame:configuration:));
        if (initializer) {
            g_bdsCashOriginalWKInit = method_getImplementation(initializer);
            method_setImplementation(initializer, (IMP)BDSCashWKInit);
        }
    });
}
