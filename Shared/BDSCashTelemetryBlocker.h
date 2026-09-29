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
"return String(ad&&ad.id)==='10290'&&!!c&&c.page==='y_mission_index'&&c.type==='c_pv'&&!!e&&e.num!==undefined&&e.num!==null;"
"}catch(x){return false;}"
"}"
"try{"
"var d=Object.getOwnPropertyDescriptor(HTMLImageElement.prototype,'src');"
"if(d&&d.set){"
"var s=d.set;"
"Object.defineProperty(HTMLImageElement.prototype,'src',{get:d.get,set:function(v){"
"try{if(hit(v)){s.call(this,blank);return;}}catch(x){}"
"s.call(this,v);},enumerable:d.enumerable,configurable:d.configurable});"
"}"
"}catch(x){}"
"try{if(navigator.sendBeacon){var sb=navigator.sendBeacon;navigator.sendBeacon=function(u,d){try{if(hit(u))return true;}catch(x){}return sb.apply(navigator,arguments);};}}catch(x){}"
"try{if(window.fetch){var f=window.fetch;window.fetch=function(i,o){try{var u=(typeof i==='string'||i instanceof URL)?i:(i&&i.url);if(hit(u))return Promise.resolve(new Response('',{status:204,statusText:'No Content'}));}catch(x){}return f.apply(this,arguments);};}}catch(x){}"
"try{var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){try{this.__bdsCashHit=hit(u);}catch(x){this.__bdsCashHit=false;}return xo.apply(this,arguments);};"
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

static IMP g_bdsCashOriginalWKInit = NULL;
static WKWebView *BDSCashWKInit(id self, SEL command, CGRect frame, WKWebViewConfiguration *configuration) {
    // 只在这个钩子确实装上时才会走到这里，也就是开关在启动时是打开的。
    // 新建的 WebView 补一份 =true 的脚本；关掉开关后不新建的页面不受影响，
    // 原生请求那条路由判定入口每次读开关负责，关掉立即放行。
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
