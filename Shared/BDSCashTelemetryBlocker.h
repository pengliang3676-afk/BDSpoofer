#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

static NSString * const BDSCashTelemetryHost = @"h2tcbox.baidu.com";
static NSString * const BDSCashTelemetryPath = @"/ztbox";

static BOOL BDSCashTelemetryRequestIsTarget(NSURLRequest *request) {
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

static NSString * const BDSCashTelemetryBlockScript = @
"(function(){"
"if(window.__bdsBlockStatCashTelemetry)return;"
"window.__bdsBlockStatCashTelemetry=true;"
"try{"
"var d=Object.getOwnPropertyDescriptor(HTMLImageElement.prototype,'src');"
"if(!d||!d.set)return;"
"var s=d.set;"
"Object.defineProperty(HTMLImageElement.prototype,'src',{get:d.get,set:function(v){"
"try{var u=new URL(v,document.baseURI);"
"if(u.protocol==='https:'&&u.hostname.toLowerCase()==='h2tcbox.baidu.com'&&u.pathname==='/ztbox'&&u.searchParams.get('action')==='zpblog'){"
"var o=JSON.parse(u.searchParams.get('data')||'null'),a=o&&o.actiondata,c=a&&a.content,e=c&&c.ext;"
"if(String(a&&a.id)==='10290'&&c&&c.page==='y_mission_index'&&c.type==='c_pv'&&e&&e.num!==undefined&&e.num!==null){"
"s.call(this,'data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=');return;"
"}}}catch(x){}s.call(this,v);},enumerable:d.enumerable,configurable:d.configurable});"
"}catch(x){}"
"})();";

static void BDSAddCashTelemetryBlockScript(WKUserContentController *controller) {
    if (!controller) return;
    for (WKUserScript *script in controller.userScripts) {
        if ([script.source containsString:@"__bdsBlockStatCashTelemetry"]) return;
    }
    WKUserScript *script = [[WKUserScript alloc]
        initWithSource:BDSCashTelemetryBlockScript
        injectionTime:WKUserScriptInjectionTimeAtDocumentStart
        forMainFrameOnly:NO];
    [controller addUserScript:script];
}

static IMP g_bdsCashOriginalWKInit = NULL;
static WKWebView *BDSCashWKInit(id self, SEL command, CGRect frame, WKWebViewConfiguration *configuration) {
    BDSAddCashTelemetryBlockScript(configuration.userContentController);
    WKWebView *(*original)(id, SEL, CGRect, WKWebViewConfiguration *) = (void *)g_bdsCashOriginalWKInit;
    return original(self, command, frame, configuration);
}

static IMP g_bdsCashOriginalSessionWithDelegate = NULL;
static IMP g_bdsCashOriginalSession = NULL;
static void BDSInjectCashTelemetryProtocol(NSURLSessionConfiguration *configuration) {
    if (!configuration) return;
    NSArray *classes = configuration.protocolClasses ?: @[];
    if ([classes containsObject:BDSCashTelemetryBlockProtocol.class]) return;
    configuration.protocolClasses = [@[BDSCashTelemetryBlockProtocol.class] arrayByAddingObjectsFromArray:classes];
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

static void BDSInstallCashTelemetryBlocking(void) {
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
    NSLog(@"[BDSCashTelemetry] blocking enabled for the verified cash page-view event");
}
