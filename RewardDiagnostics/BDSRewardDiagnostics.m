#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <math.h>
#import "ObserverScript.h"

static NSString *const BDSDVersion = @"0.1.0";
static NSString *const BDSDHandlerName = @"bds_reward_diag_010";
static char BDSDControllerKey, BDSDWebViewKey;
static dispatch_queue_t BDSDLogQueue;

static BOOL BDSDBaiduURL(NSURL *url) {
    NSString *host = url.host.lowercaseString;
    return [url.scheme.lowercaseString isEqualToString:@"https"] &&
        ([host isEqualToString:@"baidu.com"] || [host hasSuffix:@".baidu.com"]);
}

// Only this component's dedicated log directory is written. No account/config writes.
static void BDSDLog(NSDictionary *record) {
    NSDictionary *copy = [record copy];
    dispatch_async(BDSDLogQueue, ^{
        static NSString *path;
        static NSUInteger written = 0, events = 0;
        if (events >= 1024 || written >= 512 * 1024) return;
        @try {
            if (!path) {
                NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
                if (!documents) return;
                NSString *directory = [documents stringByAppendingPathComponent:@"BDSRewardDiagnostics"];
                if (![NSFileManager.defaultManager createDirectoryAtPath:directory withIntermediateDirectories:YES
                    attributes:@{NSFilePosixPermissions:@0700} error:nil]) return;
                NSString *name = [NSString stringWithFormat:@"session-%.0f-%@.jsonl", NSDate.date.timeIntervalSince1970, NSUUID.UUID.UUIDString];
                NSString *candidate = [directory stringByAppendingPathComponent:name];
                if (![NSFileManager.defaultManager createFileAtPath:candidate contents:nil attributes:@{
                    NSFilePosixPermissions:@0600, NSFileProtectionKey:NSFileProtectionCompleteUntilFirstUserAuthentication}]) return;
                path = candidate;
            }
            NSMutableDictionary *entry = [copy mutableCopy];
            entry[@"version"] = BDSDVersion;
            entry[@"timestamp_ms"] = @((long long)(NSDate.date.timeIntervalSince1970 * 1000));
            NSData *json = [NSJSONSerialization dataWithJSONObject:entry options:0 error:nil];
            if (!json || json.length > 4096 || written + json.length + 1 > 512 * 1024) return;
            NSMutableData *line = [json mutableCopy];
            [line appendBytes:"\n" length:1];
            NSFileHandle *file = [NSFileHandle fileHandleForWritingAtPath:path];
            if (!file) return;
            [file seekToEndOfFile];
            [file writeData:line];
            [file closeFile];
            written += line.length;
            events++;
        } @catch (__unused NSException *exception) { }
    });
}

static NSString *BDSDScript(void) {
    static NSString *script;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSData *data = [[NSData alloc] initWithBase64EncodedString:BDSDObserverBase64 options:0];
        script = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    });
    return script;
}

// Page messages are untrusted. Rebuild each record from narrowly allowed fields.
@interface BDSDMessageSink : NSObject <WKScriptMessageHandler>
@end
@implementation BDSDMessageSink
- (void)userContentController:(WKUserContentController *)controller didReceiveScriptMessage:(WKScriptMessage *)message {
    @try {
        if (![message.name isEqualToString:BDSDHandlerName] || !BDSDBaiduURL(message.frameInfo.request.URL) ||
            ![message.body isKindOfClass:NSDictionary.class]) return;
        NSDictionary *body = message.body;
        NSArray *events = @[@"observer_ready", @"observer_install_failed", @"request_started", @"request_complete",
            @"send_threw", @"observation_window_elapsed"];
        if (![events containsObject:body[@"event"]]) return;
        NSMutableDictionary *safe = [NSMutableDictionary dictionaryWithObject:body[@"event"] forKey:@"event"];
        safe[@"endpoint"] = @"/incentive/uanti";
        for (NSString *key in @[@"request_id", @"elapsed_ms", @"http_status", @"business_code_present",
            @"business_code_is_number_zero", @"is_safe_present", @"is_safe_truthy"]) {
            id value = body[key];
            if ([value isKindOfClass:NSNumber.class] && isfinite([value doubleValue])) safe[key] = value;
        }
        NSDictionary *enums = @{
            @"terminal_event":@[@"load", @"error", @"timeout", @"abort", @"unknown"],
            @"json_state":@[@"valid", @"invalid", @"empty", @"size_limit", @"unavailable", @"json_null_or_invalid",
                @"unsupported_response_type", @"redirect_outside_scope"],
            @"root_type":@[@"null", @"array", @"object", @"string", @"number", @"boolean", @"undefined"],
            @"data_type":@[@"null", @"array", @"object", @"string", @"number", @"boolean", @"undefined"],
            @"business_code_type":@[@"null", @"array", @"object", @"string", @"number", @"boolean", @"undefined"],
            @"is_safe_type":@[@"null", @"array", @"object", @"string", @"number", @"boolean", @"undefined"]};
        for (NSString *key in enums) if ([enums[key] containsObject:body[key]]) safe[key] = body[key];
        id code = body[@"business_code"];
        if ([code isKindOfClass:NSNumber.class] && isfinite([code doubleValue])) safe[@"business_code"] = code;
        else if ([code isKindOfClass:NSString.class] && [code length] <= 11) {
            NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^-?[0-9]{1,10}$" options:0 error:nil];
            if ([regex numberOfMatchesInString:code options:0 range:NSMakeRange(0, [code length])] == 1) safe[@"business_code"] = code;
        }
        id value = body[@"is_safe_value"];
        if (([value isKindOfClass:NSNumber.class] && isfinite([value doubleValue])) ||
            (value && [@[@"", @"0", @"1", @"true", @"false"] containsObject:value])) safe[@"is_safe_value"] = value;
        // This ID identifies only the local WKWebView, never a device or account.
        NSString *page = objc_getAssociatedObject(message.webView, &BDSDWebViewKey);
        if (page) safe[@"page_id"] = page;
        BDSDLog(safe);
    } @catch (__unused NSException *exception) { }
}
@end

static void BDSDPrepareController(WKUserContentController *controller) {
    if (!controller || objc_getAssociatedObject(controller, &BDSDControllerKey)) return;
    @try {
        static BDSDMessageSink *sink;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ sink = [BDSDMessageSink new]; });
        [controller addScriptMessageHandler:sink name:BDSDHandlerName];
        WKUserScript *script = [[WKUserScript alloc] initWithSource:BDSDScript()
            injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO];
        [controller addUserScript:script];
        objc_setAssociatedObject(controller, &BDSDControllerKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    } @catch (__unused NSException *exception) {
        BDSDLog(@{@"event":@"controller_install_failed"});
    }
}

static void BDSDAttachView(WKWebView *view) {
    @try {
    if (!view) return;
    BDSDPrepareController(view.configuration.userContentController);
    if (!objc_getAssociatedObject(view, &BDSDWebViewKey))
        objc_setAssociatedObject(view, &BDSDWebViewKey, NSUUID.UUID.UUIDString, OBJC_ASSOCIATION_COPY_NONATOMIC);
    // For an already-loaded page, only future XHRs can be observed.
    if (BDSDBaiduURL(view.URL)) [view evaluateJavaScript:BDSDScript() completionHandler:^(__unused id result, NSError *error) {
        if (error) BDSDLog(@{@"event":@"existing_page_install_failed"});
    }];
    } @catch (__unused NSException *exception) {
        BDSDLog(@{@"event":@"view_attach_failed"});
    }
}

static id (*BDSDOriginalInit)(id, SEL, CGRect, WKWebViewConfiguration *);
static id BDSDInit(id self, SEL cmd, CGRect frame, WKWebViewConfiguration *configuration) {
    @try { BDSDPrepareController(configuration.userContentController); }
    @catch (__unused NSException *exception) { }
    id view = BDSDOriginalInit(self, cmd, frame, configuration);
    BDSDAttachView(view);
    return view;
}
static void (*BDSDOriginalMove)(id, SEL);
static void BDSDMove(id self, SEL cmd) {
    BDSDOriginalMove(self, cmd);
    BDSDAttachView(self);
}

static BOOL BDSDHook(Class cls, SEL selector, IMP replacement, IMP *original) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!method) return NO;
    *original = method_getImplementation(method);
    // Materialize inherited methods on WKWebView; never modify UIView globally.
    if (!class_addMethod(cls, selector, replacement, method_getTypeEncoding(method)))
        *original = class_replaceMethod(cls, selector, replacement, method_getTypeEncoding(method));
    return *original != NULL;
}
static void BDSDVisit(UIView *view) {
    @try {
    if ([view isKindOfClass:WKWebView.class]) BDSDAttachView((WKWebView *)view);
    for (UIView *child in view.subviews) BDSDVisit(child);
    } @catch (__unused NSException *exception) { }
}

__attribute__((constructor)) static void BDSDStart(void) {
    @autoreleasepool {
        if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.baidu.BaiduMobileInfo"]) return;
        BDSDLogQueue = dispatch_queue_create("com.codex.bd-reward-diagnostics.log", DISPATCH_QUEUE_SERIAL);
        dispatch_async(dispatch_get_main_queue(), ^{
            BOOL init = BDSDHook(WKWebView.class, @selector(initWithFrame:configuration:), (IMP)BDSDInit, (IMP *)&BDSDOriginalInit);
            BOOL move = BDSDHook(WKWebView.class, @selector(didMoveToWindow), (IMP)BDSDMove, (IMP *)&BDSDOriginalMove);
            BDSDLog(@{@"event":@"native_ready", @"init_hook":@(init), @"view_hook":@(move)});
            for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
                if ([scene isKindOfClass:UIWindowScene.class])
                    for (UIWindow *window in ((UIWindowScene *)scene).windows) BDSDVisit(window);
            }
        });
    }
}
