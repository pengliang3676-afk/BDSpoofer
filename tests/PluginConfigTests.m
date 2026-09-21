#define BDS_CONFIG_TESTING 1
#include "../BDSpoofer.m"
#include <assert.h>

static void checkUnchanged(NSDictionary *before, NSDictionary *after, NSSet *allowed) {
    for(NSString *key in before) if(![allowed containsObject:key]) assert([before[key] isEqual:after[key]]);
    for(NSString *key in after) if(![allowed containsObject:key]) assert([before[key] isEqual:after[key]]);
}
static NSURLRequest *cashTelemetryRequest(NSString *host, id eventID, NSString *page,
                                          NSString *type, id amount) {
    NSMutableDictionary *ext=[NSMutableDictionary dictionary];
    if(amount) ext[@"num"]=amount;
    NSDictionary *data=@{@"actiondata":@{@"id":eventID ?: @"",
        @"content":@{@"page":page ?: @"", @"type":type ?: @"", @"ext":ext}}};
    NSData *json=[NSJSONSerialization dataWithJSONObject:data options:0 error:nil];
    NSString *value=[[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    NSURLComponents *components=[[NSURLComponents alloc] init];
    components.scheme=@"https"; components.host=host; components.path=@"/ztbox";
    components.queryItems=@[[NSURLQueryItem queryItemWithName:@"action" value:@"zpblog"],
                            [NSURLQueryItem queryItemWithName:@"data" value:value]];
    return [NSURLRequest requestWithURL:components.URL];
}
int main(void) {
    @autoreleasepool {
        NSMutableDictionary *config=[BDSDefaultConfig() mutableCopy];
        BDSApplyInitialDefaults(config,nil);
        assert(BDSRegularKeys().count==21 && BDSRiskKeys().count==5);
        assert([config[@"configVersion"] integerValue]==187);
        assert(![config[@"blockStatCashTelemetry"] boolValue]);
        for(NSString *key in BDSRegularKeys()) assert([config[key] boolValue]);
        for(NSString *key in BDSRiskKeys()) assert(![config[key] boolValue]);
        [config addEntriesFromDictionary:BDSRandomIdentityValues()];
        for(NSString *key in BDSTargetedChildKeys()) config[key]=@YES;
        config[@"spoofBaiduTargeted"]=@YES;
        g_config=[config copy];
        NSSet *identity=[NSSet setWithArray:@[@"idfa",@"idfv",@"deviceID",@"cuid",@"utdid",@"didRandomizeAdvanced"]];
        NSSet *basic=[NSSet setWithArray:@[@"deviceProfileName",@"deviceModel",@"marketingModel",@"systemVersion",@"systemBuild",@"kernOSVersion",@"hwMachine",@"hwModel",@"memorySize",@"diskSize",@"deviceName",@"kernHostname",@"screenWidth",@"screenHeight",@"screenScale",@"nativeScreenWidth",@"nativeScreenHeight",@"bootTimeOffsetSeconds",@"carrierName",@"mcc",@"mnc",@"isoCountryCode",@"localeIdentifier",@"didRandomizeBasic"]];
        BOOL sawSE2=NO;
        for(NSDictionary *device in BDSUnifiedDeviceProfiles()) {
            if([device[@"machine"] isEqual:@"iPhone12,8"]) sawSE2=YES;
        }
        assert(sawSE2 && BDSUnifiedDeviceProfiles().count==37);
        NSDictionary *se2=@{@"machine":@"iPhone12,8"};
        NSDictionary *iphone8=@{@"machine":@"iPhone10,1"};
        NSDictionary *iphoneXR=@{@"machine":@"iPhone11,8"};
        BOOL se2Has26=NO, iphone8HasLate16=NO, xrHasLate16=NO, xrHasLate18=NO, se2HasLate16=NO;
        for(NSDictionary *profile in BDSSystemProfilesForDevice(se2)) {
            if([profile[@"version"] isEqual:@"26.6"]) se2Has26=YES;
            if([profile[@"version"] hasPrefix:@"16.7.15"] || [profile[@"version"] hasPrefix:@"16.7.16"]) se2HasLate16=YES;
        }
        for(NSDictionary *profile in BDSSystemProfilesForDevice(iphone8)) {
            if([profile[@"version"] hasPrefix:@"16.7.15"] || [profile[@"version"] hasPrefix:@"16.7.16"]) iphone8HasLate16=YES;
        }
        for(NSDictionary *profile in BDSSystemProfilesForDevice(iphoneXR)) {
            if([profile[@"version"] hasPrefix:@"16.7.15"] || [profile[@"version"] hasPrefix:@"16.7.16"]) xrHasLate16=YES;
            if([profile[@"version"] hasPrefix:@"18.7.9"] || [profile[@"version"] hasPrefix:@"18.7.10"]) xrHasLate18=YES;
        }
        assert(se2Has26 && iphone8HasLate16 && xrHasLate18 && !xrHasLate16 && !se2HasLate16);
        for(int i=0;i<100;i++) {
            NSDictionary *before=g_config;
            NSMutableDictionary *after=[before mutableCopy]; [after addEntriesFromDictionary:BDSRandomBasicProfileValues()];
            checkUnchanged(before,after,basic);
            assert(![after[@"hwMachine"] isEqual:before[@"hwMachine"]]);
            NSString *ver=after[@"systemVersion"];
            NSString *machine=after[@"hwMachine"];
            if([ver hasPrefix:@"16.7.15"] || [ver hasPrefix:@"16.7.16"]) assert([machine hasPrefix:@"iPhone10,"]);
            if([ver hasPrefix:@"18.7.9"] || [ver hasPrefix:@"18.7.10"]) assert([machine hasPrefix:@"iPhone11,"]);
            g_config=after;
            before=g_config; after=[before mutableCopy]; [after addEntriesFromDictionary:BDSRandomIdentityValues()];
            checkUnchanged(before,after,identity); g_config=after;
        }
        NSArray *groups=@[@[@"targetedSystemVersion",@"targetedSystemBuild"],@[@"targetedDeviceProfileName",@"targetedHwMachine",@"targetedHwModel"],@[@"targetedScreenWidth",@"targetedScreenHeight",@"targetedScreenScale",@"targetedNativeScreenWidth",@"targetedNativeScreenHeight",@"targetedScreenHwMachine"],@[@"targetedUASystemVersion",@"targetedUASystemBuild"],@[@"targetedPushDeviceProfileName",@"targetedPushHwMachine",@"targetedPushHwModel"]];
        for(NSUInteger mask=0;mask<32;mask++) {
            NSMutableDictionary *before=[g_config mutableCopy];
            NSMutableSet *allowed=[NSMutableSet setWithArray:@[@"spoofBaiduTargeted",@"targetedGeneratedAt",@"didRandomizeTargeted"]];
            for(NSUInteger i=0;i<5;i++) { before[BDSTargetedChildKeys()[i]]=@((mask&(1<<i))!=0); if(mask&(1<<i)) [allowed addObjectsFromArray:groups[i]]; }
            g_config=before;
            NSDictionary *delta=BDSRandomTargetedProfileValues();
            if(!mask) assert(delta.count==0);
            NSMutableDictionary *after=[before mutableCopy];[after addEntriesFromDictionary:delta];
            checkUnchanged(before,after,allowed);
        }
        config=[g_config mutableCopy];config[@"targetedUASystemVersion"]=@"17.4.1";
        config[@"targetedPushDeviceProfileName"]=@"iPhone 14 Pro";
        config[@"targetedHwMachine"]=@"iPhone14,6";
        config[@"targetedScreenHwMachine"]=@"iPhone15,2";
        config[@"targetedScreenHeight"]=@852;
        g_config=config;
        assert([tg_rewrite_ua_device_info(@"iPhone_15.3") isEqual:@"iPhone_17.4.1"]);
        assert([tg_rewrite_ua_device_info(@"unknown_value") isEqual:@"unknown_value"]);
        NSString *ua=@"CPU iPhone OS 15_3 like Mac OS X Mobile/15E148 baiduboxapp/7.13.0";
        assert([tg_rewrite_ua(ua) isEqual:@"CPU iPhone OS 17_4_1 like Mac OS X Mobile/15E148 baiduboxapp/7.13.0"]);
        assert([tg_rewrite_push(@"&device_name=iPhone-ABC123&token=iPhone14,6&x=%26") isEqual:@"&device_name=iPhone%2014%20Pro&token=iPhone14,6&x=%26"]);
        assert([tg_rewrite_push(@"token=iPhone14,6") isEqual:@"token=iPhone14,6"]);
        assert(tg_status_bar()==54);
        NSDictionary *loginCfg=@{@"enabled":@YES,@"spoofBaiduSDK":@YES,@"hwMachine":@"iPhone17,3",
                                 @"deviceProfileName":@"iPhone 16",@"systemVersion":@"18.7.2"};
        g_config=loginCfg;
        NSDictionary *loginDev=BDSLoginDeviceDict();
        assert([loginDev[@"PhoneModel"] isEqual:@"iPhone17,3"]);
        assert([loginDev[@"device_name"] isEqual:@"iPhone 16"]);
        assert([loginDev[@"SystemVersion"] isEqual:@"18.7.2"]);
        NSURL *sso=[NSURL URLWithString:@"https://passport.baidu.com/phoenix/account/ssologin?type=42&code=abc"];
        NSString *ssoOut=BDSURLByAddingLoginDevice(sso).absoluteString;
        assert([ssoOut containsString:@"PhoneModel=iPhone17,3"]);
        assert([ssoOut containsString:@"device_name=iPhone%2016"] || [ssoOut containsString:@"device_name=iPhone 16"]);
        NSURL *already=[NSURL URLWithString:@"https://passport.baidu.com/phoenix/account/ssologin?PhoneModel=keep"];
        assert([BDSURLByAddingLoginDevice(already).absoluteString containsString:@"PhoneModel=keep"]);
        assert(![BDSURLByAddingLoginDevice(already).absoluteString containsString:@"PhoneModel=iPhone17,3"]);
        NSURL *other=[NSURL URLWithString:@"https://nsclick.baidu.com/v.gif"];
        assert(BDSURLByAddingLoginDevice(other)==other);
        g_config=[@{@"enabled":@YES,@"spoofBaiduSDK":@NO,@"hwMachine":@"iPhone17,3",@"deviceProfileName":@"iPhone 16"} copy];
        assert(BDSLoginDeviceDict()==nil);
        g_config=config;
        NSMutableDictionary *safe=[config mutableCopy];[safe addEntriesFromDictionary:BDSSafeSwitchValues()];
        NSMutableDictionary *reloaded=[safe mutableCopy];BDSApplyInitialDefaults(reloaded,safe);
        for(NSString *key in BDSSafeSwitchValues()) assert(![reloaded[key] boolValue]);
        assert([reloaded[@"idfv"] isEqual:safe[@"idfv"]]);
        assert(BDSCashTelemetryRequestIsTarget(cashTelemetryRequest(@"h2tcbox.baidu.com", @10290, @"y_mission_index", @"c_pv", @"3.03")));
        assert(!BDSCashTelemetryRequestIsTarget(cashTelemetryRequest(@"h2tcbox.baidu.com", @10291, @"y_mission_index", @"c_pv", @"3.03")));
        assert(!BDSCashTelemetryRequestIsTarget(cashTelemetryRequest(@"h2tcbox.baidu.com", @10290, @"other_page", @"c_pv", @"3.03")));
        assert(!BDSCashTelemetryRequestIsTarget(cashTelemetryRequest(@"example.com", @10290, @"y_mission_index", @"c_pv", @"3.03")));
        assert(!BDSCashTelemetryRequestIsTarget(cashTelemetryRequest(@"h2tcbox.baidu.com", @10290, @"y_mission_index", @"c_pv", nil)));
        NSMutableDictionary *unusedTarget=[BDSDefaultConfig() mutableCopy];
        for(NSString *key in BDSSelectedTargetKeys()) unusedTarget[key]=@NO;
        unusedTarget[@"spoofBaiduTargeted"]=@NO; unusedTarget[@"targetedGeneratedAt"]=@0;
        NSDictionary *sparse=BDSConfigForPersistentStorage(unusedTarget);
        for(NSString *key in BDSTargetedStoredValueKeys()) assert(!sparse[key]);
        assert(!sparse[@"targetedGeneratedAt"]);
        NSData *sparseData=[NSPropertyListSerialization dataWithPropertyList:sparse format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
        assert(sparseData.length<4096);
        unusedTarget[@"didRandomizeTargeted"]=@YES;
        NSDictionary *preserved=BDSConfigForPersistentStorage(unusedTarget);
        for(NSString *key in BDSTargetedStoredValueKeys()) assert(preserved[key]);
        puts("PASS plugin: compact summary state, sparse unused targeted values, independent random modes, exact cash telemetry matcher, UA/Push/screen regressions");
    }
    return 0;
}
