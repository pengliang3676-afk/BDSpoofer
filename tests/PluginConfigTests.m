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
        assert([config[@"configVersion"] integerValue]==188);
        assert(![config[@"blockStatCashTelemetry"] boolValue]);
        for(NSString *key in BDSRegularKeys()) assert([config[key] boolValue]);
        for(NSString *key in BDSRiskKeys()) assert(![config[key] boolValue]);
        assert(![config[@"spoofBaiduTargeted"] boolValue]);
        for(NSString *key in BDSSelectedTargetKeys()) assert(![config[key] boolValue]);
        [config addEntriesFromDictionary:BDSRandomIdentityValues()];
        for(NSString *key in BDSTargetedChildKeys()) config[key]=@YES;
        config[@"spoofBaiduTargeted"]=@YES;
        g_config=[config copy];
        NSSet *identity=[NSSet setWithArray:@[@"idfa",@"idfv",@"deviceID",@"cuid",@"utdid",@"didRandomizeAdvanced"]];
        NSSet *basic=[NSSet setWithArray:@[@"deviceProfileName",@"deviceModel",@"marketingModel",@"systemVersion",@"systemBuild",@"kernOSVersion",@"hwMachine",@"hwModel",@"memorySize",@"diskSize",@"deviceName",@"kernHostname",@"screenWidth",@"screenHeight",@"screenScale",@"nativeScreenWidth",@"nativeScreenHeight",@"bootTimeOffsetSeconds",@"carrierName",@"mcc",@"mnc",@"isoCountryCode",@"localeIdentifier",@"didRandomizeBasic"]];
        for(int i=0;i<100;i++) {
            NSDictionary *before=g_config;
            NSMutableDictionary *after=[before mutableCopy]; [after addEntriesFromDictionary:BDSRandomBasicProfileValues()];
            checkUnchanged(before,after,basic);
            assert(![after[@"hwMachine"] isEqual:@"iPhone12,8"]);
            assert(![after[@"hwMachine"] isEqual:before[@"hwMachine"]]);
            g_config=after;
            before=g_config; after=[before mutableCopy]; [after addEntriesFromDictionary:BDSRandomIdentityValues()];
            checkUnchanged(before,after,identity); g_config=after;
        }
        NSArray *groups=@[@[@"targetedSystemVersion",@"targetedSystemBuild"],@[@"targetedDeviceProfileName",@"targetedHwMachine",@"targetedHwModel"],@[@"targetedScreenWidth",@"targetedScreenHeight",@"targetedScreenScale",@"targetedNativeScreenWidth",@"targetedNativeScreenHeight",@"targetedScreenHwMachine"],@[@"targetedUASystemVersion",@"targetedUASystemBuild"],@[@"targetedPushDeviceProfileName",@"targetedPushHwMachine",@"targetedPushHwModel"]];
        for(NSUInteger mask=0;mask<32;mask++) {
            NSMutableDictionary *before=[g_config mutableCopy];
            NSMutableSet *allowed=[NSMutableSet setWithArray:@[@"spoofBaiduTargeted",@"targetedGeneratedAt",@"didRandomizeTargeted"]];
            for(NSUInteger i=0;i<5;i++) { before[BDSTargetedChildKeys()[i]]=@((mask&(1<<i))!=0); [allowed addObject:BDSTargetedChildKeys()[i]]; [allowed addObjectsFromArray:groups[i]]; }
            g_config=before;
            NSDictionary *delta=BDSRandomTargetedProfileValues();
            assert(delta.count>0 && [delta[@"spoofBaiduTargeted"] boolValue]);
            for(NSString *key in BDSTargetedChildKeys()) assert([delta[key] boolValue]);
            for(NSArray *group in groups) for(NSString *key in group) assert(delta[key]);
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
