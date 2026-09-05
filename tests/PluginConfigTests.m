#define BDS_CONFIG_TESTING 1
#include "../BDSpoofer.m"
#include <assert.h>

static void checkUnchanged(NSDictionary *before, NSDictionary *after, NSSet *allowed) {
    for(NSString *key in before) if(![allowed containsObject:key]) assert([before[key] isEqual:after[key]]);
    for(NSString *key in after) if(![allowed containsObject:key]) assert([before[key] isEqual:after[key]]);
}
int main(void) {
    @autoreleasepool {
        NSMutableDictionary *config=[BDSDefaultConfig() mutableCopy];
        BDSApplyInitialDefaults(config,nil);
        assert(BDSRegularKeys().count==21 && BDSRiskKeys().count==4);
        for(NSString *key in BDSRegularKeys()) assert([config[key] boolValue]);
        for(NSString *key in BDSRiskKeys()) assert(![config[key] boolValue]);
        [config addEntriesFromDictionary:BDSRandomIdentityValues()];
        for(NSString *key in BDSTargetedChildKeys()) config[key]=@YES;
        config[@"spoofBaiduTargeted"]=@YES;
        g_config=[config copy];
        NSSet *identity=[NSSet setWithArray:@[@"idfa",@"idfv",@"deviceID",@"cuid",@"utdid"]];
        NSSet *basic=[NSSet setWithArray:@[@"deviceProfileName",@"deviceModel",@"marketingModel",@"systemVersion",@"systemBuild",@"kernOSVersion",@"hwMachine",@"hwModel",@"memorySize",@"diskSize",@"deviceName",@"kernHostname",@"screenWidth",@"screenHeight",@"screenScale",@"nativeScreenWidth",@"nativeScreenHeight",@"bootTimeOffsetSeconds",@"carrierName",@"mcc",@"mnc",@"isoCountryCode",@"localeIdentifier"]];
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
            NSMutableSet *allowed=[NSMutableSet setWithArray:@[@"spoofBaiduTargeted",@"targetedGeneratedAt"]];
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
        NSMutableDictionary *safe=[config mutableCopy];[safe addEntriesFromDictionary:BDSSafeSwitchValues()];
        NSMutableDictionary *reloaded=[safe mutableCopy];BDSApplyInitialDefaults(reloaded,safe);
        for(NSString *key in BDSSafeSwitchValues()) assert(![reloaded[key] boolValue]);
        assert([reloaded[@"idfv"] isEqual:safe[@"idfv"]]);
        puts("PASS plugin: defaults, preserved manual choices, safe restore, 200 independent basic/advanced operations, all 32 targeted selections, UA/Push/screen regressions");
    }
    return 0;
}
