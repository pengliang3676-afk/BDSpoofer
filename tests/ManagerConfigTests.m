#define main BDSManagerApplicationMain
#include "../CraneManager/BDSCraneManager.m"
#undef main
#include <assert.h>
static void unchangedOutside(NSDictionary *before, NSDictionary *after, NSSet *allowed) {
    for(NSString *key in before) if(![allowed containsObject:key]) assert([before[key] isEqual:after[key]]);
    for(NSString *key in after) if(![allowed containsObject:key]) assert([before[key] isEqual:after[key]]);
}
int main(int argc,char **argv) {
    @autoreleasepool {
        assert(argc==2);
        NSDictionary *defaults=[NSDictionary dictionaryWithContentsOfFile:@(argv[1])];assert(defaults.count>20);
        NSDictionary *newA=BDSMergedConfig(nil), *newB=BDSMergedConfig(nil);
        assert(![newA[@"idfv"] isEqual:newB[@"idfv"]]);
        assert([BDSMergedConfig(newA)[@"idfv"] isEqual:newA[@"idfv"]]);
        NSMutableDictionary *config=BDSMergedConfig(defaults);
        BDSSeedIdentityIfNeeded(config,YES);
        assert([config[@"configVersion"] integerValue]==188);
        assert(![config[@"blockStatCashTelemetry"] boolValue]);
        NSSet *basicSwitchSet=[NSSet setWithArray:BDSBasicKeys()];
        for(NSString *key in BDSBasicKeys()) assert([config[key] boolValue]);
        for(NSString *key in BDSRegularKeys()) if(![basicSwitchSet containsObject:key]) assert([config[key] boolValue]);
        for(NSString *key in BDSRiskKeys()) assert(![config[key] boolValue]);
        assert([defaults[@"hwMachine"] isEqual:@"iPhone18,2"] && [defaults[@"hwModel"] isEqual:@"V54AP"]);
        assert([config[@"hwMachine"] isEqual:@"iPhone18,2"] && [config[@"systemVersion"] isEqual:@"26.6"]);
        assert([config[@"memorySize"] integerValue]==12288 && [config[@"diskSize"] integerValue]==256);
        assert(![config[@"spoofBaiduTargeted"] boolValue]);
        for(NSString *key in BDSSelectedTargetKeys()) assert(![config[key] boolValue]);
        NSString *retained=config[@"idfv"];config[@"idfa"]=@"";BDSSeedIdentityIfNeeded(config,NO);assert([retained isEqual:config[@"idfv"]]);assert([config[@"idfa"] length]>0);
        NSMutableSet *meta=[NSMutableSet setWithArray:@[@"managerGeneratedAt",@"managerProfileVersion",@"managerRandomMode",@"didRandomizeBasic",@"didRandomizeAdvanced",@"didRandomizeTargeted"]];
        NSMutableSet *advanced=[meta mutableCopy];[advanced addObjectsFromArray:@[@"idfa",@"idfv",@"deviceID",@"cuid",@"utdid"]];
        NSMutableSet *basic=[meta mutableCopy];[basic addObjectsFromArray:@[@"enabled",@"spoofAdvertisingIdentifiers",@"spoofProcessHardware",@"spoofSysctl",@"spoofLocale",@"spoofCarrier",@"spoofStorage",@"deviceProfileName",@"deviceModel",@"marketingModel",@"systemVersion",@"systemBuild",@"kernOSVersion",@"hwMachine",@"hwModel",@"memorySize",@"diskSize",@"deviceName",@"kernHostname",@"screenWidth",@"screenHeight",@"screenScale",@"nativeScreenWidth",@"nativeScreenHeight",@"bootTimeOffsetSeconds",@"carrierName",@"mcc",@"mnc",@"isoCountryCode"]];
        config[@"spoofBaiduTargeted"]=@YES;for(NSString *key in BDSTargetedKeys()) config[key]=@YES;
        config[@"spoofWiFi"]=@NO;config[@"spoofKeychain"]=@YES;
        for(int i=0;i<100;i++) {
            NSDictionary *next=BDSCreateRandomConfig(config,BDSRandomModeBasic,[NSSet set]);
            unchangedOutside(config,next,basic);config=[next mutableCopy];
            next=BDSCreateRandomConfig(config,BDSRandomModeAdvanced,[NSSet set]);
            unchangedOutside(config,next,advanced);config=[next mutableCopy];
        }
        NSArray *groups=@[@[@"targetedSystemVersion",@"targetedSystemBuild"],@[@"targetedDeviceProfileName",@"targetedHwMachine",@"targetedHwModel"],@[@"targetedScreenWidth",@"targetedScreenHeight",@"targetedScreenScale",@"targetedNativeScreenWidth",@"targetedNativeScreenHeight",@"targetedScreenHwMachine"],@[@"targetedUASystemVersion",@"targetedUASystemBuild"],@[@"targetedPushDeviceProfileName",@"targetedPushHwMachine",@"targetedPushHwModel"]];
        NSMutableSet *targetedAllowed=[meta mutableCopy];
        [targetedAllowed addObjectsFromArray:BDSTargetedKeys()];[targetedAllowed addObjectsFromArray:@[@"spoofBaiduTargeted",@"targetedGeneratedAt"]];
        for(NSArray *group in groups) [targetedAllowed addObjectsFromArray:group];
        NSDictionary *targeted=BDSCreateRandomConfig(config,BDSRandomModeTargeted,[NSSet set]);
        unchangedOutside(config,targeted,targetedAllowed);
        assert([targeted[@"spoofBaiduTargeted"] boolValue]);
        for(NSString *key in BDSTargetedKeys()) assert([targeted[key] boolValue]);
        for(NSArray *group in groups) for(NSString *key in group) assert(targeted[key]);
        for(NSDictionary *device in BDSDeviceProfiles()) {
            NSDictionary *generated=BDSCreateConfigForDevice(defaults,device,BDSRandomModeBasic,[NSSet set]);
            assert([generated[@"deviceProfileName"] isEqual:device[@"name"]]);
            assert([generated[@"hwMachine"] isEqual:device[@"machine"]]);
            assert([generated[@"hwModel"] isEqual:device[@"model"]]);
            assert([generated[@"screenWidth"] isEqual:device[@"width"]]);
            assert([generated[@"screenHeight"] isEqual:device[@"height"]]);
        }
        [config addEntriesFromDictionary:BDSSafeSwitchValues()];
        NSDictionary *reloaded=BDSMergedConfig(config);for(NSString *key in BDSSafeSwitchValues()) assert(![reloaded[key] boolValue]);
        NSMutableDictionary *unusedTarget=BDSMergedConfig(defaults);
        for(NSString *key in BDSSelectedTargetKeys()) unusedTarget[key]=@NO;
        unusedTarget[@"spoofBaiduTargeted"]=@NO; unusedTarget[@"targetedGeneratedAt"]=@0;
        NSDictionary *sparse=BDSConfigForPersistentStorage(unusedTarget);
        for(NSString *key in BDSTargetedStoredValueKeys()) assert(!sparse[key]);
        assert(!sparse[@"targetedGeneratedAt"]);
        NSData *sparseData=[NSPropertyListSerialization dataWithPropertyList:sparse format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
        assert(sparseData.length<4096);
        assert([BDSCleanContainerDisplayName(@"01（默认）", @"fallback") isEqualToString:@"01"]);
        assert([BDSCleanContainerDisplayName(@"默认", @"fallback") isEqualToString:@"默认"]);
        puts("PASS manager: per-mode random state, clean current label, sparse unused targeted values, synchronized device fields and safe restore");
    }
    return 0;
}
