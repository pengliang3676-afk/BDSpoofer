#import <Foundation/Foundation.h>

static NSArray<NSArray<NSDictionary *> *> *BDSSettingGroups(void) {
    return @[
        @[@{@"key":@"enabled",@"name":@"基础功能"},
          @{@"key":@"spoofAdvertisingIdentifiers",@"name":@"广告标识参数"},
          @{@"key":@"spoofProcessHardware",@"name":@"主机名与内存参数"},
          @{@"key":@"spoofSysctl",@"name":@"系统硬件参数"},
          @{@"key":@"spoofLocale",@"name":@"语言与地区参数"},
          @{@"key":@"spoofCarrier",@"name":@"运营商参数"},
          @{@"key":@"spoofStorage",@"name":@"存储参数"}],
        @[@{@"key":@"spoofBaiduSDK",@"name":@"百度身份参数"},
          @{@"key":@"bypassJailbreakDetect",@"name":@"防越狱检测"},
          @{@"key":@"spoofKeychain",@"name":@"Keychain 拦截",@"off":@YES},
          @{@"key":@"spoofAppGroup",@"name":@"App Group 隔离",@"off":@YES},
          @{@"key":@"spoofWebKitCookie",@"name":@"WebKit Cookie 过滤",@"off":@YES},
          @{@"key":@"spoofUserAgent",@"name":@"自定义 User-Agent",@"off":@YES}],
        @[@{@"key":@"spoofWiFi",@"name":@"Wi-Fi 参数"},
          @{@"key":@"spoofLocalIP",@"name":@"本地 IP 参数"},
          @{@"key":@"spoofPasteboard",@"name":@"剪贴板保护"},
          @{@"key":@"spoofBootTime",@"name":@"启动时间参数"},
          @{@"key":@"spoofCPU",@"name":@"CPU 参数"},
          @{@"key":@"spoofLocation",@"name":@"定位保护"},
          @{@"key":@"spoofProxyDetection",@"name":@"代理检测隐藏"},
          @{@"key":@"spoofStatfs",@"name":@"剩余空间参数"},
          @{@"key":@"spoofDlopen",@"name":@"dlopen 反检测"},
          @{@"key":@"spoofUbiquity",@"name":@"iCloud 隔离"},
          @{@"key":@"spoofPrivacyPermissions",@"name":@"通讯录与日历保护"},
          @{@"key":@"spoofBattery",@"name":@"电池参数"},
          @{@"key":@"blockStatCashTelemetry",@"name":@"阻止金额统计上报",@"off":@YES}]
    ];
}
static NSArray<NSString *> *BDSBasicKeys(void) {
    NSMutableArray *keys=[NSMutableArray array];
    for(NSDictionary *item in BDSSettingGroups()[0]) [keys addObject:item[@"key"]];
    return keys;
}
static NSArray<NSString *> *BDSRegularKeys(void) {
    NSMutableArray *keys=[NSMutableArray array];
    for (NSArray *group in BDSSettingGroups()) for(NSDictionary *item in group)
        if(![item[@"off"] boolValue]) [keys addObject:item[@"key"]];
    return keys;
}
static NSArray<NSString *> *BDSRiskKeys(void) {
    return @[@"spoofKeychain",@"spoofAppGroup",@"spoofWebKitCookie",@"spoofUserAgent",
             @"blockStatCashTelemetry"];
}
static NSArray<NSString *> *BDSSelectedTargetKeys(void) {
    return @[@"spoofBaiduTargetedSystem",@"spoofBaiduTargetedModel",@"spoofBaiduTargetedScreen",@"spoofBaiduTargetedUA",@"spoofBaiduTargetedPush"];
}
static NSArray<NSString *> *BDSTargetedStoredValueKeys(void) {
    return @[@"targetedDeviceProfileName", @"targetedSystemVersion", @"targetedSystemBuild",
             @"targetedHwMachine", @"targetedHwModel", @"targetedScreenHwMachine",
             @"targetedScreenWidth", @"targetedScreenHeight", @"targetedScreenScale",
             @"targetedNativeScreenWidth", @"targetedNativeScreenHeight",
             @"targetedUASystemVersion", @"targetedUASystemBuild",
             @"targetedPushDeviceProfileName", @"targetedPushHwMachine", @"targetedPushHwModel"];
}
static BOOL BDSRandomModeWasRun(NSDictionary *config, NSString *mode) {
    if (![config isKindOfClass:NSDictionary.class] || !mode.length) return NO;
    NSString *flag = [NSString stringWithFormat:@"didRandomize%@%@",
                      [[mode substringToIndex:1] uppercaseString], [mode substringFromIndex:1]];
    id stored = config[flag];
    if (stored) return [stored boolValue];
    if ([mode isEqualToString:@"targeted"] && [config[@"targetedGeneratedAt"] doubleValue] > 0) return YES;
    return [config[@"managerRandomMode"] isEqualToString:mode] &&
           [config[@"managerGeneratedAt"] doubleValue] > 0;
}
static void BDSMarkRandomModeRun(NSMutableDictionary *config, NSString *mode) {
    if (!config || !mode.length) return;
    NSString *flag = [NSString stringWithFormat:@"didRandomize%@%@",
                      [[mode substringToIndex:1] uppercaseString], [mode substringFromIndex:1]];
    config[flag] = @YES;
}
static NSMutableDictionary *BDSConfigForPersistentStorage(NSDictionary *config) {
    NSMutableDictionary *stored = [config mutableCopy] ?: [NSMutableDictionary dictionary];
    BOOL selected = [stored[@"spoofBaiduTargeted"] boolValue];
    if (!selected) {
        for (NSString *key in BDSSelectedTargetKeys()) {
            if ([stored[key] boolValue]) { selected = YES; break; }
        }
    }
    if (!selected && !BDSRandomModeWasRun(stored, @"targeted")) {
        for (NSString *key in BDSTargetedStoredValueKeys()) [stored removeObjectForKey:key];
        [stored removeObjectForKey:@"targetedGeneratedAt"];
    }
    [stored removeObjectForKey:@"managerResolvedPath"];
    return stored;
}
static NSDictionary *BDSSafeSwitchValues(void) {
    NSMutableDictionary *values=[NSMutableDictionary dictionary];
    for(NSString *key in BDSRegularKeys()) values[key]=@NO;
    for(NSString *key in BDSRiskKeys()) values[key]=@NO;
    for(NSString *key in BDSSelectedTargetKeys()) values[key]=@NO;
    values[@"spoofScreen"]=@NO;
    values[@"spoofBaiduTargeted"]=@NO;
    return values;
}
static void BDSSeedInitialIdentities(NSMutableDictionary *config, NSDictionary *saved) {
    for(NSString *key in @[@"idfa",@"idfv",@"deviceID",@"cuid",@"utdid"]) {
        id value=saved[key];
        if([value isKindOfClass:NSString.class] && [value length]) { config[key]=value; continue; }
        NSString *fresh=NSUUID.UUID.UUIDString;
        if([key isEqualToString:@"cuid"] || [key isEqualToString:@"utdid"]) fresh=[fresh stringByReplacingOccurrencesOfString:@"-" withString:@""];
        config[key]=[key isEqualToString:@"utdid"]?fresh.lowercaseString:fresh.uppercaseString;
    }
}
// Initialization is separate from randomization. Explicit saved choices survive.
static void BDSApplyInitialDefaults(NSMutableDictionary *config, NSDictionary *saved) {
    for(NSString *key in BDSRegularKeys()) config[key]=saved[key] ?: @YES;
    for(NSString *key in BDSRiskKeys()) config[key]=saved[key] ?: @NO;
    for(NSString *key in BDSSelectedTargetKeys()) config[key]=saved[key] ?: @NO;
    config[@"spoofBaiduTargeted"]=saved[@"spoofBaiduTargeted"] ?: @NO;
    config[@"spoofScreen"]=@NO;
    config[@"targetedScreenHwMachine"]=saved[@"targetedScreenHwMachine"] ?: config[@"targetedHwMachine"] ?: @"iPhone18,2";
    config[@"configVersion"]=@188;
}
