#import <Foundation/Foundation.h>

static NSArray<NSArray<NSDictionary *> *> *BDSSettingGroups(void) {
    return @[
        @[@{@"key":@"enabled",@"name":@"基础功能"},
          @{@"key":@"spoofAdvertisingIdentifiers",@"name":@"广告标识参数"},
          @{@"key":@"spoofProcessHardware",@"name":@"主机名与内存参数"},
          @{@"key":@"spoofLocale",@"name":@"语言与地区参数"},
          @{@"key":@"spoofCarrier",@"name":@"运营商参数"},
          @{@"key":@"spoofStorage",@"name":@"存储参数"}],
        @[@{@"key":@"spoofBaiduSDK",@"name":@"百度身份参数"},
          @{@"key":@"spoofSysctl",@"name":@"系统硬件参数"},
          @{@"key":@"bypassJailbreakDetect",@"name":@"防越狱检测",@"off":@YES},
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
// “一键基础”要打开的开关，按组内顺序取前 count 个可改项。
// 关键点：带 @"off":@YES 的项要跳过，不能占名额。
// 否则一旦某个默认关闭的项排在第 count 位之前，它就会被一键基础打开，
// 与“默认关闭”的策略直接打架（防越狱检测、阻止金额统计上报都踩过这个坑）。
// 跳过之后，前面被跳过的名额由后面第一个可改项补上，
// 所以“一键基础打开前 N 个常规开关”的语义保持不变。
static NSArray<NSString *> *BDSFirstEnabledKeys(NSArray<NSDictionary *> *group, NSUInteger count) {
    NSMutableArray *keys=[NSMutableArray array];
    for(NSDictionary *item in group) {
        if([item[@"off"] boolValue]) continue;
        [keys addObject:item[@"key"]];
        if(keys.count>=count) break;
    }
    return keys;
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
    config[@"targetedScreenHwMachine"]=saved[@"targetedScreenHwMachine"] ?: config[@"targetedHwMachine"] ?: @"iPhone14,6";
    // 必须写当前版本号。写成 @187 会把 loadConfig 里已经抬上去的版本又按回去，
    // 导致 ver < 189 之类的迁移每次启动都重复触发（防越狱检测就踩过这个坑）。
    config[@"configVersion"]=@189;
}

// ---- 随机 WiFi SSID（一键基础时自动配一个）----
//
// 为什么需要：插件的 CNCopyCurrentNetworkInfo 钩子只有在 wifiSSID 非空时才返回伪造值，
// 留空则返回 NULL。虽然 NULL 也不算泄露，但“有 Wi-Fi 权限却读不到任何网络”本身不自然。
// 所以一键基础顺手配一个常见的、烂大街的名字，让返回结果看起来像普通用户。
//
// 取名原则：
//   1. 只用真实世界最常见的形态（运营商光猫 / 路由器出厂名 / 大众化个人名）
//   2. 不用随机乱码 —— 生僻名比 NULL 更显眼
//   3. 交给组合生成而不是硬编字符串：多设备场景下（几十台）撞名会变成关联信号，
//      硬编几十个名字必然重复，组合生成可把空间扩到万级
//
// 长度：全部 ASCII 且 <= 20 字节，远小于 g_wifiSSID 的 64 字节缓冲。
static NSString *BDSRandomHexLower(NSUInteger digits) {
    static const char *set = "0123456789abcdef";
    char buf[8];
    if (digits == 0 || digits >= sizeof(buf)) digits = 4;
    for (NSUInteger i = 0; i < digits; i++) buf[i] = set[arc4random_uniform(16)];
    buf[digits] = '\0';
    return [NSString stringWithUTF8String:buf];
}
static NSArray<NSString *> *BDSCommonSSIDPool(void) {
    return @[@"ChinaNet-7Fk2", @"CMCC-5G-Home", @"TP-LINK_5F2A", @"MERCURY_2F88",
             @"Tenda_4A6C20", @"HUAWEI-3F8A", @"Xiaomi_5G", @"NETGEAR-Home",
             @"HOME-2.4G", @"HOME-5G", @"HomeWiFi", @"FamilyWiFi",
             @"WIFI-201", @"WiFi-A1B2", @"MyHome-5G", @"ChinaUnicom-Home"];
}
static NSString *BDSRandomCommonSSID(void) {
    // 四类形态按真实占比加权：运营商光猫最多，其次是路由器出厂名，个人命名其次
    NSUInteger kind = arc4random_uniform(100);
    if (kind < 34) {
        // 运营商光猫：ChinaNet-xxxx / CMCC-xxxx / ChinaUnicom-xxxx / ChinaTelecom-xxxx
        NSArray *isp = @[@"ChinaNet-", @"CMCC-", @"ChinaUnicom-", @"ChinaTelecom-", @"CU-"];
        NSString *p = isp[arc4random_uniform((uint32_t)isp.count)];
        // 光猫后缀有 4 位十六进制，也有 4 位纯数字
        NSString *suffix = arc4random_uniform(2)
            ? BDSRandomHexLower(4)
            : [NSString stringWithFormat:@"%04u", arc4random_uniform(10000)];
        return [p stringByAppendingString:suffix];
    }
    if (kind < 62) {
        // 路由器出厂默认名：TP-LINK_XXXX / MERCURY_XXXX / Tenda_xxxxxx / HUAWEI-XXXX / Xiaomi_XXXX
        NSUInteger r = arc4random_uniform(5);
        if (r == 0) return [@"TP-LINK_" stringByAppendingString:[BDSRandomHexLower(4) uppercaseString]];
        if (r == 1) return [@"MERCURY_" stringByAppendingString:[BDSRandomHexLower(4) uppercaseString]];
        if (r == 2) return [@"Tenda_" stringByAppendingString:BDSRandomHexLower(6)];
        if (r == 3) return [@"HUAWEI-" stringByAppendingString:BDSRandomHexLower(4)];
        return [@"Xiaomi_" stringByAppendingString:[BDSRandomHexLower(4) uppercaseString]];
    }
    if (kind < 82) {
        // 大众化个人命名 + 常见区分后缀
        NSArray *base = @[@"HOME", @"Home", @"MyHome", @"Family", @"WiFi", @"WIFI",
                          @"HomeWiFi", @"MyWiFi", @"House", @"Sweet Home"];
        NSArray *tail = @[@"-2.4G", @"-5G", @"_5G", @"-WiFi", @"_2.4G", @""];
        NSString *b = base[arc4random_uniform((uint32_t)base.count)];
        NSString *s = tail[arc4random_uniform((uint32_t)tail.count)];
        NSString *name = [b stringByAppendingString:s];
        // 一半概率再加个门牌/年份后缀，进一步降低撞名
        if (arc4random_uniform(2)) {
            NSArray *num = @[[NSString stringWithFormat:@"%u", 101 + arc4random_uniform(1900)],
                             [NSString stringWithFormat:@"%u", 2018 + arc4random_uniform(9)]];
            name = [name stringByAppendingFormat:@"-%@", num[arc4random_uniform(2)]];
        }
        return name;
    }
    // 少量固定形态，取自真实常见名（保留原池，分布上更自然）
    NSArray *fixed = BDSCommonSSIDPool();
    return fixed[arc4random_uniform((uint32_t)fixed.count)];
}
