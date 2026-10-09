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
          @{@"key":@"blockLaunchTimeUpload",@"name":@"拦截启动时间上报"},
          @{@"key":@"blockStatCashTelemetry",@"name":@"阻止金额统计上报"}]
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
    config[@"configVersion"]=@192;
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


// ---- 随机设备名（一键基础时自动配一个）----
//
// 为什么需要：原来是 "iPhone-" + 6 位十六进制（如 iPhone-CB1E42）。
// 这个格式真人不会用 —— 连字符加随机码是明显的程序生成特征；
// 而且多台设备全用同一模板，“整齐”本身就是关联信号。
//
// 三个出口都会读它：UIDevice.name / NSProcessInfo.hostName / kern.hostname，
// 所以必须像真人命名。按中文 iOS 用户的真实习惯分五类加权：
//   名字 + 的iPhone（最多）/ 名字 + 的iPhone 型号 / 家庭称呼 / 网名外号 / 英文名 / 纯型号
// 组合空间约万级，70 台设备偶有重名也正常（真人本来就会重名）。
// 长度全部远小于 32 字符上限。
static NSString *BDSRandomDeviceName(void) {
    static NSArray<NSString *> *surnames;
    static NSArray<NSString *> *givens;
    static NSArray<NSString *> *nicknames;
    static NSArray<NSString *> *family;
    static NSArray<NSString *> *english;
    static NSArray<NSString *> *models;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        surnames = @[@"王", @"李", @"张", @"刘", @"陈", @"杨", @"黄", @"赵", @"吴", @"周",
                     @"徐", @"孙", @"马", @"朱", @"胡", @"郭", @"何", @"林", @"高", @"罗",
                     @"郑", @"梁", @"谢", @"宋", @"唐", @"许", @"韩", @"冯", @"邓", @"曹",
                     @"彭", @"曾", @"肖", @"田", @"董", @"袁", @"潘", @"蒋", @"蔡", @"余",
                     @"杜", @"叶", @"程", @"苏", @"魏", @"吕", @"丁", @"任", @"沈", @"姚",
                     @"卢", @"姜", @"崔", @"钟", @"谭", @"陆", @"汪", @"范", @"金", @"石",
                     @"廖", @"贾", @"夏", @"韦", @"方", @"白", @"邹", @"孟", @"熊", @"秦",
                     @"邱", @"江", @"尹", @"薛", @"段", @"雷", @"侯", @"龙", @"史", @"陶"];
        givens = @[@"伟", @"芳", @"娜", @"敏", @"静", @"丽", @"强", @"磊", @"军", @"洋",
                   @"勇", @"艳", @"杰", @"娟", @"涛", @"明", @"超", @"霞", @"平", @"刚",
                   @"英", @"华", @"玉", @"兰", @"春", @"梅", @"文", @"辉", @"力", @"建",
                   @"波", @"斌", @"宇", @"浩", @"鑫", @"帆", @"琳", @"佳", @"婷", @"雪",
                   @"鹏", @"亮", @"飞", @"龙", @"凯", @"峰", @"阳", @"晨", @"曦", @"涵",
                   @"怡", @"欣", @"悦", @"昊", @"睿", @"哲", @"楠", @"倩", @"颖", @"洁",
                   @"子涵", @"雨欣", @"梓萱", @"一诺", @"浩然", @"子轩", @"沐辰", @"思远",
                   @"若曦", @"语嫣", @"俊杰", @"家豪", @"雅静", @"梦琪", @"婉婷", @"志强",
                   @"建军", @"建华", @"秀英", @"桂英", @"玉梅", @"淑珍", @"秀兰", @"国强",
                   @"晓明", @"晓东", @"小燕", @"小红", @"丹丹", @"莉莉", @"媛媛", @"涛涛"];
        nicknames = @[@"团子", @"土豆", @"大熊", @"喵喵", @"果果", @"大宝", @"小可爱",
                      @"蜜桃", @"布丁", @"崽崽", @"二狗", @"三胖", @"阿杰", @"小胖",
                      @"奶茶", @"豆豆", @"球球", @"小七", @"元宝", @"汤圆"];
        family = @[@"老爸", @"老妈", @"老婆", @"老公", @"闺女", @"儿子", @"弟弟", @"妹妹",
                   @"爷爷", @"奶奶", @"姥姥", @"姥爷", @"姐姐", @"哥哥", @"老爸的",
                   @"老妈的"];
        english = @[@"David", @"Amy", @"Kevin", @"Lily", @"Tom", @"Jack", @"Lucy",
                    @"Sunny", @"Jason", @"Cindy", @"Peter", @"Alice"];
        models = @[@"iPhone", @"iPhone 13", @"iPhone 14", @"iPhone 15", @"iPhone 16",
                   @"iPhone 17"];
    });

    NSUInteger kind = arc4random_uniform(100);
    // 0-44   姓 + 名 + 的iPhone
    // 45-59  老X / 小X / 阿X + 的iPhone 型号
    // 60-74  家庭称呼 + 的iPhone
    // 75-87  网名 / 外号
    // 88-95  英文名
    // 96-99  纯型号
    if (kind < 45) {
        NSString *who = [surnames[arc4random_uniform((uint32_t)surnames.count)]
                         stringByAppendingString:givens[arc4random_uniform((uint32_t)givens.count)]];
        return [who stringByAppendingString:@"的iPhone"];
    }
    if (kind < 60) {
        // 口语叫法：老张、小李、阿杰
        NSUInteger r = arc4random_uniform(3);
        NSString *who;
        if (r == 0) who = [@"老" stringByAppendingString:surnames[arc4random_uniform((uint32_t)surnames.count)]];
        else if (r == 1) who = [@"小" stringByAppendingString:surnames[arc4random_uniform((uint32_t)surnames.count)]];
        else who = [@"阿" stringByAppendingString:givens[arc4random_uniform((uint32_t)givens.count)]];
        return [who stringByAppendingFormat:@"的%@", models[arc4random_uniform((uint32_t)models.count)]];
    }
    // 家庭称呼 + 的iPhone（family 里带“的”的项直接接 iPhone）
    if (kind < 75) {
        NSString *f = family[arc4random_uniform((uint32_t)family.count)];
        return [f hasSuffix:@"的"] ? [f stringByAppendingString:@"iPhone"]
                                   : [f stringByAppendingString:@"的iPhone"];
    }
    // 网名 / 外号
    if (kind < 88) {
        NSString *n = nicknames[arc4random_uniform((uint32_t)nicknames.count)];
        return arc4random_uniform(2) ? [n stringByAppendingString:@"的iPhone"] : n;
    }
    // 英文名
    if (kind < 96) {
        NSString *e = english[arc4random_uniform((uint32_t)english.count)];
        return arc4random_uniform(2) ? [e stringByAppendingString:@"的iPhone"] : e;
    }
    // 纯型号
    return models[arc4random_uniform((uint32_t)models.count)];
}
