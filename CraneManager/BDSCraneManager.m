#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <limits.h>
#import <stdlib.h>

static NSString * const BDSBaiduBundleID = @"com.baidu.BaiduMobileInfo";
static NSString * const BDSConfigFileName = @"bdspoofer_config.plist";

typedef NS_ENUM(NSInteger, BDSCraneContainerPathType) {
    BDSCraneContainerPathTypeApp = 0,
    BDSCraneContainerPathTypeGroup = 1,
    BDSCraneContainerPathTypePlugin = 2,
};

@interface CraneManager : NSObject
+ (instancetype)sharedManager;
- (BOOL)isApplicationSupportedByCrane:(NSString *)applicationID;
- (NSArray *)containerIdentifiersOfApplicationWithIdentifier:(NSString *)applicationID;
- (NSString *)activeContainerIdentifierForApplicationWithIdentifier:(NSString *)applicationID;
- (NSString *)displayNameForContainerWithIdentifier:(NSString *)containerID
                             ofApplicationWithIdentifier:(NSString *)applicationID
                                   shouldUseShortVersion:(BOOL)shortVersion;
- (void)enumerate:(void (^)(BDSCraneContainerPathType type, NSString *identifier, NSString *path))block
        pathsAssociatedToContainerWithIdentifier:(NSString *)containerID
                          ofApplicationWithIdentifier:(NSString *)applicationID;
- (NSDictionary *)pathsAssociatedToContainerWithIdentifier:(NSString *)containerID
                            ofApplicationWithIdentifier:(NSString *)applicationID;
@end

@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)applicationIdentifier;
@property(nonatomic, readonly) NSURL *dataContainerURL;
@end

static NSDictionary *BDSDevice(NSString *name, NSString *machine, NSString *model,
                               NSInteger width, NSInteger height,
                               NSInteger nativeWidth, NSInteger nativeHeight,
                               NSInteger scale, NSInteger memory,
                               NSArray<NSNumber *> *disks, NSString *minimumOS,
                               NSInteger maximumMajor) {
    return @{
        @"name": name, @"machine": machine, @"model": model,
        @"width": @(width), @"height": @(height),
        @"nativeWidth": @(nativeWidth), @"nativeHeight": @(nativeHeight),
        @"scale": @(scale), @"memory": @(memory), @"disks": disks,
        @"minimumOS": minimumOS, @"maximumMajor": @(maximumMajor)
    };
}

static NSArray<NSDictionary *> *BDSDeviceProfiles(void) {
    static NSArray<NSDictionary *> *profiles;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        profiles = @[
            BDSDevice(@"iPhone 8", @"iPhone10,1", @"D20AP", 375, 667, 750, 1334, 2, 2048, @[@64,@256], @"15.0", 16),
            BDSDevice(@"iPhone 8 Plus", @"iPhone10,2", @"D21AP", 414, 736, 1080, 1920, 3, 3072, @[@64,@256], @"15.0", 16),
            BDSDevice(@"iPhone X", @"iPhone10,3", @"D22AP", 375, 812, 1125, 2436, 3, 3072, @[@64,@256], @"15.0", 16),
            BDSDevice(@"iPhone XR", @"iPhone11,8", @"N841AP", 414, 896, 828, 1792, 2, 3072, @[@64,@128,@256], @"15.0", 18),
            BDSDevice(@"iPhone XS", @"iPhone11,2", @"D321AP", 375, 812, 1125, 2436, 3, 4096, @[@64,@256,@512], @"15.0", 18),
            BDSDevice(@"iPhone XS Max", @"iPhone11,6", @"D331pAP", 414, 896, 1242, 2688, 3, 4096, @[@64,@256,@512], @"15.0", 18),
            BDSDevice(@"iPhone 11", @"iPhone12,1", @"N104AP", 414, 896, 828, 1792, 2, 4096, @[@64,@128,@256], @"15.0", 26),
            BDSDevice(@"iPhone 11 Pro", @"iPhone12,3", @"D421AP", 375, 812, 1125, 2436, 3, 4096, @[@64,@256,@512], @"15.0", 26),
            BDSDevice(@"iPhone 11 Pro Max", @"iPhone12,5", @"D431AP", 414, 896, 1242, 2688, 3, 4096, @[@64,@256,@512], @"15.0", 26),
            // iPhone SE (2nd generation) is intentionally excluded until explicitly requested.
            BDSDevice(@"iPhone 12 mini", @"iPhone13,1", @"D52gAP", 375, 812, 1080, 2340, 3, 4096, @[@64,@128,@256], @"15.0", 26),
            BDSDevice(@"iPhone 12", @"iPhone13,2", @"D53gAP", 390, 844, 1170, 2532, 3, 4096, @[@64,@128,@256], @"15.0", 26),
            BDSDevice(@"iPhone 12 Pro", @"iPhone13,3", @"D53pAP", 390, 844, 1170, 2532, 3, 6144, @[@128,@256,@512], @"15.0", 26),
            BDSDevice(@"iPhone 12 Pro Max", @"iPhone13,4", @"D54pAP", 428, 926, 1284, 2778, 3, 6144, @[@128,@256,@512], @"15.0", 26),
            BDSDevice(@"iPhone 13 mini", @"iPhone14,4", @"D16AP", 375, 812, 1080, 2340, 3, 4096, @[@128,@256,@512], @"15.0", 26),
            BDSDevice(@"iPhone 13", @"iPhone14,5", @"D17AP", 390, 844, 1170, 2532, 3, 4096, @[@128,@256,@512], @"15.0", 26),
            BDSDevice(@"iPhone 13 Pro", @"iPhone14,2", @"D63AP", 390, 844, 1170, 2532, 3, 6144, @[@128,@256,@512,@1024], @"15.0", 26),
            BDSDevice(@"iPhone 13 Pro Max", @"iPhone14,3", @"D64AP", 428, 926, 1284, 2778, 3, 6144, @[@128,@256,@512,@1024], @"15.0", 26),
            BDSDevice(@"iPhone SE (3rd generation)", @"iPhone14,6", @"D49AP", 375, 667, 750, 1334, 2, 4096, @[@64,@128,@256], @"15.4", 26),
            BDSDevice(@"iPhone 14", @"iPhone14,7", @"D27AP", 390, 844, 1170, 2532, 3, 6144, @[@128,@256,@512], @"16.0", 26),
            BDSDevice(@"iPhone 14 Pro", @"iPhone15,2", @"D73AP", 393, 852, 1179, 2556, 3, 6144, @[@128,@256,@512,@1024], @"16.0", 26),
            BDSDevice(@"iPhone 14 Pro Max", @"iPhone15,3", @"D74AP", 430, 932, 1290, 2796, 3, 6144, @[@128,@256,@512,@1024], @"16.0", 26),
            BDSDevice(@"iPhone 14 Plus", @"iPhone14,8", @"D28AP", 428, 926, 1284, 2778, 3, 6144, @[@128,@256,@512], @"16.0.2", 26),
            BDSDevice(@"iPhone 15", @"iPhone15,4", @"D37AP", 393, 852, 1179, 2556, 3, 6144, @[@128,@256,@512], @"17.0", 26),
            BDSDevice(@"iPhone 15 Plus", @"iPhone15,5", @"D38AP", 430, 932, 1290, 2796, 3, 6144, @[@128,@256,@512], @"17.0", 26),
            BDSDevice(@"iPhone 15 Pro", @"iPhone16,1", @"D83AP", 393, 852, 1179, 2556, 3, 8192, @[@128,@256,@512,@1024], @"17.0", 26),
            BDSDevice(@"iPhone 15 Pro Max", @"iPhone16,2", @"D84AP", 430, 932, 1290, 2796, 3, 8192, @[@256,@512,@1024], @"17.0", 26),
            BDSDevice(@"iPhone 16", @"iPhone17,3", @"D47AP", 393, 852, 1179, 2556, 3, 8192, @[@128,@256,@512], @"18.0", 26),
            BDSDevice(@"iPhone 16 Plus", @"iPhone17,4", @"D48AP", 430, 932, 1290, 2796, 3, 8192, @[@128,@256,@512], @"18.0", 26),
            BDSDevice(@"iPhone 16 Pro", @"iPhone17,1", @"D93AP", 402, 874, 1206, 2622, 3, 8192, @[@128,@256,@512,@1024], @"18.0", 26),
            BDSDevice(@"iPhone 16 Pro Max", @"iPhone17,2", @"D94AP", 440, 956, 1320, 2868, 3, 8192, @[@256,@512,@1024], @"18.0", 26),
            BDSDevice(@"iPhone 16e", @"iPhone17,5", @"V59AP", 390, 844, 1170, 2532, 3, 8192, @[@128,@256,@512], @"18.3.1", 26),
            BDSDevice(@"iPhone 17", @"iPhone18,3", @"V57AP", 402, 874, 1206, 2622, 3, 8192, @[@256,@512], @"26.0", 26),
            BDSDevice(@"iPhone 17 Pro", @"iPhone18,1", @"V53AP", 402, 874, 1206, 2622, 3, 12288, @[@256,@512,@1024], @"26.0", 26),
            BDSDevice(@"iPhone 17 Pro Max", @"iPhone18,2", @"V54AP", 440, 956, 1320, 2868, 3, 12288, @[@256,@512,@1024], @"26.0", 26),
            BDSDevice(@"iPhone Air", @"iPhone18,4", @"D23AP", 420, 912, 1260, 2736, 3, 12288, @[@256,@512,@1024], @"26.0", 26),
            BDSDevice(@"iPhone 17e", @"iPhone18,5", @"V159AP", 390, 844, 1170, 2532, 3, 8192, @[@128,@256,@512], @"26.3.1", 26),
        ];
    });
    return profiles;
}

static NSDictionary *BDSSystem(NSString *version, NSString *build) {
    return @{@"version": version, @"build": build};
}

static NSArray<NSDictionary *> *BDSSystemProfiles(void) {
    static NSArray<NSDictionary *> *profiles;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        profiles = @[
            BDSSystem(@"15.0", @"19A346"), BDSSystem(@"15.0.2", @"19A404"),
            BDSSystem(@"15.1.1", @"19B81"), BDSSystem(@"15.2.1", @"19C63"),
            BDSSystem(@"15.3", @"19D50"), BDSSystem(@"15.3.1", @"19D52"),
            BDSSystem(@"15.4", @"19E241"), BDSSystem(@"15.4.1", @"19E258"),
            BDSSystem(@"15.5", @"19F77"), BDSSystem(@"15.6", @"19G71"),
            BDSSystem(@"15.6.1", @"19G82"), BDSSystem(@"15.7", @"19H12"),
            BDSSystem(@"15.7.1", @"19H117"),
            BDSSystem(@"16.0", @"20A362"), BDSSystem(@"16.0.2", @"20A380"),
            BDSSystem(@"16.0.3", @"20A392"), BDSSystem(@"16.1", @"20B82"),
            BDSSystem(@"16.1.1", @"20B101"), BDSSystem(@"16.1.2", @"20B110"),
            BDSSystem(@"16.2", @"20C65"), BDSSystem(@"16.3", @"20D47"),
            BDSSystem(@"16.3.1", @"20D67"), BDSSystem(@"16.4", @"20E247"),
            BDSSystem(@"16.4.1", @"20E252"), BDSSystem(@"16.5", @"20F66"),
            BDSSystem(@"16.5.1", @"20F75"), BDSSystem(@"16.6", @"20G75"),
            BDSSystem(@"16.6.1", @"20G81"), BDSSystem(@"16.7", @"20H19"),
            BDSSystem(@"16.7.1", @"20H30"), BDSSystem(@"16.7.2", @"20H115"),
            BDSSystem(@"16.7.15", @"20H380"), BDSSystem(@"16.7.16", @"20H392"),
            BDSSystem(@"17.0", @"21A329"), BDSSystem(@"17.0.1", @"21A340"),
            BDSSystem(@"17.0.2", @"21A351"), BDSSystem(@"17.0.3", @"21A360"),
            BDSSystem(@"17.1", @"21B74"), BDSSystem(@"17.1.1", @"21B91"),
            BDSSystem(@"17.1.2", @"21B101"), BDSSystem(@"17.2", @"21C62"),
            BDSSystem(@"17.2.1", @"21C66"), BDSSystem(@"17.3", @"21D50"),
            BDSSystem(@"17.3.1", @"21D61"), BDSSystem(@"17.4", @"21E219"),
            BDSSystem(@"17.4.1", @"21E236"), BDSSystem(@"17.5", @"21F79"),
            BDSSystem(@"17.5.1", @"21F90"), BDSSystem(@"17.6", @"21G80"),
            BDSSystem(@"17.6.1", @"21G93"), BDSSystem(@"17.7", @"21H16"),
            BDSSystem(@"17.7.1", @"21H216"), BDSSystem(@"17.7.2", @"21H221"),
            BDSSystem(@"18.0", @"22A3354"), BDSSystem(@"18.0.1", @"22A3370"),
            BDSSystem(@"18.1", @"22B83"), BDSSystem(@"18.1.1", @"22B91"),
            BDSSystem(@"18.2", @"22C152"), BDSSystem(@"18.2.1", @"22C161"),
            BDSSystem(@"18.3", @"22D63"), BDSSystem(@"18.3.1", @"22D72"),
            BDSSystem(@"18.3.2", @"22D82"), BDSSystem(@"18.4", @"22E240"),
            BDSSystem(@"18.4.1", @"22E252"), BDSSystem(@"18.5", @"22F76"),
            BDSSystem(@"18.6", @"22G86"), BDSSystem(@"18.6.1", @"22G90"),
            BDSSystem(@"18.6.2", @"22G100"), BDSSystem(@"18.7", @"22H20"),
            BDSSystem(@"18.7.1", @"22H31"), BDSSystem(@"18.7.2", @"22H123"),
            BDSSystem(@"18.7.9", @"22H355"), BDSSystem(@"18.7.10", @"22H374"),
            BDSSystem(@"26.4.2", @"23E261"), BDSSystem(@"26.5", @"23F77"),
            BDSSystem(@"26.5.2", @"23F84"), BDSSystem(@"26.6", @"23G71"),
            BDSSystem(@"26.6.1", @"23G83"),
        ];
    });
    return profiles;
}

static NSString *BDSRandomHex(NSUInteger count, BOOL uppercase) {
    static const char *hex = "0123456789abcdef";
    NSMutableString *value = [NSMutableString stringWithCapacity:count];
    for (NSUInteger i = 0; i < count; i++) {
        [value appendFormat:@"%c", hex[arc4random_uniform(16)]];
    }
    return uppercase ? value.uppercaseString : value;
}

static BOOL BDSVersionInRange(NSString *version, NSDictionary *device) {
    NSString *minimum = device[@"minimumOS"];
    NSInteger maximumMajor = [device[@"maximumMajor"] integerValue];
    if ([version compare:minimum options:NSNumericSearch] == NSOrderedAscending) return NO;
    if (version.integerValue > maximumMajor) return NO;

    NSString *machine = device[@"machine"];
    if ([version hasPrefix:@"18.7.9"] || [version hasPrefix:@"18.7.10"]) {
        return [machine hasPrefix:@"iPhone11,"];
    }
    if (version.integerValue == 26 && ![machine hasPrefix:@"iPhone12,"] &&
        ![machine hasPrefix:@"iPhone13,"] && ![machine hasPrefix:@"iPhone14,"] &&
        ![machine hasPrefix:@"iPhone15,"] && ![machine hasPrefix:@"iPhone16,"] &&
        ![machine hasPrefix:@"iPhone17,"] && ![machine hasPrefix:@"iPhone18,"]) {
        return NO;
    }
    return YES;
}

static NSDictionary *BDSRandomSystemForDevice(NSDictionary *device) {
    NSMutableDictionary<NSNumber *, NSMutableArray<NSDictionary *> *> *byMajor = [NSMutableDictionary dictionary];
    for (NSDictionary *profile in BDSSystemProfiles()) {
        NSString *version = profile[@"version"];
        if (!BDSVersionInRange(version, device)) continue;
        NSNumber *major = @(version.integerValue);
        if (!byMajor[major]) byMajor[major] = [NSMutableArray array];
        [byMajor[major] addObject:profile];
    }
    NSArray<NSNumber *> *majors = [[byMajor allKeys] sortedArrayUsingSelector:@selector(compare:)];
    if (!majors.count) return BDSSystemProfiles().firstObject;
    NSNumber *major = majors[arc4random_uniform((uint32_t)majors.count)];
    NSArray *versions = byMajor[major];
    return versions[arc4random_uniform((uint32_t)versions.count)];
}

static NSDictionary *BDSDefaultConfig(void) {
    NSString *templatePath = [[NSBundle mainBundle] pathForResource:@"bdspoofer_config" ofType:@"plist"];
    NSDictionary *templateConfig = templatePath ? [NSDictionary dictionaryWithContentsOfFile:templatePath] : nil;
    return templateConfig ?: @{};
}

static NSDictionary *BDSRandomCarrier(void) {
    NSArray *carriers = @[
        @{@"carrierName": @"中国移动", @"mcc": @"460", @"mnc": @"00", @"isoCountryCode": @"cn"},
        @{@"carrierName": @"中国联通", @"mcc": @"460", @"mnc": @"01", @"isoCountryCode": @"cn"},
        @{@"carrierName": @"中国电信", @"mcc": @"460", @"mnc": @"03", @"isoCountryCode": @"cn"},
    ];
    return carriers[arc4random_uniform((uint32_t)carriers.count)];
}

typedef NS_ENUM(NSInteger, BDSRandomMode) {
    BDSRandomModeBasic = 0,
    BDSRandomModeAdvanced = 1,
    BDSRandomModeTargeted = 2,
};

static NSArray<NSString *> *BDSTargetedKeys(void) {
    return @[@"spoofBaiduTargetedSystem", @"spoofBaiduTargetedModel",
             @"spoofBaiduTargetedScreen", @"spoofBaiduTargetedUA",
             @"spoofBaiduTargetedPush"];
}

static NSArray<NSString *> *BDSTargetedNames(void) {
    return @[@"系统版本", @"机型标识", @"屏幕参数", @"User-Agent", @"Push参数"];
}

static void BDSSeedIdentityIfNeeded(NSMutableDictionary *config, BOOL force) {
    if (!force && config[@"idfa"] && config[@"idfv"] && config[@"deviceID"] &&
        config[@"cuid"] && config[@"utdid"]) return;
    config[@"idfa"] = NSUUID.UUID.UUIDString.uppercaseString;
    config[@"idfv"] = NSUUID.UUID.UUIDString.uppercaseString;
    config[@"deviceID"] = NSUUID.UUID.UUIDString.uppercaseString;
    config[@"cuid"] = BDSRandomHex(32, YES);
    config[@"utdid"] = BDSRandomHex(32, NO);
}

static NSMutableDictionary *BDSMergedConfig(NSDictionary *existing) {
    NSMutableDictionary *config = [BDSDefaultConfig() mutableCopy];
    if (existing.count) [config addEntriesFromDictionary:existing];
    NSInteger version = [existing[@"configVersion"] integerValue];
    if (version < 185) {
        // 与插件 v185 迁移保持一致：首次升级将 5 个定向选择重置为关闭，并拆出 UA/Push 独立参数。
        config[@"targetedUASystemVersion"] = existing[@"targetedUASystemVersion"] ?: config[@"targetedSystemVersion"] ?: @"15.4.1";
        config[@"targetedUASystemBuild"] = existing[@"targetedUASystemBuild"] ?: config[@"targetedSystemBuild"] ?: @"19E258";
        config[@"targetedPushDeviceProfileName"] = existing[@"targetedPushDeviceProfileName"] ?: config[@"targetedDeviceProfileName"] ?: @"iPhone SE (3rd generation)";
        config[@"targetedPushHwMachine"] = existing[@"targetedPushHwMachine"] ?: config[@"targetedHwMachine"] ?: @"iPhone14,6";
        config[@"targetedPushHwModel"] = existing[@"targetedPushHwModel"] ?: config[@"targetedHwModel"] ?: @"D49AP";
        config[@"spoofBaiduTargeted"] = @NO;
        for (NSString *key in BDSTargetedKeys()) config[key] = @NO;
    }
    config[@"configVersion"] = @185;
    return config;
}

static NSMutableDictionary *BDSCreateConfigForDevice(NSDictionary *existing,
                                                       NSDictionary *device,
                                                       BDSRandomMode mode,
                                                       NSSet<NSString *> *selectedTargetedKeys) {
    if (![device isKindOfClass:NSDictionary.class]) return nil;
    if (mode == BDSRandomModeTargeted && !selectedTargetedKeys.count) return nil;
    BOOL hadExistingConfig = existing.count > 0;
    NSMutableDictionary *config = BDSMergedConfig(existing);

    NSDictionary *system = BDSRandomSystemForDevice(device);

    [config addEntriesFromDictionary:@{
        @"configVersion": @185,
        @"enabled": @YES,
        @"spoofAdvertisingIdentifiers": @YES,
        @"spoofProcessHardware": @YES,
        @"spoofLocale": @YES,
        @"spoofCarrier": @YES,
        @"spoofScreen": @NO,
        @"spoofStorage": @YES,
        @"spoofBaiduSDK": @YES,
        @"spoofSysctl": @YES,
        @"bypassJailbreakDetect": @YES,
        @"spoofWiFi": @YES,
        @"spoofLocalIP": @YES,
        @"spoofPasteboard": @YES,
        @"spoofBootTime": @YES,
        @"spoofCPU": @YES,
        @"spoofLocation": @YES,
        @"spoofProxyDetection": @YES,
        @"spoofStatfs": @YES,
        @"spoofDlopen": @YES,
        @"spoofUbiquity": @YES,
        @"spoofPrivacyPermissions": @YES,
        @"spoofBattery": @YES,
        @"managerGeneratedAt": @([[NSDate date] timeIntervalSince1970]),
        @"managerProfileVersion": @107,
        @"managerRandomMode": mode == BDSRandomModeTargeted ? @"targeted" : @"basic",
    }];

    if (mode == BDSRandomModeBasic) {
        NSArray *disks = device[@"disks"];
        if (![disks isKindOfClass:NSArray.class] || !disks.count) return nil;
        NSNumber *disk = disks[arc4random_uniform((uint32_t)disks.count)];
        NSString *deviceName = [NSString stringWithFormat:@"iPhone-%@", [BDSRandomHex(6, YES) uppercaseString]];
        [config addEntriesFromDictionary:@{
            @"spoofBaiduTargeted": @NO,
            @"spoofBaiduTargetedSystem": @NO,
            @"spoofBaiduTargetedModel": @NO,
            @"spoofBaiduTargetedScreen": @NO,
            @"spoofBaiduTargetedUA": @NO,
            @"spoofBaiduTargetedPush": @NO,
            @"deviceProfileName": device[@"name"],
            @"deviceModel": @"iPhone",
            @"marketingModel": @"iPhone",
            @"systemVersion": system[@"version"],
            @"systemBuild": system[@"build"],
            @"kernOSVersion": system[@"build"],
            @"hwMachine": device[@"machine"],
            @"hwModel": device[@"model"],
            @"memorySize": device[@"memory"],
            @"diskSize": disk,
            @"deviceName": deviceName,
            @"kernHostname": deviceName,
            @"screenWidth": device[@"width"],
            @"screenHeight": device[@"height"],
            @"screenScale": device[@"scale"],
            @"nativeScreenWidth": device[@"nativeWidth"],
            @"nativeScreenHeight": device[@"nativeHeight"],
            @"bootTimeOffsetSeconds": @(86400 + arc4random_uniform(7 * 86400)),
        }];
        [config addEntriesFromDictionary:BDSRandomCarrier()];
    } else {
        // 只开启并随机用户预先选择的类别；未选类别保持关闭且参数不变。
        config[@"spoofBaiduTargeted"] = @YES;
        for (NSString *key in BDSTargetedKeys()) config[key] = @([selectedTargetedKeys containsObject:key]);
        config[@"targetedGeneratedAt"] = @([[NSDate date] timeIntervalSince1970]);
        if ([selectedTargetedKeys containsObject:@"spoofBaiduTargetedSystem"]) {
            // 系统组同时更新公共系统出口和百度定向出口，避免返回真机/旧基础版本。
            config[@"systemVersion"] = system[@"version"];
            config[@"systemBuild"] = system[@"build"];
            config[@"kernOSVersion"] = system[@"build"];
            config[@"targetedSystemVersion"] = system[@"version"];
            config[@"targetedSystemBuild"] = system[@"build"];
        }
        if ([selectedTargetedKeys containsObject:@"spoofBaiduTargetedModel"]) {
            NSArray<NSNumber *> *disks = device[@"disks"];
            NSNumber *disk = ([disks isKindOfClass:NSArray.class] && disks.count)
                ? disks[arc4random_uniform((uint32_t)disks.count)] : @64;
            config[@"deviceProfileName"] = device[@"name"];
            config[@"deviceModel"] = @"iPhone";
            config[@"marketingModel"] = @"iPhone";
            config[@"hwMachine"] = device[@"machine"];
            config[@"hwModel"] = device[@"model"];
            config[@"memorySize"] = device[@"memory"];
            config[@"diskSize"] = disk;
            config[@"targetedDeviceProfileName"] = device[@"name"];
            config[@"targetedHwMachine"] = device[@"machine"];
            config[@"targetedHwModel"] = device[@"model"];
        }
        if ([selectedTargetedKeys containsObject:@"spoofBaiduTargetedScreen"]) {
            // 保存匹配资料，但 spoofScreen 仍保持 NO，不改变真机 UIKit 布局。
            config[@"screenWidth"] = device[@"width"];
            config[@"screenHeight"] = device[@"height"];
            config[@"screenScale"] = device[@"scale"];
            config[@"nativeScreenWidth"] = device[@"nativeWidth"];
            config[@"nativeScreenHeight"] = device[@"nativeHeight"];
            config[@"targetedScreenWidth"] = device[@"width"];
            config[@"targetedScreenHeight"] = device[@"height"];
            config[@"targetedScreenScale"] = device[@"scale"];
            config[@"targetedNativeScreenWidth"] = device[@"nativeWidth"];
            config[@"targetedNativeScreenHeight"] = device[@"nativeHeight"];
        }
        if ([selectedTargetedKeys containsObject:@"spoofBaiduTargetedUA"]) {
            config[@"targetedUASystemVersion"] = system[@"version"];
            config[@"targetedUASystemBuild"] = system[@"build"];
        }
        if ([selectedTargetedKeys containsObject:@"spoofBaiduTargetedPush"]) {
            config[@"targetedPushDeviceProfileName"] = device[@"name"];
            config[@"targetedPushHwMachine"] = device[@"machine"];
            config[@"targetedPushHwModel"] = device[@"model"];
        }
    }
    // 新容器必须有独立种子；已有容器的长期身份值在基础/定向随机时保持不变。
    if (!hadExistingConfig) BDSSeedIdentityIfNeeded(config, YES);
    return config;
}

static NSMutableDictionary *BDSCreateRandomConfig(NSDictionary *existing,
                                                   BDSRandomMode mode,
                                                   NSSet<NSString *> *selectedTargetedKeys) {
    if (mode == BDSRandomModeAdvanced) {
        NSMutableDictionary *config = BDSMergedConfig(existing);
        config[@"managerGeneratedAt"] = @([[NSDate date] timeIntervalSince1970]);
        config[@"managerProfileVersion"] = @107;
        config[@"managerRandomMode"] = @"advanced";
        // 与插件“一键高级”一致：只更换五个长期身份值，所有参数和开关保持原状态。
        BDSSeedIdentityIfNeeded(config, YES);
        return config;
    }
    NSArray<NSDictionary *> *devices = BDSDeviceProfiles();
    if (!devices.count) return nil;
    NSDictionary *device = devices[arc4random_uniform((uint32_t)devices.count)];
    return BDSCreateConfigForDevice(existing, device, mode, selectedTargetedKeys);
}

static NSString *gCraneLoadDetail;

static void BDSAddCraneCandidate(NSMutableOrderedSet<NSString *> *candidates, NSString *path) {
    if (path.length) [candidates addObject:path];
}

static void BDSAddCraneCandidateFromAppPath(NSMutableOrderedSet<NSString *> *candidates,
                                            NSString *appPath) {
    if (!appPath.length) return;
    NSRange marker = [appPath rangeOfString:@"/Applications/" options:NSBackwardsSearch];
    if (marker.location == NSNotFound) return;
    NSString *jailbreakRoot = [appPath substringToIndex:marker.location];
    BDSAddCraneCandidate(candidates,
        [jailbreakRoot stringByAppendingPathComponent:@"usr/lib/libcrane.dylib"]);
}

static void *BDSLoadCraneLibrary(void) {
    static void *cachedHandle;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSMutableOrderedSet<NSString *> *candidates = [NSMutableOrderedSet orderedSet];

        // RootHide registers jailbreak apps using their randomized physical jbroot path.
        // Derive the matching usr/lib from our own bundle before trying generic paths.
        NSString *bundlePath = NSBundle.mainBundle.bundlePath;
        BDSAddCraneCandidateFromAppPath(candidates, bundlePath);
        char resolved[PATH_MAX] = {0};
        if (realpath(bundlePath.fileSystemRepresentation, resolved)) {
            BDSAddCraneCandidateFromAppPath(candidates, [NSString stringWithUTF8String:resolved]);
        }

        BDSAddCraneCandidate(candidates, @"@rpath/libcrane.dylib");
        BDSAddCraneCandidate(candidates, @"libcrane.dylib");
        BDSAddCraneCandidate(candidates, @"/usr/lib/libcrane.dylib");
        BDSAddCraneCandidate(candidates, @"/var/jb/usr/lib/libcrane.dylib");
        // The cracked RootHide build keeps a stable package mirror; use it only as a fallback.
        BDSAddCraneCandidate(candidates, @"/var/mobile/Library/pkgmirror/usr/lib/libcrane.dylib");

        NSMutableArray<NSString *> *errors = [NSMutableArray array];
        for (NSString *candidate in candidates) {
            dlerror();
            void *handle = dlopen(candidate.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL);
            if (handle) {
                cachedHandle = handle;
                gCraneLoadDetail = [NSString stringWithFormat:@"已加载：%@", candidate];
                break;
            }
            const char *error = dlerror();
            if (error) [errors addObject:[NSString stringWithFormat:@"%@：%s", candidate, error]];
        }
        if (!cachedHandle) {
            NSString *lastError = errors.lastObject ?: @"dlopen 没有返回具体错误";
            gCraneLoadDetail = [NSString stringWithFormat:@"App：%@\n%@", bundlePath, lastError];
        }
    });
    return cachedHandle;
}

@interface BDSManagerViewController : UITableViewController
@property(nonatomic, strong) CraneManager *crane;
@property(nonatomic, strong) NSArray<NSDictionary *> *containers;
@property(nonatomic, strong) NSMutableSet<NSString *> *selectedContainerIDs;
@property(nonatomic, copy) NSString *activeContainerID;
@property(nonatomic, copy) NSString *baiduBaseDataPath;
@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, strong) UIButton *basicButton;
@property(nonatomic, strong) UIButton *advancedButton;
@property(nonatomic, strong) UIButton *targetedButton;
@property(nonatomic, strong) NSMutableSet<NSString *> *targetedSelectionKeys;
@property(nonatomic, strong) NSArray<UIButton *> *targetedOptionButtons;
- (void)randomizeBasicForSelectedContainers;
- (void)randomizeAdvancedForSelectedContainers;
- (void)randomizeTargetedForSelectedContainers;
- (void)toggleTargetedOption:(UIButton *)sender;
- (void)refreshTargetedOptionButtons;
- (void)applySelectedContainersWithMode:(BDSRandomMode)mode;
@end

static NSString *BDSContainerSummary(NSDictionary *config) {
    if (![config isKindOfClass:NSDictionary.class]) return @"尚未写入参数";

    NSString *basicName = config[@"deviceProfileName"] ?: @"未知机型";
    NSString *basicSystem = config[@"systemVersion"] ?: @"未知";
    NSMutableString *summary = [NSMutableString stringWithFormat:@"基础：%@ · iOS %@", basicName, basicSystem];

    if ([config[@"spoofBaiduTargeted"] boolValue]) {
        NSMutableArray<NSString *> *targeted = [NSMutableArray array];
        if ([config[@"spoofBaiduTargetedModel"] boolValue]) {
            [targeted addObject:config[@"targetedDeviceProfileName"] ?: @"未知机型"];
        }
        if ([config[@"spoofBaiduTargetedSystem"] boolValue]) {
            [targeted addObject:[NSString stringWithFormat:@"iOS %@", config[@"targetedSystemVersion"] ?: @"未知"]];
        }
        if (!targeted.count) {
            NSArray<NSString *> *keys = BDSTargetedKeys();
            NSArray<NSString *> *names = BDSTargetedNames();
            for (NSUInteger i = 0; i < keys.count && i < names.count; i++) {
                if ([config[keys[i]] boolValue]) [targeted addObject:names[i]];
            }
        }
        if (targeted.count) [summary appendFormat:@"\n定向：%@", [targeted componentsJoinedByString:@" · "]];
    }
    return summary;
}

static NSString *BDSTargetedResultDetail(NSDictionary *config, NSSet<NSString *> *selection) {
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    if ([selection containsObject:@"spoofBaiduTargetedModel"]) {
        [lines addObject:[NSString stringWithFormat:@"定向机型：%@（%@ / %@）",
            config[@"targetedDeviceProfileName"] ?: @"未知机型",
            config[@"targetedHwMachine"] ?: @"未知",
            config[@"targetedHwModel"] ?: @"未知"]];
    }
    if ([selection containsObject:@"spoofBaiduTargetedSystem"]) {
        [lines addObject:[NSString stringWithFormat:@"定向系统：iOS %@（%@）",
            config[@"targetedSystemVersion"] ?: @"未知",
            config[@"targetedSystemBuild"] ?: @"未知"]];
    }
    if ([selection containsObject:@"spoofBaiduTargetedScreen"]) {
        [lines addObject:[NSString stringWithFormat:@"定向屏幕：%@×%@ @%@x，物理 %@×%@",
            config[@"targetedScreenWidth"] ?: @0,
            config[@"targetedScreenHeight"] ?: @0,
            config[@"targetedScreenScale"] ?: @0,
            config[@"targetedNativeScreenWidth"] ?: @0,
            config[@"targetedNativeScreenHeight"] ?: @0]];
    }
    if ([selection containsObject:@"spoofBaiduTargetedUA"]) {
        [lines addObject:[NSString stringWithFormat:@"定向 User-Agent：iOS %@（%@）",
            config[@"targetedUASystemVersion"] ?: @"未知",
            config[@"targetedUASystemBuild"] ?: @"未知"]];
    }
    if ([selection containsObject:@"spoofBaiduTargetedPush"]) {
        [lines addObject:[NSString stringWithFormat:@"定向 Push：%@（%@）",
            config[@"targetedPushDeviceProfileName"] ?: @"未知机型",
            config[@"targetedPushHwMachine"] ?: @"未知"]];
    }
    return [lines componentsJoinedByString:@"\n"];
}

@implementation BDSManagerViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"卍解";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.selectedContainerIDs = [NSMutableSet set];
    self.targetedSelectionKeys = [NSMutableSet set];
    self.tableView.rowHeight = 68.0;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(reloadContainers)];
    [self buildHeaderAndFooter];
    [self reloadContainers];
}

- (void)buildHeaderAndFooter {
    CGFloat width = UIScreen.mainScreen.bounds.size.width;
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, width, 118)];
    UILabel *label = [[UILabel alloc] initWithFrame:CGRectInset(header.bounds, 18, 12)];
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    label.numberOfLines = 0;
    label.font = [UIFont systemFontOfSize:14];
    label.textColor = UIColor.secondaryLabelColor;
    label.text = @"选择一个或多个百度 Crane 容器，再选择基础、高级或定向随机。配置会提前写入各自 Documents；首次打开未运行容器即可生效。36 款机型，SE2 已排除。";
    [header addSubview:label];
    self.tableView.tableHeaderView = header;

    UIView *footer = [[UIView alloc] initWithFrame:CGRectMake(0, 0, width, 376)];
    UILabel *targetedLabel = [[UILabel alloc] initWithFrame:CGRectMake(18, 8, width - 36, 26)];
    targetedLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    targetedLabel.font = [UIFont boldSystemFontOfSize:15];
    targetedLabel.textColor = UIColor.secondaryLabelColor;
    targetedLabel.text = @"定向指纹项目（先选择，再点定向随机）";
    [footer addSubview:targetedLabel];

    NSMutableArray<UIButton *> *optionButtons = [NSMutableArray array];
    NSArray<NSString *> *names = BDSTargetedNames();
    CGFloat optionGap = 10.0;
    CGFloat optionWidth = floor((width - 36.0 - optionGap) / 2.0);
    for (NSUInteger i = 0; i < names.count; i++) {
        UIButton *option = [UIButton buttonWithType:UIButtonTypeSystem];
        if (i < 4) {
            NSUInteger row = i / 2;
            NSUInteger column = i % 2;
            CGFloat x = 18.0 + (CGFloat)column * (optionWidth + optionGap);
            option.frame = CGRectMake(x, 38.0 + (CGFloat)row * 42.0, optionWidth, 36.0);
            option.autoresizingMask = column == 0
                ? UIViewAutoresizingFlexibleRightMargin : UIViewAutoresizingFlexibleLeftMargin;
        } else {
            option.frame = CGRectMake(18.0, 122.0, width - 36.0, 36.0);
            option.autoresizingMask = UIViewAutoresizingFlexibleWidth;
        }
        option.tag = (NSInteger)i;
        option.layer.cornerRadius = 8;
        option.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
        option.titleLabel.font = [UIFont systemFontOfSize:15];
        [option addTarget:self action:@selector(toggleTargetedOption:) forControlEvents:UIControlEventTouchUpInside];
        [footer addSubview:option];
        [optionButtons addObject:option];
    }
    self.targetedOptionButtons = optionButtons;
    [self refreshTargetedOptionButtons];

    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.frame = CGRectMake(18, 176, width - 36, 52);
    button.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    button.layer.cornerRadius = 12;
    button.backgroundColor = UIColor.systemBlueColor;
    [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    button.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    button.titleLabel.adjustsFontSizeToFitWidth = YES;
    button.titleLabel.minimumScaleFactor = 0.78;
    [button setTitle:@"为选中容器一键随机整套基础参数" forState:UIControlStateNormal];
    [button addTarget:self action:@selector(randomizeBasicForSelectedContainers) forControlEvents:UIControlEventTouchUpInside];
    [footer addSubview:button];
    self.basicButton = button;

    UIButton *advancedButton = [UIButton buttonWithType:UIButtonTypeSystem];
    advancedButton.frame = CGRectMake(18, 240, width - 36, 52);
    advancedButton.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    advancedButton.layer.cornerRadius = 12;
    advancedButton.backgroundColor = UIColor.systemGreenColor;
    [advancedButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    advancedButton.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    advancedButton.titleLabel.adjustsFontSizeToFitWidth = YES;
    advancedButton.titleLabel.minimumScaleFactor = 0.78;
    [advancedButton setTitle:@"为选中容器一键随机整套高级参数" forState:UIControlStateNormal];
    [advancedButton addTarget:self action:@selector(randomizeAdvancedForSelectedContainers) forControlEvents:UIControlEventTouchUpInside];
    [footer addSubview:advancedButton];
    self.advancedButton = advancedButton;

    UIButton *targetedButton = [UIButton buttonWithType:UIButtonTypeSystem];
    targetedButton.frame = CGRectMake(18, 304, width - 36, 52);
    targetedButton.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    targetedButton.layer.cornerRadius = 12;
    targetedButton.backgroundColor = UIColor.systemRedColor;
    [targetedButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    targetedButton.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    targetedButton.titleLabel.adjustsFontSizeToFitWidth = YES;
    targetedButton.titleLabel.minimumScaleFactor = 0.78;
    [targetedButton setTitle:@"为选中容器一键随机定向指纹参数" forState:UIControlStateNormal];
    [targetedButton addTarget:self action:@selector(randomizeTargetedForSelectedContainers) forControlEvents:UIControlEventTouchUpInside];
    [footer addSubview:targetedButton];
    self.targetedButton = targetedButton;
    self.tableView.tableFooterView = footer;
}

- (NSString *)appPathForContainerID:(NSString *)containerID {
    if (!containerID.length || !self.crane) return nil;
    __block NSString *appPath = nil;
    if ([self.crane respondsToSelector:@selector(enumerate:pathsAssociatedToContainerWithIdentifier:ofApplicationWithIdentifier:)]) {
        [self.crane enumerate:^(BDSCraneContainerPathType type, NSString *identifier, NSString *path) {
            if (!appPath && type == BDSCraneContainerPathTypeApp && path.length) appPath = [path copy];
        } pathsAssociatedToContainerWithIdentifier:containerID ofApplicationWithIdentifier:BDSBaiduBundleID];
    }
    if (appPath.length) return appPath;

    if ([self.crane respondsToSelector:@selector(pathsAssociatedToContainerWithIdentifier:ofApplicationWithIdentifier:)]) {
        NSDictionary *paths = [self.crane pathsAssociatedToContainerWithIdentifier:containerID
                                                    ofApplicationWithIdentifier:BDSBaiduBundleID];
        NSMutableArray<NSString *> *candidates = [NSMutableArray array];
        for (id value in paths.allValues) {
            if ([value isKindOfClass:NSString.class] && [value length]) [candidates addObject:value];
            if ([value isKindOfClass:NSArray.class]) {
                for (id nested in value) {
                    if ([nested isKindOfClass:NSString.class] && [nested length]) [candidates addObject:nested];
                }
            }
        }
        for (NSString *candidate in candidates) {
            if ([candidate containsString:@"/Data/Application/"] ||
                [candidate containsString:@"/Application Support/Crane/"]) return candidate;
        }
        if (candidates.count) return candidates.firstObject;
    }
    return nil;
}

- (NSString *)resolvedBaiduBaseDataPath {
    if (self.baiduBaseDataPath.length) return self.baiduBaseDataPath;

    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    if ([proxyClass respondsToSelector:@selector(applicationProxyForIdentifier:)]) {
        LSApplicationProxy *proxy = [(id)proxyClass applicationProxyForIdentifier:BDSBaiduBundleID];
        NSString *path = proxy.dataContainerURL.path;
        if (path.length) self.baiduBaseDataPath = path;
    }

    // Crane 1.3.14 stores non-default app containers below the real app data
    // root. Normalize a path returned by libCrane if LSApplicationProxy is not
    // available in this process.
    if (!self.baiduBaseDataPath.length) {
        NSArray *identifiers = [self.crane containerIdentifiersOfApplicationWithIdentifier:BDSBaiduBundleID] ?: @[];
        for (NSString *identifier in identifiers) {
            if (![identifier isKindOfClass:NSString.class] || !identifier.length) continue;
            NSString *candidate = [self appPathForContainerID:identifier];
            if (!candidate.length) continue;
            NSRange marker = [candidate rangeOfString:@"/Library/___Crane_Containers/"];
            if (marker.location != NSNotFound) {
                candidate = [candidate substringToIndex:marker.location];
            }
            if ([candidate containsString:@"/Containers/Data/Application/"]) {
                self.baiduBaseDataPath = candidate;
                break;
            }
        }
    }
    return self.baiduBaseDataPath;
}

- (NSString *)configPathForContainerID:(NSString *)containerID {
    NSString *basePath = [self resolvedBaiduBaseDataPath];
    if (!basePath.length || !containerID.length) return nil;

    NSString *containerPath = basePath;
    if (![containerID isEqualToString:@"DEFAULT"]) {
        containerPath = [[[basePath stringByAppendingPathComponent:@"Library"]
            stringByAppendingPathComponent:@"___Crane_Containers"]
            stringByAppendingPathComponent:containerID];
    }
    return [[containerPath stringByAppendingPathComponent:@"Documents"]
        stringByAppendingPathComponent:BDSConfigFileName];
}

- (void)reloadContainers {
    self.basicButton.enabled = NO;
    self.advancedButton.enabled = NO;
    self.targetedButton.enabled = NO;
    self.baiduBaseDataPath = nil;
    void *handle = BDSLoadCraneLibrary();
    Class managerClass = NSClassFromString(@"CraneManager");
    if (!handle || !managerClass || ![managerClass respondsToSelector:@selector(sharedManager)]) {
        self.containers = @[];
        [self.tableView reloadData];
        NSString *detail = [NSString stringWithFormat:
            @"没有找到兼容的 libcrane.dylib。请确认 Crane 1.3.14-6 已安装并已启用。\n\n%@",
            gCraneLoadDetail ?: @"没有加载诊断"];
        [self showMessage:@"无法加载 Crane" detail:detail];
        return;
    }

    self.crane = [managerClass sharedManager];
    if (![self.crane isApplicationSupportedByCrane:BDSBaiduBundleID]) {
        self.containers = @[];
        [self.tableView reloadData];
        [self showMessage:@"百度尚未启用 Crane" detail:@"请先在 Crane 中为百度极速版创建至少一个容器。"];
        return;
    }

    NSArray *identifiers = [self.crane containerIdentifiersOfApplicationWithIdentifier:BDSBaiduBundleID] ?: @[];
    self.activeContainerID = [self.crane activeContainerIdentifierForApplicationWithIdentifier:BDSBaiduBundleID];
    NSMutableArray *rows = [NSMutableArray array];
    for (id rawID in identifiers) {
        if (![rawID isKindOfClass:NSString.class] || ![rawID length]) continue;
        NSString *containerID = rawID;
        NSString *name = [self.crane displayNameForContainerWithIdentifier:containerID
                                               ofApplicationWithIdentifier:BDSBaiduBundleID
                                                     shouldUseShortVersion:NO];
        NSString *path = [self configPathForContainerID:containerID];
        NSDictionary *config = path.length ? [NSDictionary dictionaryWithContentsOfFile:path] : nil;
        NSString *summary = BDSContainerSummary(config);
        [rows addObject:@{@"id": containerID, @"name": name ?: containerID,
                          @"summary": summary, @"path": path ?: @""}];
    }
    [rows sortUsingComparator:^NSComparisonResult(NSDictionary *left, NSDictionary *right) {
        return [left[@"name"] localizedStandardCompare:right[@"name"]];
    }];
    self.containers = rows;
    [self.selectedContainerIDs intersectSet:[NSSet setWithArray:[rows valueForKey:@"id"]]];
    self.basicButton.enabled = rows.count > 0;
    self.advancedButton.enabled = rows.count > 0;
    self.targetedButton.enabled = rows.count > 0;
    [self.tableView reloadData];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.containers.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *identifier = @"ContainerCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:identifier];
    if (!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:identifier];
    NSDictionary *row = self.containers[indexPath.row];
    NSString *containerID = row[@"id"];
    BOOL selected = [self.selectedContainerIDs containsObject:containerID];
    BOOL active = [containerID isEqualToString:self.activeContainerID];
    cell.textLabel.text = active ? [NSString stringWithFormat:@"%@（当前）", row[@"name"]] : row[@"name"];
    cell.detailTextLabel.text = row[@"summary"];
    cell.detailTextLabel.numberOfLines = 2;
    cell.accessoryType = selected ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSString *containerID = self.containers[indexPath.row][@"id"];
    if ([self.selectedContainerIDs containsObject:containerID]) [self.selectedContainerIDs removeObject:containerID];
    else [self.selectedContainerIDs addObject:containerID];
    [tableView reloadRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationAutomatic];
}

- (void)randomizeBasicForSelectedContainers {
    [self applySelectedContainersWithMode:BDSRandomModeBasic];
}

- (void)randomizeAdvancedForSelectedContainers {
    [self applySelectedContainersWithMode:BDSRandomModeAdvanced];
}

- (void)randomizeTargetedForSelectedContainers {
    if (!self.targetedSelectionKeys.count) {
        [self showMessage:@"尚未选择定向项目" detail:@"请先在下方 5 项中开启至少一项，再点击定向随机。"];
        return;
    }
    [self applySelectedContainersWithMode:BDSRandomModeTargeted];
}

- (void)toggleTargetedOption:(UIButton *)sender {
    NSArray<NSString *> *keys = BDSTargetedKeys();
    if (sender.tag < 0 || (NSUInteger)sender.tag >= keys.count) return;
    NSString *key = keys[(NSUInteger)sender.tag];
    if ([self.targetedSelectionKeys containsObject:key]) [self.targetedSelectionKeys removeObject:key];
    else [self.targetedSelectionKeys addObject:key];
    [self refreshTargetedOptionButtons];
}

- (void)refreshTargetedOptionButtons {
    NSArray<NSString *> *keys = BDSTargetedKeys();
    NSArray<NSString *> *names = BDSTargetedNames();
    [self.targetedOptionButtons enumerateObjectsUsingBlock:^(UIButton *button, NSUInteger idx, BOOL *stop) {
        (void)stop;
        if (idx >= keys.count || idx >= names.count) return;
        BOOL selected = [self.targetedSelectionKeys containsObject:keys[idx]];
        [button setTitle:[NSString stringWithFormat:@"%@：%@", names[idx], selected ? @"开" : @"关"]
                 forState:UIControlStateNormal];
    }];
}

- (void)applySelectedContainersWithMode:(BDSRandomMode)mode {
    if (!self.selectedContainerIDs.count) {
        [self showMessage:@"尚未选择容器" detail:@"请先点击需要配置的 Crane 容器。"];
        return;
    }

    NSMutableArray<NSString *> *successes = [NSMutableArray array];
    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    NSSet<NSString *> *targetedSelection = [self.targetedSelectionKeys copy];
    for (NSDictionary *row in self.containers) {
        NSString *containerID = row[@"id"];
        if (![self.selectedContainerIDs containsObject:containerID]) continue;
        NSString *configPath = row[@"path"];
        if (!configPath.length) configPath = [self configPathForContainerID:containerID];
        if (!configPath.length) {
            [failures addObject:[NSString stringWithFormat:@"%@：没有取得容器路径", row[@"name"]]];
            continue;
        }

        NSString *documents = configPath.stringByDeletingLastPathComponent;
        NSError *directoryError = nil;
        if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                       withIntermediateDirectories:YES
                                                        attributes:@{NSFilePosixPermissions:@0755}
                                                             error:&directoryError]) {
            [failures addObject:[NSString stringWithFormat:@"%@：%@", row[@"name"], directoryError.localizedDescription]];
            continue;
        }

        NSDictionary *existing = [NSDictionary dictionaryWithContentsOfFile:configPath];
        NSMutableDictionary *config = BDSCreateRandomConfig(existing, mode, targetedSelection);
        if (!config.count) {
            [failures addObject:[NSString stringWithFormat:@"%@：没有生成有效配置", row[@"name"]]];
            continue;
        }
        config[@"managerContainerIdentifier"] = containerID;
        config[@"managerResolvedPath"] = configPath;
        NSError *serializationError = nil;
        NSData *data = [NSPropertyListSerialization dataWithPropertyList:config
                                                                   format:NSPropertyListXMLFormat_v1_0
                                                                  options:0 error:&serializationError];
        NSError *writeError = nil;
        BOOL wrote = data && [data writeToFile:configPath options:NSDataWritingAtomic error:&writeError];
        if (!wrote) {
            NSError *error = writeError ?: serializationError;
            [failures addObject:[NSString stringWithFormat:@"%@：%@", row[@"name"], error.localizedDescription ?: @"写入失败"]];
            continue;
        }
        [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions:@0644}
                                         ofItemAtPath:configPath error:nil];

        NSDictionary *verified = [NSDictionary dictionaryWithContentsOfFile:configPath];
        BOOL identifierMatches = [verified[@"managerContainerIdentifier"] isEqualToString:containerID];
        BOOL contentMatches = NO;
        if (mode == BDSRandomModeAdvanced) {
            contentMatches = YES;
            for (NSString *key in @[@"idfa", @"idfv", @"deviceID", @"cuid", @"utdid"]) {
                if (![verified[key] isEqual:config[key]]) { contentMatches = NO; break; }
            }
        } else {
            contentMatches = [verified[@"systemVersion"] isEqual:config[@"systemVersion"]] &&
                             [verified[@"deviceProfileName"] isEqual:config[@"deviceProfileName"]];
            NSArray<NSString *> *requiredOn = @[
                @"enabled", @"spoofAdvertisingIdentifiers", @"spoofProcessHardware", @"spoofLocale",
                @"spoofCarrier", @"spoofStorage", @"spoofBaiduSDK", @"spoofSysctl",
                @"bypassJailbreakDetect", @"spoofWiFi", @"spoofLocalIP", @"spoofPasteboard",
                @"spoofBootTime", @"spoofCPU", @"spoofLocation", @"spoofProxyDetection",
                @"spoofStatfs", @"spoofDlopen", @"spoofUbiquity", @"spoofPrivacyPermissions",
                @"spoofBattery"
            ];
            for (NSString *key in requiredOn) {
                if (![verified[key] boolValue]) { contentMatches = NO; break; }
            }
            if ([verified[@"spoofScreen"] boolValue]) contentMatches = NO;
            BOOL expectedTargeted = mode == BDSRandomModeTargeted;
            if ([verified[@"spoofBaiduTargeted"] boolValue] != expectedTargeted) contentMatches = NO;
            for (NSString *key in BDSTargetedKeys()) {
                BOOL expectedChild = expectedTargeted && [targetedSelection containsObject:key];
                if ([verified[key] boolValue] != expectedChild) { contentMatches = NO; break; }
            }
            if (contentMatches && expectedTargeted) {
                if ([targetedSelection containsObject:@"spoofBaiduTargetedSystem"]) {
                    contentMatches = [verified[@"targetedSystemVersion"] isEqual:config[@"targetedSystemVersion"]] &&
                                     [verified[@"targetedSystemBuild"] isEqual:config[@"targetedSystemBuild"]] &&
                                     [verified[@"systemVersion"] isEqual:config[@"targetedSystemVersion"]] &&
                                     [verified[@"systemBuild"] isEqual:config[@"targetedSystemBuild"]] &&
                                     [verified[@"kernOSVersion"] isEqual:config[@"targetedSystemBuild"]];
                }
                if (contentMatches && [targetedSelection containsObject:@"spoofBaiduTargetedModel"]) {
                    contentMatches = [verified[@"targetedDeviceProfileName"] isEqual:config[@"targetedDeviceProfileName"]] &&
                                     [verified[@"targetedHwMachine"] isEqual:config[@"targetedHwMachine"]] &&
                                     [verified[@"targetedHwModel"] isEqual:config[@"targetedHwModel"]] &&
                                     [verified[@"deviceProfileName"] isEqual:config[@"targetedDeviceProfileName"]] &&
                                     [verified[@"hwMachine"] isEqual:config[@"targetedHwMachine"]] &&
                                     [verified[@"hwModel"] isEqual:config[@"targetedHwModel"]] &&
                                     [verified[@"memorySize"] isEqual:config[@"memorySize"]] &&
                                     [verified[@"diskSize"] isEqual:config[@"diskSize"]];
                }
                if (contentMatches && [targetedSelection containsObject:@"spoofBaiduTargetedScreen"]) {
                    contentMatches = [verified[@"targetedScreenWidth"] isEqual:config[@"targetedScreenWidth"]] &&
                                     [verified[@"targetedScreenHeight"] isEqual:config[@"targetedScreenHeight"]] &&
                                     [verified[@"targetedScreenScale"] isEqual:config[@"targetedScreenScale"]] &&
                                     [verified[@"targetedNativeScreenWidth"] isEqual:config[@"targetedNativeScreenWidth"]] &&
                                     [verified[@"targetedNativeScreenHeight"] isEqual:config[@"targetedNativeScreenHeight"]] &&
                                     [verified[@"screenWidth"] isEqual:config[@"targetedScreenWidth"]] &&
                                     [verified[@"screenHeight"] isEqual:config[@"targetedScreenHeight"]] &&
                                     [verified[@"screenScale"] isEqual:config[@"targetedScreenScale"]] &&
                                     [verified[@"nativeScreenWidth"] isEqual:config[@"targetedNativeScreenWidth"]] &&
                                     [verified[@"nativeScreenHeight"] isEqual:config[@"targetedNativeScreenHeight"]];
                }
                if (contentMatches && [targetedSelection containsObject:@"spoofBaiduTargetedUA"]) {
                    contentMatches = [verified[@"targetedUASystemVersion"] isEqual:config[@"targetedUASystemVersion"]] &&
                                     [verified[@"targetedUASystemBuild"] isEqual:config[@"targetedUASystemBuild"]];
                }
                if (contentMatches && [targetedSelection containsObject:@"spoofBaiduTargetedPush"]) {
                    contentMatches = [verified[@"targetedPushDeviceProfileName"] isEqual:config[@"targetedPushDeviceProfileName"]] &&
                                     [verified[@"targetedPushHwMachine"] isEqual:config[@"targetedPushHwMachine"]] &&
                                     [verified[@"targetedPushHwModel"] isEqual:config[@"targetedPushHwModel"]];
                }
            }
        }
        if (!identifierMatches || !contentMatches) {
            [failures addObject:[NSString stringWithFormat:@"%@：写后回读校验失败\n%@",
                row[@"name"], configPath]];
            continue;
        }
        if (mode == BDSRandomModeAdvanced) {
            [successes addObject:[NSString stringWithFormat:@"%@：五项高级身份参数已更换", row[@"name"]]];
        } else {
            if (mode == BDSRandomModeTargeted) {
                NSMutableArray<NSString *> *selectedNames = [NSMutableArray array];
                NSArray<NSString *> *keys = BDSTargetedKeys();
                NSArray<NSString *> *names = BDSTargetedNames();
                for (NSUInteger i = 0; i < keys.count; i++) {
                    if ([targetedSelection containsObject:keys[i]]) [selectedNames addObject:names[i]];
                }
                NSString *resultDetail = BDSTargetedResultDetail(config, targetedSelection);
                [successes addObject:[NSString stringWithFormat:@"%@：已随机 %@%@%@",
                    row[@"name"], [selectedNames componentsJoinedByString:@"、"],
                    resultDetail.length ? @"\n" : @"", resultDetail ?: @""]];
            } else {
                [successes addObject:[NSString stringWithFormat:@"%@：%@ / iOS %@（基础）",
                    row[@"name"], config[@"deviceProfileName"], config[@"systemVersion"]]];
            }
        }
    }

    [self reloadContainers];
    NSMutableString *detail = [NSMutableString string];
    if (successes.count) [detail appendFormat:@"成功：\n%@", [successes componentsJoinedByString:@"\n"]];
    if (failures.count) [detail appendFormat:@"%@失败：\n%@", detail.length ? @"\n\n" : @"", [failures componentsJoinedByString:@"\n"]];
    if (successes.count) {
        if (mode == BDSRandomModeBasic) {
            [detail appendString:@"\n\n基础、反关联和原有 3 项高级功能已开启；定向总开关及 5 个子开关已关闭。"];
        } else if (mode == BDSRandomModeAdvanced) {
            [detail appendString:@"\n\n只更换 IDFA、IDFV、DeviceID、CUID、UTDID；其他参数和开关均未改变。"];
        } else {
            [detail appendString:@"\n\n只随机已选择的定向项目；基础 6 项、高级 3 项和反关联 12 项已开启。未选定向项目、长期身份值及风险测试 4 项未改变。"];
        }
        [detail appendString:@"\n未运行的容器可直接首次打开；已在后台运行的百度仍需彻底结束一次再打开。"];
    }
    if (successes.count && mode == BDSRandomModeBasic) {
        [self.targetedSelectionKeys removeAllObjects];
        [self refreshTargetedOptionButtons];
    }
    [self showMessage:failures.count ? @"配置完成（部分失败）" : @"配置已写入" detail:detail];
}

- (void)showMessage:(NSString *)title detail:(NSString *)detail {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:detail
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end

@interface BDSAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation BDSAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    BDSManagerViewController *root = [[BDSManagerViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    UINavigationController *navigation = [[UINavigationController alloc] initWithRootViewController:root];
    self.window.rootViewController = navigation;
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(BDSAppDelegate.class));
    }
}
