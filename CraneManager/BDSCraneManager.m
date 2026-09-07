#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <limits.h>
#import <stdlib.h>
#import "../Shared/BDSSettingsUI.h"

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
    if(force || ![config[@"idfa"] length]) config[@"idfa"] = NSUUID.UUID.UUIDString.uppercaseString;
    if(force || ![config[@"idfv"] length]) config[@"idfv"] = NSUUID.UUID.UUIDString.uppercaseString;
    if(force || ![config[@"deviceID"] length]) config[@"deviceID"] = NSUUID.UUID.UUIDString.uppercaseString;
    if(force || ![config[@"cuid"] length]) config[@"cuid"] = BDSRandomHex(32, YES);
    if(force || ![config[@"utdid"] length]) config[@"utdid"] = BDSRandomHex(32, NO);
}

static NSMutableDictionary *BDSMergedConfig(NSDictionary *existing) {
    NSMutableDictionary *config=[BDSDefaultConfig() mutableCopy];
    if(existing.count) [config addEntriesFromDictionary:existing];
    BDSApplyInitialDefaults(config,existing);
    BDSSeedInitialIdentities(config,existing);
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
        @"configVersion": @187,
        @"managerGeneratedAt": @([[NSDate date] timeIntervalSince1970]),
        @"managerProfileVersion": @103,
        @"managerRandomMode": mode == BDSRandomModeTargeted ? @"targeted" : @"basic",
    }];

    if (mode == BDSRandomModeBasic) {
        BDSMarkRandomModeRun(config, @"basic");
        NSArray *disks = device[@"disks"];
        if (![disks isKindOfClass:NSArray.class] || !disks.count) return nil;
        NSNumber *disk = disks[arc4random_uniform((uint32_t)disks.count)];
        NSString *deviceName = [NSString stringWithFormat:@"iPhone-%@", [BDSRandomHex(6, YES) uppercaseString]];
        [config addEntriesFromDictionary:@{
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

        BDSMarkRandomModeRun(config, @"targeted");
        config[@"spoofBaiduTargeted"] = @YES;
        for (NSString *key in BDSTargetedKeys()) config[key] = @([selectedTargetedKeys containsObject:key]);
        config[@"targetedGeneratedAt"] = @([[NSDate date] timeIntervalSince1970]);
        if ([selectedTargetedKeys containsObject:@"spoofBaiduTargetedSystem"]) {

            config[@"targetedSystemVersion"] = system[@"version"];
            config[@"targetedSystemBuild"] = system[@"build"];
        }
        if ([selectedTargetedKeys containsObject:@"spoofBaiduTargetedModel"]) {
            config[@"targetedDeviceProfileName"] = device[@"name"];
            config[@"targetedHwMachine"] = device[@"machine"];
            config[@"targetedHwModel"] = device[@"model"];
        }
        if ([selectedTargetedKeys containsObject:@"spoofBaiduTargetedScreen"]) {

            config[@"targetedScreenHwMachine"] = device[@"machine"];
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

    if (!hadExistingConfig) BDSSeedIdentityIfNeeded(config, YES);
    return config;
}

static NSMutableDictionary *BDSCreateRandomConfig(NSDictionary *existing,
                                                   BDSRandomMode mode,
                                                   NSSet<NSString *> *selectedTargetedKeys) {
    if (mode == BDSRandomModeAdvanced) {
        NSMutableDictionary *config = BDSMergedConfig(existing);
        config[@"managerGeneratedAt"] = @([[NSDate date] timeIntervalSince1970]);
        config[@"managerProfileVersion"] = @103;
        config[@"managerRandomMode"] = @"advanced";
        BDSMarkRandomModeRun(config, @"advanced");
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
- (void)randomizeBasicForSelectedContainers;
- (void)showAssociationSettings;
- (void)restoreSafeSettings;
- (BOOL)saveSwitchChanges:(NSDictionary *)changes;
- (NSDictionary *)selectedSwitchConfiguration;
- (void)randomizeAdvancedForSelectedContainers;
- (void)randomizeTargetedForSelectedContainers;
- (void)applySelectedContainersWithMode:(BDSRandomMode)mode;
@end

static NSString *BDSContainerSummary(NSDictionary *config) {
    if (![config isKindOfClass:NSDictionary.class]) return @"尚未写入参数";
    NSMutableString *summary = [NSMutableString string];
    if (BDSRandomModeWasRun(config, @"basic")) {
        [summary appendFormat:@"基础（已随机）：%@ · iOS %@",
            config[@"hwMachine"] ?: @"未知机型", config[@"systemVersion"] ?: @"未知"];
    } else {
        [summary appendString:@"基础：未随机"];
    }
    [summary appendFormat:@"\n高级：%@",
        BDSRandomModeWasRun(config, @"advanced") ? @"已随机" : @"未随机"];
    if (BDSRandomModeWasRun(config, @"targeted")) {
        NSMutableArray<NSString *> *targeted = [NSMutableArray array];
        if ([config[@"spoofBaiduTargetedModel"] boolValue]) {
            [targeted addObject:config[@"targetedHwMachine"] ?: @"未知机型"];
        }
        if ([config[@"spoofBaiduTargetedSystem"] boolValue]) {
            [targeted addObject:[NSString stringWithFormat:@"iOS %@", config[@"targetedSystemVersion"] ?: @"未知"]];
        }
        if (!targeted.count) [targeted addObject:@"已保存定向参数"];
        [summary appendFormat:@"\n定向（已随机）：%@%@",
            [targeted componentsJoinedByString:@" · "],
            [config[@"spoofBaiduTargeted"] boolValue] ? @"" : @" · 当前关闭"];
    } else {
        [summary appendString:@"\n定向：未随机"];
    }
    return summary;
}

static NSString *BDSCleanContainerDisplayName(NSString *name, NSString *fallback) {
    NSString *clean = name.length ? name : fallback;
    clean = [clean stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    for (NSString *suffix in @[@"（默认）", @"(默认)", @"（Default）", @"(Default)"]) {
        if ([clean hasSuffix:suffix] && ![clean isEqualToString:suffix]) {
            clean = [clean substringToIndex:clean.length-suffix.length];
            clean = [clean stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            break;
        }
    }
    return clean.length ? clean : fallback;
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

static BOOL BDSWriteContainerConfig(NSString *path, NSDictionary *config) {
    if(!path.length || !config.count) return NO;
    NSFileManager *fm=NSFileManager.defaultManager;
    NSError *error=nil;
    if(![fm createDirectoryAtPath:path.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0755} error:&error]) return NO;
    NSData *data=[NSPropertyListSerialization dataWithPropertyList:config format:NSPropertyListXMLFormat_v1_0 options:0 error:&error];
    if(!data || ![data writeToFile:path options:NSDataWritingAtomic error:&error]) return NO;
    [fm setAttributes:@{NSFilePosixPermissions:@0644} ofItemAtPath:path error:nil];
    return [[NSDictionary dictionaryWithContentsOfFile:path] isEqualToDictionary:config];
}

@implementation BDSManagerViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"卍解";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.selectedContainerIDs = [NSMutableSet set];
    self.targetedSelectionKeys = [NSMutableSet set];
    self.tableView.rowHeight = 96.0;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(reloadContainers)];
    [self buildHeaderAndFooter];
    [self reloadContainers];
}

- (void)buildHeaderAndFooter {
    CGFloat width=CGRectGetWidth(self.tableView.bounds);
    UIView *header=[[UIView alloc] initWithFrame:CGRectMake(0,0,width,8)];
    self.tableView.tableHeaderView=header;
    UIView *footer=[[UIView alloc] initWithFrame:CGRectMake(0,0,width,288)];
    NSArray *titles=@[@"一键随机基础整套设置",@"一键随机高级整套设置",@"一键随机定向指纹设置",@"反关联项",@"恢复安全",@"关闭"];
    NSArray *selectors=@[NSStringFromSelector(@selector(randomizeBasicForSelectedContainers)),NSStringFromSelector(@selector(randomizeAdvancedForSelectedContainers)),NSStringFromSelector(@selector(randomizeTargetedForSelectedContainers)),NSStringFromSelector(@selector(showAssociationSettings)),NSStringFromSelector(@selector(restoreSafeSettings)),NSStringFromSelector(@selector(closeApp))];
    for(NSUInteger i=0;i<titles.count;i++) {
        UIButton *button=[UIButton buttonWithType:UIButtonTypeSystem];
        button.autoresizingMask=UIViewAutoresizingFlexibleWidth;
        button.tag=1000+i;
        button.layer.cornerRadius=12;
        button.layer.masksToBounds=YES;
        button.backgroundColor=i<3?BDSRandomButtonColor(i):UIColor.secondarySystemGroupedBackgroundColor;
        [button setTitleColor:i<3?UIColor.whiteColor:UIColor.labelColor forState:UIControlStateNormal];
        [button setTitle:titles[i] forState:UIControlStateNormal];
        button.titleLabel.font=[UIFont boldSystemFontOfSize:17];
        button.titleLabel.adjustsFontSizeToFitWidth=YES;
        button.titleLabel.minimumScaleFactor=0.7;
        [button addTarget:self action:NSSelectorFromString(selectors[i]) forControlEvents:UIControlEventTouchUpInside];
        [footer addSubview:button];
        if(i==0) self.basicButton=button;
        else if(i==1) self.advancedButton=button;
        else if(i==2) self.targetedButton=button;
    }
    self.tableView.tableFooterView=footer;
    [self layoutFooterButtons];
}

- (void)layoutFooterButtons {
    UIView *footer=self.tableView.tableFooterView;
    if(!footer) return;
    CGFloat width=CGRectGetWidth(self.tableView.bounds);
    CGRect footerFrame=footer.frame;
    if(fabs(footerFrame.size.width-width)>0.5) {
        footerFrame.size.width=width;
        footer.frame=footerFrame;
        self.tableView.tableFooterView=footer;
    }
    CGFloat sideInset=18.0;
    CGFloat buttonWidth=MAX(0,CGRectGetWidth(footer.bounds)-sideInset*2.0);
    CGFloat buttonHeight=48.0;
    CGFloat rowStep=56.0;
    for(NSUInteger i=0;i<3;i++) {
        UIButton *button=[footer viewWithTag:1000+i];
        button.frame=CGRectMake(sideInset,6+i*rowStep,buttonWidth,buttonHeight);
    }
    CGFloat pairGap=6.0;
    CGFloat pairWidth=MAX(0,(buttonWidth-pairGap)/2.0);
    [footer viewWithTag:1003].frame=CGRectMake(sideInset,6+3*rowStep,pairWidth,buttonHeight);
    [footer viewWithTag:1004].frame=CGRectMake(sideInset+pairWidth+pairGap,6+3*rowStep,pairWidth,buttonHeight);
    [footer viewWithTag:1005].frame=CGRectMake(sideInset,6+4*rowStep,buttonWidth,buttonHeight);
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    [self layoutFooterButtons];
}

- (void)closeApp {
    exit(EXIT_SUCCESS);
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
        name = BDSCleanContainerDisplayName(name, containerID);
        NSString *path = [self configPathForContainerID:containerID];
        NSDictionary *config = path.length ? [NSDictionary dictionaryWithContentsOfFile:path] : nil;
        NSMutableDictionary *initialized=BDSMergedConfig(config);
        BDSSeedIdentityIfNeeded(initialized,NO);
        initialized[@"managerContainerIdentifier"]=containerID;
        initialized=BDSConfigForPersistentStorage(initialized);
        BOOL ready=[initialized isEqualToDictionary:config] || BDSWriteContainerConfig(path,initialized);
        if(ready) config=initialized;
        NSString *summary = ready ? BDSContainerSummary(config) : @"初始化保存失败，请刷新重试";
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
    cell.detailTextLabel.numberOfLines = 3;
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
    if(!self.selectedContainerIDs.count) { [self showMessage:@"尚未选择容器" detail:@"请先选择需要配置的容器。"]; return; }
    BDSTargetedPage *page=[[BDSTargetedPage alloc] initWithStyle:UITableViewStyleInsetGrouped];
    page.selection=[self.targetedSelectionKeys mutableCopy];
    __weak BDSManagerViewController *weakSelf=self;
    page.selectionChanged=^BOOL(NSSet *selected) { weakSelf.targetedSelectionKeys=[selected mutableCopy]; return YES; };
    page.randomize=^{
        [weakSelf.navigationController popViewControllerAnimated:NO];
        [weakSelf applySelectedContainersWithMode:BDSRandomModeTargeted];
    };
    [self.navigationController pushViewController:page animated:YES];
}

- (NSDictionary *)selectedSwitchConfiguration {
    NSMutableDictionary *combined=nil;
    for(NSDictionary *row in self.containers) {
        if(![self.selectedContainerIDs containsObject:row[@"id"]]) continue;
        NSDictionary *config=[NSDictionary dictionaryWithContentsOfFile:row[@"path"]];
        if(!combined) combined=[config mutableCopy];
        else for(NSString *key in BDSSafeSwitchValues()) combined[key]=@([combined[key] boolValue] && [config[key] boolValue]);
    }
    return combined ?: @{};
}

- (BOOL)saveSwitchChanges:(NSDictionary *)changes {
    if(!self.selectedContainerIDs.count) return NO;
    BOOL saved=YES;
    for(NSDictionary *row in self.containers) {
        if(![self.selectedContainerIDs containsObject:row[@"id"]]) continue;
        NSString *path=row[@"path"];
        NSDictionary *existing=[NSDictionary dictionaryWithContentsOfFile:path];
        if(!existing) { saved=NO; continue; }
        NSMutableDictionary *config=[existing mutableCopy];
        [config addEntriesFromDictionary:changes];
        if(!BDSWriteContainerConfig(path,config)) saved=NO;
    }
    [self reloadContainers];
    return saved;
}

- (void)showAssociationSettings {
    if(!self.selectedContainerIDs.count) { [self showMessage:@"尚未选择容器" detail:@"请先选择需要配置的容器。"]; return; }
    BDSAssociationPage *page=[[BDSAssociationPage alloc] initWithStyle:UITableViewStyleInsetGrouped];
    page.configuration=[self selectedSwitchConfiguration];
    __weak BDSManagerViewController *weakSelf=self;
    page.saveChanges=^BOOL(NSDictionary *changes) { return [weakSelf saveSwitchChanges:changes]; };
    [self.navigationController pushViewController:page animated:YES];
}

- (void)restoreSafeSettings {
    if(!self.selectedContainerIDs.count) { [self showMessage:@"尚未选择容器" detail:@"请先选择需要恢复安全设置的容器。"]; return; }
    BOOL saved=[self saveSwitchChanges:BDSSafeSwitchValues()];
    [self showMessage:saved?@"已恢复安全":@"部分保存失败" detail:saved?@"选中容器的所有开关已关闭，参数值保留。请彻底关闭百度后重新打开。":@"请刷新容器列表后检查设置。"];
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
        config = BDSConfigForPersistentStorage(config);
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
        BOOL contentMatches = [verified isEqualToDictionary:config];
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
            [detail appendString:@"\n\n仅基础参数已更换；高级身份、定向参数与所有开关保持不变。"];
        } else if (mode == BDSRandomModeAdvanced) {
            [detail appendString:@"\n\n只更换 IDFA、IDFV、DeviceID、CUID、UTDID；其他参数和开关均未改变。"];
        } else {
            [detail appendString:@"\n\n仅已选择的定向参数已更换；基础参数、高级身份及常规开关保持不变。"];
        }
        [detail appendString:@"\n未运行的容器可直接首次打开；已在后台运行的百度仍需彻底结束一次再打开。"];
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
