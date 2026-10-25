//
//  KSSpooferManager — 快手伪装管理器（独立 App）
//
//  用途：在启动快手之前先「一键随机」，把默认身份写进
//        /var/mobile/Library/Preferences/com.bds.ksspoofer.default.plist
//        KSSpoofer 插件启动时若容器内没有配置，就读这个默认身份。
//
#import <UIKit/UIKit.h>

static NSString *KSDefaultCfgPath(void) {
    return @"/var/mobile/Library/Preferences/com.bds.ksspoofer.default.plist";
}

#pragma mark - 机型池（与插件一致）

typedef struct {
    const char *name;
    const char *machine;
    const char *model;
    int memMB;
    int diskGroup;
    const char *osGroup;
} KSProfile;

static const int kDisks0[] = { 64, 128, 256 };
static const int kDisks1[] = { 128, 256, 512 };
static const int kDisks2[] = { 128, 256, 512, 1024 };
static const int kDisks3[] = { 256, 512, 1024 };
static const int *kDiskGroups[] = { kDisks0, kDisks1, kDisks2, kDisks3 };
static const int kDiskCounts[] = { 3, 3, 4, 3 };

static const KSProfile kProfiles[] = {
    { "iPhone 8",                "iPhone10,1", "D20AP",   2048, 0, "16"   },
    { "iPhone 8 Plus",           "iPhone10,2", "D21AP",   3072, 0, "16"   },
    { "iPhone X",                "iPhone10,3", "D22AP",   3072, 0, "16"   },
    { "iPhone XR",               "iPhone11,8", "N841AP",  3072, 1, "1617" },
    { "iPhone XS",               "iPhone11,2", "D321AP",  4096, 1, "1617" },
    { "iPhone XS Max",           "iPhone11,6", "D331pAP", 4096, 1, "1617" },
    { "iPhone 11",               "iPhone12,1", "N104AP",  4096, 0, "1617" },
    { "iPhone 11 Pro",           "iPhone12,3", "D421AP",  4096, 1, "1617" },
    { "iPhone 11 Pro Max",       "iPhone12,5", "D431AP",  4096, 1, "1617" },
    { "iPhone SE (2nd)",         "iPhone12,8", "D79AP",   3072, 0, "1617" },
    { "iPhone 12 mini",          "iPhone13,1", "D52gAP",  4096, 0, "1617" },
    { "iPhone 12",               "iPhone13,2", "D53gAP",  4096, 0, "1617" },
    { "iPhone 12 Pro",           "iPhone13,3", "D53pAP",  6144, 1, "1617" },
    { "iPhone 12 Pro Max",       "iPhone13,4", "D54pAP",  6144, 1, "1617" },
    { "iPhone 13 mini",          "iPhone14,4", "D16AP",   4096, 1, "1617" },
    { "iPhone 13",               "iPhone14,5", "D17AP",   4096, 1, "1617" },
    { "iPhone 13 Pro",           "iPhone14,2", "D63AP",   6144, 2, "1617" },
    { "iPhone 13 Pro Max",       "iPhone14,3", "D64AP",   6144, 2, "1617" },
    { "iPhone SE (3rd)",         "iPhone14,6", "D49AP",   4096, 0, "1617" },
    { "iPhone 14",               "iPhone14,7", "D27AP",   6144, 1, "1617" },
    { "iPhone 14 Plus",          "iPhone14,8", "D28AP",   6144, 1, "1617" },
    { "iPhone 14 Pro",           "iPhone15,2", "D73AP",   6144, 2, "1617" },
    { "iPhone 14 Pro Max",       "iPhone15,3", "D74AP",   6144, 2, "1617" },
    { "iPhone 15",               "iPhone15,4", "D37AP",   6144, 1, "17"   },
    { "iPhone 15 Plus",          "iPhone15,5", "D38AP",   6144, 1, "17"   },
    { "iPhone 15 Pro",           "iPhone16,1", "D83AP",   8192, 2, "17"   },
    { "iPhone 15 Pro Max",       "iPhone16,2", "D84AP",   8192, 3, "17"   },
    { "iPhone 16",               "iPhone17,3", "D47AP",   8192, 1, "18"   },
    { "iPhone 16 Plus",          "iPhone17,4", "D48AP",   8192, 1, "18"   },
    { "iPhone 16 Pro",           "iPhone17,1", "D93AP",   8192, 2, "18"   },
    { "iPhone 16 Pro Max",       "iPhone17,2", "D94AP",   8192, 3, "18"   },
    { "iPhone 16e",              "iPhone17,5", "V59AP",   8192, 1, "18"   },
};
static const int kProfileCount = (int)(sizeof(kProfiles) / sizeof(kProfiles[0]));

static NSMutableDictionary *KSRandomIdentity(void) {
    int idx = (int)arc4random_uniform((uint32_t)kProfileCount);
    const KSProfile *p = &kProfiles[idx];
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    m[@"hwMachine"] = [NSString stringWithUTF8String:p->machine];
    m[@"hwModel"] = [NSString stringWithUTF8String:p->model];
    m[@"memoryMB"] = @(p->memMB);
    int dg = p->diskGroup;
    m[@"diskGB"] = @(kDiskGroups[dg][arc4random_uniform((uint32_t)kDiskCounts[dg])]);

    static const char *v16[] = { "16.6.1", "16.7" };
    static const char *b16[] = { "20G81", "20H18" };
    static const char *v17[] = { "17.0.1", "17.0.2", "17.1" };
    static const char *b17[] = { "21A340", "21A351", "21B80" };
    static const char *v18[] = { "18.0", "18.1" };
    static const char *b18[] = { "22A3354", "22B83" };
    const char **vs = v16; const char **bs = b16; int n = 2;
    if (strcmp(p->osGroup, "17") == 0) { vs = v17; bs = b17; n = 3; }
    else if (strcmp(p->osGroup, "18") == 0) { vs = v18; bs = b18; n = 2; }
    else if (strcmp(p->osGroup, "1617") == 0) {
        if (arc4random_uniform(2) == 0) { vs = v16; bs = b16; n = 2; }
        else { vs = v17; bs = b17; n = 3; }
    }
    int vi = (int)arc4random_uniform((uint32_t)n);
    m[@"systemVersion"] = [NSString stringWithUTF8String:vs[vi]];
    m[@"systemBuild"] = [NSString stringWithUTF8String:bs[vi]];
    m[@"deviceName"] = @"iPhone";
    m[@"profileId"] = [NSString stringWithFormat:@"1.%d", idx];
    m[@"profileName"] = [NSString stringWithUTF8String:p->name];
    // 安装时间：今天 00:00 ~ 现在之间的随机毫秒
    NSDate *now = [NSDate date];
    NSDate *start = [[NSCalendar currentCalendar] startOfDayForDate:now];
    double a = [start timeIntervalSince1970], b = [now timeIntervalSince1970];
    if (b <= a) b = a + 3600;
    double r = (double)arc4random_uniform(10000) / 10000.0;
    m[@"installTimeMs"] = @((long long)((a + (b - a) * r) * 1000.0));
    m[@"enabled"] = @YES;
    return m;
}

static NSDictionary *KSLoadDefault(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:KSDefaultCfgPath()];
    return [d isKindOfClass:NSDictionary.class] ? d : nil;
}

#pragma mark - UI

@interface KSVC : UIViewController
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *infoLabel;
@property (nonatomic, strong) UIButton *randomBtn;
@property (nonatomic, strong) UILabel *hintLabel;
@end

@implementation KSVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1];

    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 90, self.view.bounds.size.width - 40, 44)];
    self.titleLabel.text = @"快手伪装管理器";
    self.titleLabel.textColor = [UIColor whiteColor];
    self.titleLabel.font = [UIFont boldSystemFontOfSize:26];
    [self.view addSubview:self.titleLabel];

    self.infoLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 150, self.view.bounds.size.width - 40, 220)];
    self.infoLabel.numberOfLines = 0;
    self.infoLabel.textColor = [UIColor lightGrayColor];
    self.infoLabel.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
    [self.view addSubview:self.infoLabel];

    self.randomBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.randomBtn.frame = CGRectMake(20, 390, self.view.bounds.size.width - 40, 52);
    [self.randomBtn setTitle:@"一键随机（写默认身份）" forState:UIControlStateNormal];
    self.randomBtn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    self.randomBtn.backgroundColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.85 alpha:1];
    [self.randomBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.randomBtn.layer.cornerRadius = 10;
    [self.randomBtn addTarget:self action:@selector(randomize) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.randomBtn];

    self.hintLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 456, self.view.bounds.size.width - 40, 80)];
    self.hintLabel.numberOfLines = 0;
    self.hintLabel.textColor = [UIColor grayColor];
    self.hintLabel.font = [UIFont systemFontOfSize:13];
    self.hintLabel.text = @"流程：点「一键随机」→ 打开快手（会自动读这份默认身份）\n如果快手容器里已有自己的配置，以容器配置为准。";
    [self.view addSubview:self.hintLabel];

    [self refresh];
}

- (void)refresh {
    NSDictionary *d = KSLoadDefault();
    if (!d) {
        self.infoLabel.text = @"尚无默认身份\n（点下面的一键随机生成）";
        return;
    }
    long long ms = [d[@"installTimeMs"] longLongValue];
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"MM-dd HH:mm:ss";
    NSString *t = ms > 0 ? [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)ms / 1000.0]] : @"-";
    self.infoLabel.text = [NSString stringWithFormat:
        @"档案: %@  %@\n机型: %@ (%@)\n系统: %@ (%@)\n内存: %@ MB\n磁盘: %@ GB\n安装时间: %@",
        d[@"profileId"] ?: @"-", d[@"profileName"] ?: @"-",
        d[@"hwMachine"] ?: @"-", d[@"hwModel"] ?: @"-",
        d[@"systemVersion"] ?: @"-", d[@"systemBuild"] ?: @"-",
        d[@"memoryMB"] ?: @"-", d[@"diskGB"] ?: @"-", t];
}

- (void)randomize {
    NSMutableDictionary *m = KSRandomIdentity();
    NSString *path = KSDefaultCfgPath();
    BOOL ok = [m writeToFile:path atomically:YES];
    if (!ok) {
        // 权限兜底：写不进 /var/mobile/Library/Preferences 就写 tmp
        path = @"/tmp/com.bds.ksspoofer.default.plist";
        ok = [m writeToFile:path atomically:YES];
    }
    [self refresh];
    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:ok ? @"已生成默认身份" : @"写入失败"
                         message:ok ? [NSString stringWithFormat:
                             @"%@ %@ / %@\n\n现在打开快手即可生效。\n（如果快手已开，先后台划掉）",
                             m[@"profileId"], m[@"profileName"], m[@"systemVersion"]]
                                  : [NSString stringWithFormat:@"写不进：%@", path]
                  preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}
@end

@interface KSAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation KSAppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [KSVC new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([KSAppDelegate class]));
    }
}
