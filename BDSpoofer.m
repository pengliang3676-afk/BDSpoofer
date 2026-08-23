//
//  BDSpoofer.m
//  百度极速版设备信息虚拟化插件
//  注入方式：TrollFools
//  不依赖 Substrate/ElleKit，使用 Objective-C runtime method_setImplementation
//
//  1.7.0：
//    H. 主面板精简，基础/高级功能改为独立二级页面
//    I. 基础随机与高级身份随机彻底分离
//    J. 悬浮按钮自动贴边，静置 5 秒后收成半透明把手
//  1.6.2：
//    G. 整套随机保留本机真实屏幕尺寸，避免 UIScreen hook 导致界面缩放
//  1.6.1：
//    E. 基础页面增加“一键随机整套设备参数”
//       （iPhone 8 至 iPhone 13 系列，含 SE2/SE3；iOS 15/16）
//    F. 基础功能默认开启；随机操作仅在手动点击时执行并持久保存
//  1.6.0：
//    A. iPhone 8 默认硬件参数（与 SE2 硬件一致）
//    B. _dyld_get_image_name 镜像名过滤（fishhook）
//    C. C 函数级文件检测 hook（stat/lstat/access/fopen/opendir，fishhook）
//    D. NSBundle 遍历过滤（allFrameworks/allBundles/loadedBundles）
//    C 函数 hook 全部使用 fishhook（GOT 替换），不使用 DYLD_INTERPOSE，
//    原始函数指针直接指向 libSystem 真实地址，结构上杜绝递归。
//    arm64 iOS 上 stat 已是 64 位 inode，不 hook stat64。
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <Security/Security.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <WebKit/WebKit.h>
#import <dirent.h>
#import <stdio.h>
#import <unistd.h>
#import <string.h>
#import <errno.h>
#import <stdlib.h>
#import <mach/mach.h>

#pragma mark - 原子操作

#define BDS_ATOMIC_SET(var, val) __atomic_store_n(&(var), (val), __ATOMIC_RELEASE)
#define BDS_ATOMIC_GET(var) __atomic_load_n(&(var), __ATOMIC_ACQUIRE)

#pragma mark - 配置

static NSDictionary *g_config = nil;

// C hook 使用的全局开关（原子读写，constructor 中从配置设置）
static int g_enabledC = 0;
static int g_spoofSysctlC = 0;
static int g_bypassJailbreakC = 0;

// C hook 使用的缓存伪造值（constructor 和 saveConfigValues 中更新）
static char g_hwMachine[32] = "iPhone10,1";
static char g_hwModel[32] = "D20AP";
static char g_kernOSVersion[16] = "19H117";
static char g_kernHostname[65] = "iPhone";

static NSDictionary *BDSDefaultConfig(void) {
    static NSDictionary *defaults;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        defaults = @{
            @"configVersion": @170,
            @"enabled": @YES,
            @"spoofAdvertisingIdentifiers": @YES,
            @"spoofProcessHardware": @YES,
            @"spoofLocale": @YES,
            @"spoofCarrier": @YES,
            @"spoofScreen": @NO,
            @"spoofStorage": @YES,
            @"spoofBaiduSDK": @YES,
            @"spoofSysctl": @YES,
            @"spoofKeychain": @YES,
            @"spoofUserAgent": @YES,
            @"bypassJailbreakDetect": @YES,
            @"floatingButtonSide": @"right",
            @"floatingButtonYPermille": @520
        };
    });
    return defaults;
}

static NSString *configPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"bdspoofer_config.plist"];
}

static NSString *cfgStr(NSString *key, NSString *def) {
    NSString *v = g_config[key];
    return (v && [v isKindOfClass:[NSString class]]) ? v : def;
}
static BOOL cfgBool(NSString *key, BOOL def) {
    NSNumber *v = g_config[key];
    return v ? [v boolValue] : def;
}
static NSInteger cfgInt(NSString *key, NSInteger def) {
    NSNumber *v = g_config[key];
    return v ? [v integerValue] : def;
}

static void bds_update_c_cache(void) {
    NSString *v;
    v = cfgStr(@"hwMachine", @"iPhone10,1");
    snprintf(g_hwMachine, sizeof(g_hwMachine), "%s", v.UTF8String);
    v = cfgStr(@"hwModel", @"D20AP");
    snprintf(g_hwModel, sizeof(g_hwModel), "%s", v.UTF8String);
    v = cfgStr(@"kernOSVersion", @"19H117");
    snprintf(g_kernOSVersion, sizeof(g_kernOSVersion), "%s", v.UTF8String);
    v = cfgStr(@"kernHostname", @"iPhone");
    snprintf(g_kernHostname, sizeof(g_kernHostname), "%s", v.UTF8String);
}

static void loadConfig() {
    NSString *p1 = configPath();
    NSString *p2 = [[NSBundle mainBundle] pathForResource:@"bdspoofer_config" ofType:@"plist"];
    NSString *path = [[NSFileManager defaultManager] fileExistsAtPath:p1] ? p1 : p2;
    NSDictionary *loaded = path ? [NSDictionary dictionaryWithContentsOfFile:path] : nil;
    NSMutableDictionary *merged = [BDSDefaultConfig() mutableCopy];
    if (loaded) [merged addEntriesFromDictionary:loaded];
    NSInteger ver = [loaded[@"configVersion"] integerValue];
    if (ver < 150) {
        [merged addEntriesFromDictionary:@{
            @"configVersion": @150,
            @"enabled": @YES,
            @"spoofBaiduSDK": @YES,
            @"spoofSysctl": @NO,
            @"spoofKeychain": @YES,
            @"spoofUserAgent": @YES,
            @"bypassJailbreakDetect": @YES
        }];
    }
    if (ver < 160) {
        [merged addEntriesFromDictionary:@{
            @"configVersion": @160,
            @"spoofSysctl": @YES,
            @"systemVersion": @"15.7.1",
            @"systemBuild": @"19H117",
            @"hwMachine": @"iPhone10,1",
            @"hwModel": @"D20AP",
            @"kernOSVersion": @"19H117",
            @"screenWidth": @375,
            @"screenHeight": @667,
            @"screenScale": @2,
            @"memorySize": @2048,
            @"diskSize": @64
        }];
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 161) {
        // 1.6.1 只迁移基础功能开关；高级功能保持 1.6.0 的已有状态。
        [merged addEntriesFromDictionary:@{
            @"configVersion": @161,
            @"enabled": @YES,
            @"spoofAdvertisingIdentifiers": @YES,
            @"spoofProcessHardware": @YES,
            @"spoofLocale": @YES,
            @"spoofCarrier": @YES,
            @"spoofScreen": @NO,
            @"spoofStorage": @YES
        }];
        if (!loaded[@"nativeScreenWidth"]) merged[@"nativeScreenWidth"] = @750;
        if (!loaded[@"nativeScreenHeight"]) merged[@"nativeScreenHeight"] = @1334;
        if (!loaded[@"deviceProfileName"]) merged[@"deviceProfileName"] = @"iPhone 8";
        // 修正旧默认值中 15.7.1 与 15.7.3 Build 混用的问题，不覆盖用户自定义组合。
        if ([merged[@"systemVersion"] isEqualToString:@"15.7.1"] &&
            [merged[@"systemBuild"] isEqualToString:@"19H307"]) {
            merged[@"systemBuild"] = @"19H117";
            if ([merged[@"kernOSVersion"] isEqualToString:@"19H307"]) {
                merged[@"kernOSVersion"] = @"19H117";
            }
        }
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 162) {
        // UIScreen 会直接影响真实界面布局；升级后默认关闭并保留本机屏幕。
        merged[@"configVersion"] = @162;
        merged[@"spoofScreen"] = @NO;
        [merged writeToFile:p1 atomically:YES];
    }
    if (ver < 170) {
        merged[@"configVersion"] = @170;
        if (!loaded[@"floatingButtonSide"]) merged[@"floatingButtonSide"] = @"right";
        if (!loaded[@"floatingButtonYPermille"]) merged[@"floatingButtonYPermille"] = @520;
        [merged writeToFile:p1 atomically:YES];
    }
    g_config = [merged copy];
    bds_update_c_cache();
}

static BOOL saveConfigValues(NSDictionary *values) {
    if (!values.count) return NO;
    NSMutableDictionary *next = [g_config mutableCopy] ?: [NSMutableDictionary dictionary];
    [next addEntriesFromDictionary:values];
    BOOL saved = [next writeToFile:configPath() atomically:YES];
    if (saved) {
        g_config = [next copy];
        bds_update_c_cache();
        BDS_ATOMIC_SET(g_enabledC, cfgBool(@"enabled", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_spoofSysctlC, cfgBool(@"spoofSysctl", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_bypassJailbreakC, cfgBool(@"bypassJailbreakDetect", NO) ? 1 : 0);
    }
    return saved;
}

#pragma mark - Hook 工具

static void hookInst(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        if (oldImp) *oldImp = method_getImplementation(m);
        method_setImplementation(m, newImp);
    }
}

static void hookClass(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    if (!cls) return;
    Method m = class_getClassMethod(cls, sel);
    if (m) {
        if (oldImp) *oldImp = method_getImplementation(m);
        method_setImplementation(m, newImp);
    }
}

#pragma mark - fishhook（内嵌，GOT 符号重绑定）
// fishhook 通过修改各 image 的 __la_symbol_ptr / __nl_symbol_ptr 中的指针来 hook C 函数。
// 原始地址保存在 rebinding.replaced 中，直接指向 libSystem 真实实现，
// 调用原始函数不经过 GOT，因此结构上不可能出现 DYLD_INTERPOSE + dlsym 的递归问题。

// 架构类型定义（标准 fishhook 的 __LP64__ 类型块）
#ifdef __LP64__
typedef struct mach_header_64 bds_mach_header_t;
typedef struct segment_command_64 bds_segment_command_t;
typedef struct section_64 bds_section_t;
typedef struct nlist_64 bds_nlist_t;
#define BDS_LC_SEGMENT LC_SEGMENT_64
#else
typedef struct mach_header bds_mach_header_t;
typedef struct segment_command bds_segment_command_t;
typedef struct section bds_section_t;
typedef struct nlist bds_nlist_t;
#define BDS_LC_SEGMENT LC_SEGMENT
#endif

// SEG_DATA_CONST 在旧版 SDK 中未定义（官方 fishhook 同样做此兼容）
#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif

struct bds_rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct bds_rebindings_entry {
    struct bds_rebinding *rebindings;
    size_t rebindings_nel;
    struct bds_rebindings_entry *next;
};

static struct bds_rebindings_entry *bds_rebindings_head = NULL;

static int bds_prepend_rebindings(struct bds_rebindings_entry **head,
                                  struct bds_rebinding rebindings[],
                                  size_t nel) {
    struct bds_rebindings_entry *new_entry =
        (struct bds_rebindings_entry *)malloc(sizeof(struct bds_rebindings_entry));
    if (!new_entry) return -1;
    new_entry->rebindings =
        (struct bds_rebinding *)malloc(sizeof(struct bds_rebinding) * nel);
    if (!new_entry->rebindings) { free(new_entry); return -1; }
    memcpy(new_entry->rebindings, rebindings, sizeof(struct bds_rebinding) * nel);
    new_entry->rebindings_nel = nel;
    new_entry->next = *head;
    *head = new_entry;
    return 0;
}

static void bds_perform_rebinding_with_section(struct bds_rebindings_entry *rebindings,
                                               bds_section_t *section,
                                               intptr_t slide,
                                               bds_nlist_t *symtab,
                                               char *strtab,
                                               uint32_t *indirect_symtab,
                                               uint32_t nindirectsyms) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    uint32_t pointer_count = (uint32_t)(section->size / sizeof(void *));

    // 越界保护：reserved1 + 指针数不能超过间接符号表大小
    if (section->reserved1 >= nindirectsyms ||
        pointer_count > nindirectsyms - section->reserved1) {
        return;
    }

    int protected_region = 0;  // 延迟 vm_protect：找到匹配符号后才解除写保护

    for (uint i = 0; i < pointer_count; i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        if (!symbol_name[0] || !symbol_name[1]) continue;
        struct bds_rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    // 延迟到真正需要写入时才解除该 GOT 区域的写保护
                    if (!protected_region) {
                        kern_return_t vr = vm_protect(mach_task_self(),
                            (vm_address_t)indirect_symbol_bindings,
                            (vm_size_t)section->size, NO,
                            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        if (vr != KERN_SUCCESS) return;  // 写保护解除失败，跳过整个节
                        protected_region = 1;
                    }
                    if (cur->rebindings[j].replaced != NULL &&
                        indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    goto bds_symbol_loop;
                }
            }
            cur = cur->next;
        }
    bds_symbol_loop:;
    }
}

static void bds_rebind_symbols_for_image(struct bds_rebindings_entry *rebindings,
                                         const struct mach_header *header,
                                         intptr_t slide) {
    if (header->magic != MH_MAGIC_64 && header->magic != MH_MAGIC) return;

    bds_segment_command_t *cur_seg_cmd;
    bds_segment_command_t *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(bds_mach_header_t);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (bds_segment_command_t *)cur;
        if (cur_seg_cmd->cmd == BDS_LC_SEGMENT) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment) return;
    if (dysymtab_cmd->nindirectsyms == 0) return;

    uintptr_t linkedit_base =
        (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    bds_nlist_t *symtab = (bds_nlist_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab =
        (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(bds_mach_header_t);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (bds_segment_command_t *)cur;
        if (cur_seg_cmd->cmd == BDS_LC_SEGMENT) {
            // 只扫描 __DATA 和 __DATA_CONST（官方 fishhook 同样如此）。
            // 不扫描 __AUTH/__AUTH_CONST：arm64e 上这些段的 GOT 指针带 PAC 签名，
            // 直接写入未签名指针会在调用时触发认证失败崩溃。
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
                strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
                continue;
            }
            for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
                bds_section_t *sect =
                    (bds_section_t *)(cur + sizeof(bds_segment_command_t)) + j;
                uint8_t sect_type = sect->flags & SECTION_TYPE;
                if (sect_type == S_LAZY_SYMBOL_POINTERS ||
                    sect_type == S_NON_LAZY_SYMBOL_POINTERS) {
                    bds_perform_rebinding_with_section(rebindings, sect, slide,
                                                       symtab, strtab, indirect_symtab,
                                                       dysymtab_cmd->nindirectsyms);
                }
            }
        }
    }
}

static void bds_rebind_symbols_for_image_cb(const struct mach_header *mh, intptr_t slide) {
    bds_rebind_symbols_for_image(bds_rebindings_head, mh, slide);
}

static int bds_rebind_symbols(struct bds_rebinding rebindings[], size_t nel) {
    int retval = bds_prepend_rebindings(&bds_rebindings_head, rebindings, nel);
    if (retval < 0) return retval;
    if (bds_rebindings_head->next == NULL) {
        // 第一次调用：注册 dyld 回调，回调会立即对所有已加载 image 执行 rebind
        _dyld_register_func_for_add_image(bds_rebind_symbols_for_image_cb);
    } else {
        // 后续调用：手动对已加载 image 执行 rebind
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            bds_rebind_symbols_for_image(bds_rebindings_head,
                                         _dyld_get_image_header(i),
                                         _dyld_get_image_vmaddr_slide(i));
        }
    }
    return retval;
}

#pragma mark - 统一越狱路径表（C 数组）

static const char *bds_jailbreak_path_strings[] = {
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Library/MobileSubstrate",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/sbin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/usr/bin/sshd",
    "/usr/bin/cycript",
    "/usr/lib/libsubstrate.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libellekit.dylib",
    "/usr/lib/TweakInject",
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/ssh",
    "/var/jb",
    "/var/jb/Library",
    "/var/jb/basebin",
    "/var/jb/usr/lib/TweakInject",
    "/.bootstrapped_electra",
    "/.cydia_no_stash",
    "/.installed_unc0ver",
    "/jb",
    "/var/LIY",
    "/var/Memory.me",
    "/var/checkra1n.dmg",
    NULL
};

static int bds_c_is_jailbreak_path(const char *path) {
    if (!path) return 0;
    for (int i = 0; bds_jailbreak_path_strings[i]; i++) {
        const char *p = bds_jailbreak_path_strings[i];
        size_t len = strlen(p);
        if (strcmp(path, p) == 0) return 1;
        if (strncmp(path, p, len) == 0 && path[len] == '/') return 1;
    }
    return 0;
}

#pragma mark - UIDevice Hook

static IMP orig_systemVersion = NULL;
static NSString *new_systemVersion(id self, SEL _cmd) {
    return cfgStr(@"systemVersion", @"15.7.1");
}

static IMP orig_model = NULL;
static NSString *new_model(id self, SEL _cmd) {
    return cfgStr(@"deviceModel", @"iPhone");
}

static IMP orig_localizedModel = NULL;
static NSString *new_localizedModel(id self, SEL _cmd) {
    return cfgStr(@"marketingModel", @"iPhone");
}

static IMP orig_name = NULL;
static NSString *new_name(id self, SEL _cmd) {
    return cfgStr(@"deviceName", @"iPhone");
}

static IMP orig_systemName = NULL;
static NSString *new_systemName(id self, SEL _cmd) {
    return @"iOS";
}

static IMP orig_identifierForVendor = NULL;
static NSUUID *new_identifierForVendor(id self, SEL _cmd) {
    NSString *uuid = cfgStr(@"idfv", @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
    NSUUID *value = [[NSUUID alloc] initWithUUIDString:uuid];
    if (value) return value;
    if (orig_identifierForVendor) {
        return ((NSUUID *(*)(id, SEL))orig_identifierForVendor)(self, _cmd);
    }
    return nil;
}

#pragma mark - ASIdentifierManager Hook

static IMP orig_advertisingIdentifier = NULL;
static NSUUID *new_advertisingIdentifier(id self, SEL _cmd) {
    NSString *uuid = cfgStr(@"idfa", @"FEDCBA98-7654-3210-FEDC-BA9876543210");
    NSUUID *value = [[NSUUID alloc] initWithUUIDString:uuid];
    if (value) return value;
    if (orig_advertisingIdentifier) {
        return ((NSUUID *(*)(id, SEL))orig_advertisingIdentifier)(self, _cmd);
    }
    return nil;
}

static IMP orig_isAdvertisingTrackingEnabled = NULL;
static BOOL new_isAdvertisingTrackingEnabled(id self, SEL _cmd) {
    return NO;
}

#pragma mark - ATTrackingManager Hook (iOS 14+)

static IMP orig_trackingAuthorizationStatus = NULL;
static NSInteger new_trackingAuthorizationStatus(id self, SEL _cmd) {
    return 2; // denied
}

#pragma mark - NSProcessInfo Hook

static IMP orig_operatingSystemVersionString = NULL;
static NSString *new_operatingSystemVersionString(id self, SEL _cmd) {
    NSString *v = cfgStr(@"systemVersion", @"15.7.1");
    NSString *b = cfgStr(@"systemBuild", @"19H117");
    return [NSString stringWithFormat:@"Version %@ (Build %@)", v, b];
}

static IMP orig_operatingSystemVersion = NULL;
static NSOperatingSystemVersion new_operatingSystemVersion(id self, SEL _cmd) {
    NSOperatingSystemVersion v = {15, 7, 1};
    NSString *s = cfgStr(@"systemVersion", @"15.7.1");
    NSArray *p = [s componentsSeparatedByString:@"."];
    if (p.count >= 1) v.majorVersion = [p[0] integerValue];
    if (p.count >= 2) v.minorVersion = [p[1] integerValue];
    if (p.count >= 3) v.patchVersion = [p[2] integerValue];
    return v;
}

static IMP orig_hostName = NULL;
static NSString *new_hostName(id self, SEL _cmd) {
    return cfgStr(@"kernHostname", @"iPhone");
}

static IMP orig_physicalMemory = NULL;
static unsigned long long new_physicalMemory(id self, SEL _cmd) {
    return (unsigned long long)cfgInt(@"memorySize", 2048) * 1024 * 1024;
}

#pragma mark - NSLocale Hook

static IMP orig_localeIdentifier = NULL;
static NSString *new_localeIdentifier(id self, SEL _cmd) {
    return cfgStr(@"localeIdentifier", @"zh_CN");
}

#pragma mark - CTTelephonyNetworkInfo / CTCarrier Hook

static IMP orig_subscriberCellularProvider = NULL;
static CTCarrier *new_subscriberCellularProvider(id self, SEL _cmd) {
    CTCarrier *fake = [[CTCarrier alloc] init];
    return fake;
}

static IMP orig_serviceSubscriberCellularProviders = NULL;
static NSDictionary *new_serviceSubscriberCellularProviders(id self, SEL _cmd) {
    CTCarrier *fake = [[CTCarrier alloc] init];
    return @{@"0000000100000001": fake};
}

static IMP orig_carrierName = NULL;
static NSString *new_carrierName(id self, SEL _cmd) {
    return cfgStr(@"carrierName", @"中国移动");
}

static IMP orig_mobileCountryCode = NULL;
static NSString *new_mobileCountryCode(id self, SEL _cmd) {
    return cfgStr(@"mcc", @"460");
}

static IMP orig_mobileNetworkCode = NULL;
static NSString *new_mobileNetworkCode(id self, SEL _cmd) {
    return cfgStr(@"mnc", @"00");
}

static IMP orig_isoCountryCode = NULL;
static NSString *new_isoCountryCode(id self, SEL _cmd) {
    return cfgStr(@"isoCountryCode", @"cn");
}

static IMP orig_allowsVOIP = NULL;
static BOOL new_allowsVOIP(id self, SEL _cmd) {
    return YES;
}

#pragma mark - UIScreen Hook

static IMP orig_bounds = NULL;
static CGRect new_bounds(id self, SEL _cmd) {
    CGFloat w = cfgInt(@"screenWidth", 375);
    CGFloat h = cfgInt(@"screenHeight", 667);
    return CGRectMake(0, 0, w, h);
}

static IMP orig_nativeBounds = NULL;
static CGRect new_nativeBounds(id self, SEL _cmd) {
    CGFloat scale = (CGFloat)cfgInt(@"screenScale", 2);
    CGFloat w = (CGFloat)cfgInt(@"nativeScreenWidth",
                                cfgInt(@"screenWidth", 375) * scale);
    CGFloat h = (CGFloat)cfgInt(@"nativeScreenHeight",
                                cfgInt(@"screenHeight", 667) * scale);
    return CGRectMake(0, 0, w, h);
}

static IMP orig_scale = NULL;
static CGFloat new_scale(id self, SEL _cmd) {
    return (CGFloat)cfgInt(@"screenScale", 2);
}

#pragma mark - NSFileManager Hook（磁盘大小）

static IMP orig_attributesOfFileSystemForPath = NULL;
static NSDictionary *new_attributesOfFileSystemForPath(id self, SEL _cmd, id path, NSError **error) {
    typedef NSDictionary *(*FileSystemAttributesIMP)(id, SEL, NSString *, NSError **);
    NSDictionary *orig = orig_attributesOfFileSystemForPath
        ? ((FileSystemAttributesIMP)orig_attributesOfFileSystemForPath)(self, _cmd, path, error)
        : nil;
    if (!orig) return orig;
    NSMutableDictionary *m = [orig mutableCopy];
    long long diskSize = cfgInt(@"diskSize", 64) * 1024LL * 1024LL * 1024LL;
    m[NSFileSystemSize] = @(diskSize);
    m[NSFileSystemFreeSize] = @(diskSize / 2);
    return m;
}

#pragma mark - 百度 SDK Hook

static NSRecursiveLock *g_baiduLock = nil;
static NSMutableDictionary<NSString *, NSValue *> *g_baiduOrigImps = nil;
static NSMutableSet<NSString *> *g_baiduHookedKeys = nil;

static NSString *bds_cuid_value(void) {
    return cfgStr(@"cuid", @"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6");
}
static NSString *bds_utdid_value(void) {
    return cfgStr(@"utdid", @"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
}
static NSString *bds_deviceID_value(void) {
    return cfgStr(@"deviceID", @"A1B2C3D4-E5F6-A7B8-C9D0-E1F2A3B4C5D6");
}

static NSString *bds_fake_value_for_cmd(SEL _cmd) {
    NSString *selName = NSStringFromSelector(_cmd).lowercaseString;
    if ([selName containsString:@"utdid"]) return bds_utdid_value();
    if ([selName containsString:@"cuid"]) return bds_cuid_value();
    return bds_deviceID_value();
}

static NSString *new_baidu_string_sync(id self, SEL _cmd) {
    BOOL isClassMethod = object_isClass(self);
    NSString *className = isClassMethod ? NSStringFromClass(self) : NSStringFromClass([self class]);
    NSString *impKey = [NSString stringWithFormat:@"%@.%@.%@",
                        className, NSStringFromSelector(_cmd),
                        isClassMethod ? @"C" : @"I"];

    NSValue *origValue = nil;
    [g_baiduLock lock];
    origValue = g_baiduOrigImps[impKey];
    [g_baiduLock unlock];

    if (!cfgBool(@"spoofBaiduSDK", NO)) {
        if (origValue) {
            IMP orig = [origValue pointerValue];
            return ((NSString *(*)(id, SEL))orig)(self, _cmd);
        }
        return nil;
    }

    if (origValue) {
        IMP orig = [origValue pointerValue];
        id result = ((id (*)(id, SEL))orig)(self, _cmd);
        if ([result isKindOfClass:[NSString class]]) {
            return bds_fake_value_for_cmd(_cmd);
        }
        return result;
    }
    return bds_fake_value_for_cmd(_cmd);
}

static BOOL bds_isSafeSyncMethod(Method m) {
    if (!m) return NO;
    if (method_getNumberOfArguments(m) != 2) return NO;
    char retType[16];
    method_getReturnType(m, retType, sizeof(retType));
    return retType[0] == '@';
}

static void bds_tryHookMethod(Class cls, SEL sel, BOOL isClassMethod) {
    if (!cls) return;
    NSString *className = NSStringFromClass(cls);
    NSString *key = [NSString stringWithFormat:@"%@.%@.%s",
                     className, NSStringFromSelector(sel), isClassMethod ? "C" : "I"];
    NSString *impKey = [NSString stringWithFormat:@"%@.%@.%@",
                        className, NSStringFromSelector(sel),
                        isClassMethod ? @"C" : @"I"];

    [g_baiduLock lock];

    if ([g_baiduHookedKeys containsObject:key]) {
        [g_baiduLock unlock];
        return;
    }

    Method m = isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m || !bds_isSafeSyncMethod(m)) {
        [g_baiduLock unlock];
        return;
    }

    Class targetCls = isClassMethod ? object_getClass(cls) : cls;
    IMP oldImp = class_replaceMethod(targetCls, sel, (IMP)new_baidu_string_sync,
                                     method_getTypeEncoding(m));
    if (!oldImp) {
        oldImp = method_getImplementation(m);
    }

    [g_baiduOrigImps setObject:[NSValue valueWithPointer:oldImp] forKey:impKey];
    [g_baiduHookedKeys addObject:key];
    [g_baiduLock unlock];
}

static void bds_tryHookClass(NSString *className, NSArray<NSString *> *selectors) {
    Class cls = objc_getClass(className.UTF8String);
    if (!cls) return;
    for (NSString *selName in selectors) {
        SEL sel = NSSelectorFromString(selName);
        bds_tryHookMethod(cls, sel, YES);
        bds_tryHookMethod(cls, sel, NO);
    }
}

static NSArray<NSDictionary *> *bds_baiduTargets(void) {
    static NSArray *targets;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        targets = @[
            @{@"class": @"CuidSDK", @"selectors": @[@"cuid", @"getCUID", @"getCuid", @"CUID"]},
            @{@"class": @"CuidSDK18BBADevAccountPatch", @"selectors": @[@"cuid", @"getCUID", @"getCuid"]},
            @{@"class": @"UTDIDModule", @"selectors": @[@"utdid", @"getUTDID", @"UTDID"]},
            @{@"class": @"MobStat", @"selectors": @[@"deviceId", @"getDeviceId", @"deviceID", @"getDeviceID",
                                                     @"getDeviceIdentification", @"deviceIdentification"]},
            @{@"class": @"DeviceIdentifierFetcher", @"selectors": @[@"deviceIdentifier", @"getDeviceIdentifier",
                                                                     @"sharedIdentifier", @"fetchIdentifier"]}
        ];
    });
    return targets;
}

static void bds_scanBaiduSDKClasses(void) {
    if (!g_baiduLock) {
        g_baiduLock = [[NSRecursiveLock alloc] init];
        g_baiduOrigImps = [NSMutableDictionary dictionary];
        g_baiduHookedKeys = [NSMutableSet set];
    }
    for (NSDictionary *target in bds_baiduTargets()) {
        bds_tryHookClass(target[@"class"], target[@"selectors"]);
    }
}

static void bds_dyld_add_image_cb(const struct mach_header *mh, intptr_t vmaddr_slide) {
    (void)mh; (void)vmaddr_slide;
    bds_scanBaiduSDKClasses();
}

static void installBaiduSDKHooks(void) {
    bds_scanBaiduSDKClasses();
    _dyld_register_func_for_add_image(bds_dyld_add_image_cb);
}

#pragma mark - sysctlbyname Hook（fishhook，纯 C）

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);

static int bds_my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                                void *newp, size_t newlen) {
    // 异常参数或写入操作直接透传
    if (!name || (oldp && !oldlenp) || newp) {
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    if (!BDS_ATOMIC_GET(g_enabledC) || !BDS_ATOMIC_GET(g_spoofSysctlC)) {
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    const char *fake = NULL;
    if (strcmp(name, "hw.machine") == 0) {
        fake = g_hwMachine;
    } else if (strcmp(name, "hw.model") == 0) {
        fake = g_hwModel;
    } else if (strcmp(name, "kern.osversion") == 0) {
        fake = g_kernOSVersion;
    } else if (strcmp(name, "kern.hostname") == 0) {
        fake = g_kernHostname;
    }

    if (!fake) {
        return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    size_t fakeLen = strlen(fake) + 1;

    if (oldp == NULL) {
        if (oldlenp) *oldlenp = fakeLen;
        return 0;
    }

    if (*oldlenp < fakeLen) {
        *oldlenp = fakeLen;
        return ENOMEM;
    }

    memcpy(oldp, fake, fakeLen);
    *oldlenp = fakeLen;
    return 0;
}

#pragma mark - Keychain Hook（fishhook）

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);

static BOOL bds_keychainValueContainsBaidu(id value) {
    if (![value isKindOfClass:NSString.class]) return NO;
    return [(NSString *)value rangeOfString:@"baidu"
                                    options:NSCaseInsensitiveSearch].location != NSNotFound;
}

static OSStatus bds_my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (!g_config || !cfgBool(@"enabled", NO) ||
        !cfgBool(@"spoofKeychain", NO) || !query) {
        return orig_SecItemCopyMatching(query, result);
    }

    @autoreleasepool {
        NSDictionary *dictionary = (__bridge NSDictionary *)query;
        NSArray *keys = @[
            (__bridge id)kSecAttrAccessGroup,
            (__bridge id)kSecAttrService,
            (__bridge id)kSecAttrAccount,
            (__bridge id)kSecAttrDescription,
            (__bridge id)kSecAttrLabel,
            @"agrp"
        ];
        for (id key in keys) {
            if (bds_keychainValueContainsBaidu(dictionary[key])) {
                if (result) *result = NULL;
                return errSecItemNotFound;
            }
        }
    }

    return orig_SecItemCopyMatching(query, result);
}

#pragma mark - User-Agent Hook

static IMP orig_wk_customUserAgent = NULL;
static NSString *new_wk_customUserAgent(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    NSString *custom = cfgStr(@"userAgent", @"");
    if (custom.length > 0) return custom;
    NSString *v = [cfgStr(@"systemVersion", @"15.7.1") stringByReplacingOccurrencesOfString:@"." withString:@"_"];
    return [NSString stringWithFormat:
        @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", v];
}

static IMP orig_nsmurl_setValue = NULL;
static void new_nsmurl_setValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if (field && value &&
        [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame &&
        cfgBool(@"spoofUserAgent", NO)) {
        NSString *custom = cfgStr(@"userAgent", @"");
        value = custom.length > 0 ? custom : nil;
        if (!value) {
            NSString *v = [cfgStr(@"systemVersion", @"15.7.1") stringByReplacingOccurrencesOfString:@"." withString:@"_"];
            value = [NSString stringWithFormat:
                @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", v];
        }
    }
    typedef void (*SetValueIMP)(id, SEL, NSString *, NSString *);
    if (orig_nsmurl_setValue) ((SetValueIMP)orig_nsmurl_setValue)(self, _cmd, value, field);
}

static IMP orig_nsmurl_addValue = NULL;
static void new_nsmurl_addValue(id self, SEL _cmd, NSString *value, NSString *field) {
    if (field && value &&
        [field caseInsensitiveCompare:@"User-Agent"] == NSOrderedSame &&
        cfgBool(@"spoofUserAgent", NO)) {
        NSString *custom = cfgStr(@"userAgent", @"");
        value = custom.length > 0 ? custom : nil;
        if (!value) {
            NSString *v = [cfgStr(@"systemVersion", @"15.7.1") stringByReplacingOccurrencesOfString:@"." withString:@"_"];
            value = [NSString stringWithFormat:
                @"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", v];
        }
    }
    typedef void (*AddValueIMP)(id, SEL, NSString *, NSString *);
    if (orig_nsmurl_addValue) ((AddValueIMP)orig_nsmurl_addValue)(self, _cmd, value, field);
}

#pragma mark - B: dyld 镜像名过滤（fishhook，纯 C）

static const char *(*orig_dyld_get_image_name)(uint32_t);

static const char *bds_fake_image_names[] = {
    "/System/Library/Frameworks/Foundation.framework/Foundation",
    "/System/Library/Frameworks/UIKit.framework/UIKit",
    "/usr/lib/libobjc.A.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
    "/usr/lib/system/libsystem_kernel.dylib",
    "/usr/lib/system/libsystem_c.dylib",
    "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
    "/usr/lib/libc++.1.dylib"
};
#define BDS_FAKE_IMAGE_COUNT (sizeof(bds_fake_image_names) / sizeof(bds_fake_image_names[0]))

static int bds_c_should_hide_image(const char *name) {
    if (!name) return 0;
    static const char *needles[] = {
        "BDSpoofer", "TrollFools", "TrollStore", "dopamine", "Dopamine",
        "ellekit", "ElleKit", "libhooker", "substrate", "Substrate",
        "CydiaSubstrate", "TweakInject", "/var/jb/", "roothide", "RootHide",
        "Choicy", "A-Bypass", "Shadow", "Liberty", "UnSub",
        NULL
    };
    for (int i = 0; needles[i]; i++) {
        if (strstr(name, needles[i])) return 1;
    }
    return 0;
}

static const char *bds_my_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name(image_index);
    if (!name) return name;
    if (!BDS_ATOMIC_GET(g_enabledC) || !BDS_ATOMIC_GET(g_bypassJailbreakC)) return name;
    if (bds_c_should_hide_image(name)) {
        return bds_fake_image_names[image_index % BDS_FAKE_IMAGE_COUNT];
    }
    return name;
}

#pragma mark - C: C 函数级文件检测 hook（fishhook）
// arm64 iOS 上 struct stat 已使用 64 位 inode（__DARWIN_ONLY_64_BIT_INO_T=1），
// stat64/struct stat64 不公开，因此不 hook stat64。

static int (*orig_stat)(const char *, struct stat *);
static int (*orig_lstat)(const char *, struct stat *);
static int (*orig_access)(const char *, int);
static FILE *(*orig_fopen)(const char *, const char *);
static DIR *(*orig_opendir)(const char *);

static int bds_my_stat(const char *path, struct stat *buf) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat(path, buf);
}

static int bds_my_lstat(const char *path, struct stat *buf) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat(path, buf);
}

static int bds_my_access(const char *path, int mode) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access(path, mode);
}

static FILE *bds_my_fopen(const char *path, const char *mode) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen(path, mode);
}

static DIR *bds_my_opendir(const char *path) {
    if (BDS_ATOMIC_GET(g_enabledC) && BDS_ATOMIC_GET(g_bypassJailbreakC) &&
        bds_c_is_jailbreak_path(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_opendir(path);
}

#pragma mark - 越狱检测绕过（ObjC 层）

static NSArray<NSString *> *bds_jailbreakSchemes(void) {
    static NSArray *schemes;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        schemes = @[@"cydia", @"sileo", @"zebra", @"installer", @"filza", @"undecimus", @"activator"];
    });
    return schemes;
}

static BOOL bds_isJailbreakPath(NSString *path) {
    if (!path) return NO;
    return bds_c_is_jailbreak_path(path.UTF8String) ? YES : NO;
}

static BOOL bds_isSuspiciousBundlePath(NSString *path) {
    if (!path) return NO;
    if (bds_isJailbreakPath(path)) return YES;
    NSString *lower = path.lowercaseString;
    NSArray *needles = @[@"bdspoofer", @"trollfools", @"trollstore", @"dopamine",
                         @"ellekit", @"libhooker", @"substrate", @"tweakinject",
                         @"roothide", @"/var/jb/"];
    for (NSString *n in needles) {
        if ([lower containsString:n]) return YES;
    }
    return NO;
}

static IMP orig_fileExistsAtPath = NULL;
static BOOL new_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (cfgBool(@"bypassJailbreakDetect", NO) && bds_isJailbreakPath(path)) return NO;
    typedef BOOL (*ExistsIMP)(id, SEL, NSString *);
    if (orig_fileExistsAtPath) return ((ExistsIMP)orig_fileExistsAtPath)(self, _cmd, path);
    return NO;
}

static IMP orig_fileExistsAtPathIsDir = NULL;
static BOOL new_fileExistsAtPathIsDir(id self, SEL _cmd, NSString *path, BOOL *isDirectory) {
    if (cfgBool(@"bypassJailbreakDetect", NO) && bds_isJailbreakPath(path)) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    typedef BOOL (*ExistsDirIMP)(id, SEL, NSString *, BOOL *);
    if (orig_fileExistsAtPathIsDir) return ((ExistsDirIMP)orig_fileExistsAtPathIsDir)(self, _cmd, path, isDirectory);
    return NO;
}

static IMP orig_canOpenURL = NULL;
static BOOL new_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (cfgBool(@"bypassJailbreakDetect", NO)) {
        NSString *scheme = url.scheme.lowercaseString;
        if (scheme && [bds_jailbreakSchemes() containsObject:scheme]) return NO;
    }
    typedef BOOL (*CanOpenIMP)(id, SEL, NSURL *);
    if (orig_canOpenURL) return ((CanOpenIMP)orig_canOpenURL)(self, _cmd, url);
    return NO;
}

#pragma mark - D: NSBundle 遍历过滤

static IMP orig_allFrameworks = NULL;
static NSArray *new_allFrameworks(id self, SEL _cmd) {
    typedef NSArray *(*AllFrameworksIMP)(id, SEL);
    NSArray *orig = orig_allFrameworks ? ((AllFrameworksIMP)orig_allFrameworks)(self, _cmd) : @[];
    if (!cfgBool(@"bypassJailbreakDetect", NO)) return orig;
    NSMutableArray *filtered = [NSMutableArray array];
    for (NSBundle *bundle in orig) {
        if (![bundle isKindOfClass:[NSBundle class]]) { [filtered addObject:bundle]; continue; }
        if (!bds_isSuspiciousBundlePath(bundle.bundlePath)) {
            [filtered addObject:bundle];
        }
    }
    return filtered;
}

static IMP orig_allBundles = NULL;
static NSArray *new_allBundles(id self, SEL _cmd) {
    typedef NSArray *(*AllBundlesIMP)(id, SEL);
    NSArray *orig = orig_allBundles ? ((AllBundlesIMP)orig_allBundles)(self, _cmd) : @[];
    if (!cfgBool(@"bypassJailbreakDetect", NO)) return orig;
    NSMutableArray *filtered = [NSMutableArray array];
    for (NSBundle *bundle in orig) {
        if (![bundle isKindOfClass:[NSBundle class]]) { [filtered addObject:bundle]; continue; }
        if (!bds_isSuspiciousBundlePath(bundle.bundlePath)) {
            [filtered addObject:bundle];
        }
    }
    return filtered;
}

static IMP orig_loadedBundles = NULL;
static NSArray *new_loadedBundles(id self, SEL _cmd) {
    typedef NSArray *(*LoadedBundlesIMP)(id, SEL);
    NSArray *orig = orig_loadedBundles ? ((LoadedBundlesIMP)orig_loadedBundles)(self, _cmd) : @[];
    if (!cfgBool(@"bypassJailbreakDetect", NO)) return orig;
    NSMutableArray *filtered = [NSMutableArray array];
    for (NSBundle *bundle in orig) {
        if (![bundle isKindOfClass:[NSBundle class]]) { [filtered addObject:bundle]; continue; }
        if (!bds_isSuspiciousBundlePath(bundle.bundlePath)) {
            [filtered addObject:bundle];
        }
    }
    return filtered;
}

#pragma mark - C 函数 hook 安装（fishhook）

static void installCHooks(void) {
    struct bds_rebinding rebindings[] = {
        {"sysctlbyname", (void *)bds_my_sysctlbyname, (void **)&orig_sysctlbyname},
        {"SecItemCopyMatching", (void *)bds_my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"_dyld_get_image_name", (void *)bds_my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"stat", (void *)bds_my_stat, (void **)&orig_stat},
        {"lstat", (void *)bds_my_lstat, (void **)&orig_lstat},
        {"access", (void *)bds_my_access, (void **)&orig_access},
        {"fopen", (void *)bds_my_fopen, (void **)&orig_fopen},
        {"opendir", (void *)bds_my_opendir, (void **)&orig_opendir},
    };
    bds_rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
}

#pragma mark - 悬浮配置入口

static const void *BDSButtonKey = &BDSButtonKey;
static const CGFloat BDSButtonFullSize = 42.0;
static const CGFloat BDSButtonCollapsedWidth = 18.0;
static const NSTimeInterval BDSButtonCollapseDelay = 5.0;

@interface BDSUIController : NSObject
@property (nonatomic, assign) NSUInteger floatingButtonGeneration;
+ (instancetype)shared;
- (void)attachButton;
- (void)openPanel;
- (void)editSystemVersion;
- (void)editDeviceName;
- (void)editIdentifiers;
- (void)randomizeBasicProfile;
- (void)randomizeAdvancedProfile;
- (void)showOptionalSwitches;
- (void)showOptionalEditors;
- (void)showAdvancedSwitches;
- (void)showAdvancedEditors;
- (void)editProcessHardware;
- (void)editLocaleCarrier;
- (void)editScreenStorage;
- (void)showSelfTest;
- (void)presentMessage:(NSString *)message title:(NSString *)title;
- (void)showRestartNotice:(BOOL)saved;
- (void)scheduleButtonCollapse:(UIButton *)button;
- (void)expandButton:(UIButton *)button animated:(BOOL)animated;
- (void)collapseButton:(UIButton *)button;
@end

static UIWindow *BDSMainWindow(void) {
    UIWindow *fallback = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] ||
            scene.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window.isKeyWindow) return window;
            if (!fallback && window.rootViewController && window.windowLevel == UIWindowLevelNormal) {
                fallback = window;
            }
        }
    }
    return fallback;
}

static UIViewController *BDSTopController(void) {
    UIViewController *controller = BDSMainWindow().rootViewController;
    while (controller) {
        if (controller.presentedViewController) {
            controller = controller.presentedViewController;
        } else if ([controller isKindOfClass:UINavigationController.class]) {
            controller = ((UINavigationController *)controller).visibleViewController;
        } else if ([controller isKindOfClass:UITabBarController.class]) {
            controller = ((UITabBarController *)controller).selectedViewController;
        } else {
            break;
        }
    }
    return controller;
}

static NSString *BDSOnOff(BOOL value) {
    return value ? @"开" : @"关";
}

static NSString *BDSRandomHex32(BOOL uppercase) {
    NSString *value = [[NSUUID.UUID.UUIDString
        stringByReplacingOccurrencesOfString:@"-" withString:@""] substringToIndex:32];
    return uppercase ? value.uppercaseString : value.lowercaseString;
}

static NSDictionary *BDSRandomIdentityValues(void) {
    return @{
        @"idfa": NSUUID.UUID.UUIDString.uppercaseString,
        @"idfv": NSUUID.UUID.UUIDString.uppercaseString,
        @"deviceID": NSUUID.UUID.UUIDString.uppercaseString,
        @"cuid": BDSRandomHex32(YES),
        @"utdid": BDSRandomHex32(NO)
    };
}

static NSArray<NSDictionary *> *BDSDeviceProfiles(void) {
    static NSArray<NSDictionary *> *profiles;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        profiles = @[
            @{@"name": @"iPhone 8", @"machine": @"iPhone10,1", @"model": @"D20AP",
              @"width": @375, @"height": @667, @"nativeWidth": @750, @"nativeHeight": @1334,
              @"scale": @2, @"memory": @2048, @"disks": @[@64, @256]},
            @{@"name": @"iPhone 8 Plus", @"machine": @"iPhone10,2", @"model": @"D21AP",
              @"width": @414, @"height": @736, @"nativeWidth": @1080, @"nativeHeight": @1920,
              @"scale": @3, @"memory": @3072, @"disks": @[@64, @256]},
            @{@"name": @"iPhone X", @"machine": @"iPhone10,3", @"model": @"D22AP",
              @"width": @375, @"height": @812, @"nativeWidth": @1125, @"nativeHeight": @2436,
              @"scale": @3, @"memory": @3072, @"disks": @[@64, @256]},
            @{@"name": @"iPhone XR", @"machine": @"iPhone11,8", @"model": @"N841AP",
              @"width": @414, @"height": @896, @"nativeWidth": @828, @"nativeHeight": @1792,
              @"scale": @2, @"memory": @3072, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone XS", @"machine": @"iPhone11,2", @"model": @"D321AP",
              @"width": @375, @"height": @812, @"nativeWidth": @1125, @"nativeHeight": @2436,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @256, @512]},
            @{@"name": @"iPhone XS Max", @"machine": @"iPhone11,6", @"model": @"D331pAP",
              @"width": @414, @"height": @896, @"nativeWidth": @1242, @"nativeHeight": @2688,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @256, @512]},
            @{@"name": @"iPhone 11", @"machine": @"iPhone12,1", @"model": @"N104AP",
              @"width": @414, @"height": @896, @"nativeWidth": @828, @"nativeHeight": @1792,
              @"scale": @2, @"memory": @4096, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone 11 Pro", @"machine": @"iPhone12,3", @"model": @"D421AP",
              @"width": @375, @"height": @812, @"nativeWidth": @1125, @"nativeHeight": @2436,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @256, @512]},
            @{@"name": @"iPhone 11 Pro Max", @"machine": @"iPhone12,5", @"model": @"D431AP",
              @"width": @414, @"height": @896, @"nativeWidth": @1242, @"nativeHeight": @2688,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @256, @512]},
            @{@"name": @"iPhone SE (2nd generation)", @"machine": @"iPhone12,8", @"model": @"D79AP",
              @"width": @375, @"height": @667, @"nativeWidth": @750, @"nativeHeight": @1334,
              @"scale": @2, @"memory": @3072, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone 12 mini", @"machine": @"iPhone13,1", @"model": @"D52gAP",
              @"width": @375, @"height": @812, @"nativeWidth": @1080, @"nativeHeight": @2340,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone 12", @"machine": @"iPhone13,2", @"model": @"D53gAP",
              @"width": @390, @"height": @844, @"nativeWidth": @1170, @"nativeHeight": @2532,
              @"scale": @3, @"memory": @4096, @"disks": @[@64, @128, @256]},
            @{@"name": @"iPhone 12 Pro", @"machine": @"iPhone13,3", @"model": @"D53pAP",
              @"width": @390, @"height": @844, @"nativeWidth": @1170, @"nativeHeight": @2532,
              @"scale": @3, @"memory": @6144, @"disks": @[@128, @256, @512]},
            @{@"name": @"iPhone 12 Pro Max", @"machine": @"iPhone13,4", @"model": @"D54pAP",
              @"width": @428, @"height": @926, @"nativeWidth": @1284, @"nativeHeight": @2778,
              @"scale": @3, @"memory": @6144, @"disks": @[@128, @256, @512]},
            @{@"name": @"iPhone 13 mini", @"machine": @"iPhone14,4", @"model": @"D16AP",
              @"width": @375, @"height": @812, @"nativeWidth": @1080, @"nativeHeight": @2340,
              @"scale": @3, @"memory": @4096, @"disks": @[@128, @256, @512]},
            @{@"name": @"iPhone 13", @"machine": @"iPhone14,5", @"model": @"D17AP",
              @"width": @390, @"height": @844, @"nativeWidth": @1170, @"nativeHeight": @2532,
              @"scale": @3, @"memory": @4096, @"disks": @[@128, @256, @512]},
            @{@"name": @"iPhone 13 Pro", @"machine": @"iPhone14,2", @"model": @"D63AP",
              @"width": @390, @"height": @844, @"nativeWidth": @1170, @"nativeHeight": @2532,
              @"scale": @3, @"memory": @6144, @"disks": @[@128, @256, @512, @1024]},
            @{@"name": @"iPhone 13 Pro Max", @"machine": @"iPhone14,3", @"model": @"D64AP",
              @"width": @428, @"height": @926, @"nativeWidth": @1284, @"nativeHeight": @2778,
              @"scale": @3, @"memory": @6144, @"disks": @[@128, @256, @512, @1024]},
            @{@"name": @"iPhone SE (3rd generation)", @"machine": @"iPhone14,6", @"model": @"D49AP",
              @"width": @375, @"height": @667, @"nativeWidth": @750, @"nativeHeight": @1334,
              @"scale": @2, @"memory": @4096, @"disks": @[@64, @128, @256]}
        ];
    });
    return profiles;
}

static NSArray<NSDictionary *> *BDSSystemProfiles(void) {
    static NSArray<NSDictionary *> *profiles;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        profiles = @[
            @{@"version": @"15.7.1", @"build": @"19H117"},
            @{@"version": @"15.7.3", @"build": @"19H307"},
            @{@"version": @"16.6.1", @"build": @"20G81"},
            @{@"version": @"16.7", @"build": @"20H19"}
        ];
    });
    return profiles;
}

static NSDictionary *BDSRandomBasicProfileValues(void) {
    NSArray<NSDictionary *> *allDevices = BDSDeviceProfiles();
    NSString *currentMachine = cfgStr(@"hwMachine", @"");
    NSMutableArray<NSDictionary *> *candidates = [NSMutableArray array];
    for (NSDictionary *profile in allDevices) {
        if (![profile[@"machine"] isEqualToString:currentMachine]) [candidates addObject:profile];
    }
    if (!candidates.count) [candidates addObjectsFromArray:allDevices];
    NSDictionary *device = candidates[arc4random_uniform((uint32_t)candidates.count)];
    NSArray<NSDictionary *> *systems = BDSSystemProfiles();
    NSDictionary *system = systems[arc4random_uniform((uint32_t)systems.count)];
    NSArray<NSNumber *> *disks = device[@"disks"];
    NSNumber *disk = disks[arc4random_uniform((uint32_t)disks.count)];

    NSMutableDictionary *values = [NSMutableDictionary dictionary];
    NSString *deviceSuffix = [BDSRandomHex32(YES) substringToIndex:6];
    NSString *deviceName = [@"iPhone-" stringByAppendingString:deviceSuffix];
    values[@"enabled"] = @YES;
    values[@"spoofAdvertisingIdentifiers"] = @YES;
    values[@"spoofProcessHardware"] = @YES;
    values[@"spoofLocale"] = @YES;
    values[@"spoofCarrier"] = @YES;
    // 保持本机真实屏幕，避免随机到大屏机型后界面被放大或缩小。
    values[@"spoofScreen"] = @NO;
    values[@"spoofStorage"] = @YES;
    values[@"deviceProfileName"] = device[@"name"];
    values[@"deviceModel"] = @"iPhone";
    values[@"marketingModel"] = @"iPhone";
    values[@"systemVersion"] = system[@"version"];
    values[@"systemBuild"] = system[@"build"];
    values[@"kernOSVersion"] = system[@"build"];
    values[@"hwMachine"] = device[@"machine"];
    values[@"hwModel"] = device[@"model"];
    values[@"memorySize"] = device[@"memory"];
    values[@"diskSize"] = disk;
    values[@"deviceName"] = deviceName;
    values[@"kernHostname"] = deviceName;
    return values;
}

static NSString *BDSConfigSummary(void) {
    return [NSString stringWithFormat:
        @"状态：%@\n设备：%@\n系统：iOS %@ (%@)",
        cfgBool(@"enabled", NO) ? @"已开启" : @"已关闭",
        cfgStr(@"deviceProfileName", @"iPhone 8"),
        cfgStr(@"systemVersion", @"15.7.1"),
        cfgStr(@"systemBuild", @"19H117")];
}

@implementation BDSUIController

+ (instancetype)shared {
    static BDSUIController *controller;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ controller = [BDSUIController new]; });
    return controller;
}

- (void)attachButton {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = BDSMainWindow();
        if (!window) return;
        UIButton *button = objc_getAssociatedObject(window, BDSButtonKey);
        if (!button) {
            BOOL leftSide = [cfgStr(@"floatingButtonSide", @"right") isEqualToString:@"left"];
            CGFloat containerWidth = CGRectGetWidth(window.bounds);
            CGFloat containerHeight = CGRectGetHeight(window.bounds);
            CGFloat centerY = containerHeight * ((CGFloat)cfgInt(@"floatingButtonYPermille", 520) / 1000.0);
            centerY = MIN(MAX(centerY, BDSButtonFullSize / 2.0 + 44.0),
                          containerHeight - BDSButtonFullSize / 2.0 - 20.0);
            CGFloat x = leftSide ? 4.0 : containerWidth - BDSButtonFullSize - 4.0;
            button = [UIButton buttonWithType:UIButtonTypeSystem];
            button.frame = CGRectMake(x, centerY - BDSButtonFullSize / 2.0,
                                      BDSButtonFullSize, BDSButtonFullSize);
            button.autoresizingMask = (leftSide ? UIViewAutoresizingFlexibleRightMargin : UIViewAutoresizingFlexibleLeftMargin) |
                                      UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleBottomMargin;
            button.backgroundColor = [UIColor colorWithRed:0.05 green:0.48 blue:0.95 alpha:0.90];
            button.layer.cornerRadius = BDSButtonFullSize / 2.0;
            button.layer.borderWidth = 1.0;
            button.layer.borderColor = UIColor.whiteColor.CGColor;
            button.accessibilityLabel = @"设备隐私配置";
            [button setTitle:@"隐" forState:UIControlStateNormal];
            [button setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            button.titleLabel.font = [UIFont boldSystemFontOfSize:17.0];
            [button addTarget:self action:@selector(buttonTapped:) forControlEvents:UIControlEventTouchUpInside];
            UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(buttonPanned:)];
            [button addGestureRecognizer:pan];
            [window addSubview:button];
            objc_setAssociatedObject(window, BDSButtonKey, button, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            [self scheduleButtonCollapse:button];
        }
        [window bringSubviewToFront:button];
    });
}

- (void)buttonTapped:(UIButton *)button {
    self.floatingButtonGeneration++;
    [self openPanel];
    [self scheduleButtonCollapse:button];
}

- (void)scheduleButtonCollapse:(UIButton *)button {
    NSUInteger generation = ++self.floatingButtonGeneration;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(BDSButtonCollapseDelay * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (generation != self.floatingButtonGeneration || !button.superview) return;
        [self collapseButton:button];
    });
}

- (void)expandButton:(UIButton *)button animated:(BOOL)animated {
    UIView *container = button.superview;
    if (!container) return;
    self.floatingButtonGeneration++;
    BOOL leftSide = CGRectGetMidX(button.frame) < CGRectGetWidth(container.bounds) / 2.0;
    CGFloat centerY = CGRectGetMidY(button.frame);
    CGRect target = CGRectMake(leftSide ? 4.0 : CGRectGetWidth(container.bounds) - BDSButtonFullSize - 4.0,
                               centerY - BDSButtonFullSize / 2.0,
                               BDSButtonFullSize, BDSButtonFullSize);
    void (^changes)(void) = ^{
        button.frame = target;
        button.backgroundColor = [UIColor colorWithRed:0.05 green:0.48 blue:0.95 alpha:0.90];
        button.layer.cornerRadius = BDSButtonFullSize / 2.0;
        button.layer.borderWidth = 1.0;
        [button setTitle:@"隐" forState:UIControlStateNormal];
        button.titleLabel.font = [UIFont boldSystemFontOfSize:17.0];
    };
    if (animated) [UIView animateWithDuration:0.18 animations:changes]; else changes();
}

- (void)collapseButton:(UIButton *)button {
    UIView *container = button.superview;
    if (!container) return;
    BOOL leftSide = CGRectGetMidX(button.frame) < CGRectGetWidth(container.bounds) / 2.0;
    CGFloat centerY = CGRectGetMidY(button.frame);
    CGRect target = CGRectMake(leftSide ? 0.0 : CGRectGetWidth(container.bounds) - BDSButtonCollapsedWidth,
                               centerY - BDSButtonFullSize / 2.0,
                               BDSButtonCollapsedWidth, BDSButtonFullSize);
    [UIView animateWithDuration:0.22 animations:^{
        button.frame = target;
        button.backgroundColor = [UIColor colorWithRed:0.05 green:0.48 blue:0.95 alpha:0.35];
        button.layer.cornerRadius = BDSButtonCollapsedWidth / 2.0;
        button.layer.borderWidth = 0.0;
        [button setTitle:(leftSide ? @"›" : @"‹") forState:UIControlStateNormal];
        button.titleLabel.font = [UIFont boldSystemFontOfSize:16.0];
    }];
}

- (void)buttonPanned:(UIPanGestureRecognizer *)gesture {
    UIButton *button = (UIButton *)gesture.view;
    UIView *container = button.superview;
    if (!button || !container) return;
    if (gesture.state == UIGestureRecognizerStateBegan) {
        [self expandButton:button animated:YES];
        [gesture setTranslation:CGPointZero inView:container];
        return;
    }
    CGPoint translation = [gesture translationInView:container];
    CGPoint center = CGPointMake(button.center.x + translation.x, button.center.y + translation.y);
    CGFloat half = CGRectGetWidth(button.bounds) / 2.0;
    center.x = MIN(MAX(center.x, half + 2.0), CGRectGetWidth(container.bounds) - half - 2.0);
    center.y = MIN(MAX(center.y, half + 44.0), CGRectGetHeight(container.bounds) - half - 20.0);
    button.center = center;
    [gesture setTranslation:CGPointZero inView:container];
    if (gesture.state == UIGestureRecognizerStateEnded ||
        gesture.state == UIGestureRecognizerStateCancelled ||
        gesture.state == UIGestureRecognizerStateFailed) {
        BOOL leftSide = button.center.x < CGRectGetWidth(container.bounds) / 2.0;
        CGFloat targetX = leftSide ? 4.0 : CGRectGetWidth(container.bounds) - BDSButtonFullSize - 4.0;
        CGRect target = CGRectMake(targetX, button.center.y - BDSButtonFullSize / 2.0,
                                   BDSButtonFullSize, BDSButtonFullSize);
        button.autoresizingMask = (leftSide ? UIViewAutoresizingFlexibleRightMargin : UIViewAutoresizingFlexibleLeftMargin) |
                                  UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleBottomMargin;
        NSInteger yPermille = (NSInteger)(((button.center.y / CGRectGetHeight(container.bounds)) * 1000.0) + 0.5);
        saveConfigValues(@{@"floatingButtonSide": leftSide ? @"left" : @"right",
                           @"floatingButtonYPermille": @(yPermille)});
        [UIView animateWithDuration:0.20 animations:^{ button.frame = target; } completion:^(BOOL finished) {
            (void)finished;
            [self scheduleButtonCollapse:button];
        }];
    }
}

- (void)presentMessage:(NSString *)message title:(NSString *)title {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *presenter = BDSTopController();
        if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleCancel handler:nil]];
        [presenter presentViewController:alert animated:YES completion:nil];
    });
}

- (void)showRestartNotice:(BOOL)saved {
    [self presentMessage:(saved ? @"配置已写入。请彻底关闭百度极速版后重新打开。" : @"配置写入失败，请检查 App Documents 目录权限。")
                    title:(saved ? @"保存成功" : @"保存失败")];
}

- (void)openPanel {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"百度设备隐私"
                                                                   message:BDSConfigSummary()
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"一键随机整套基础参数" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self randomizeBasicProfile];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"一键随机整套高级参数" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self randomizeAdvancedProfile];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"基础功能设置  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showOptionalSwitches];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"高级功能设置  ›" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showAdvancedSwitches];
        });
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"公开 API 自检" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        [self showSelfTest];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"恢复安全关闭状态" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        (void)action;
        NSDictionary *safe = @{
            @"enabled": @NO,
            @"spoofProcessHardware": @NO,
            @"spoofLocale": @NO,
            @"spoofCarrier": @NO,
            @"spoofScreen": @NO,
            @"spoofStorage": @NO,
            @"spoofBaiduSDK": @NO,
            @"spoofSysctl": @NO,
            @"spoofKeychain": @NO,
            @"spoofUserAgent": @NO,
            @"bypassJailbreakDetect": @NO
        };
        [self showRestartNotice:saveConfigValues(safe)];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editSystemVersion {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"修改系统版本"
                                                                   message:@"版本和 Build 必须保持匹配；保存后重启生效。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"例如 15.7.1";
        field.text = cfgStr(@"systemVersion", @"15.7.1");
        field.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"例如 19H117";
        field.text = cfgStr(@"systemBuild", @"19H117");
        field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *version = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *build = [alert.textFields[1].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].uppercaseString;
        NSRange match = [version rangeOfString:@"^[0-9]+\\.[0-9]+(\\.[0-9]+)?$" options:NSRegularExpressionSearch];
        if (match.location == NSNotFound || !build.length || build.length > 16) {
            [self presentMessage:@"请输入有效版本号和 Build，例如 15.7.1 / 19H117。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"systemVersion": version, @"systemBuild": build})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editDeviceName {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"修改设备名称"
                                                                   message:@"UIDevice.model 固定保持为 iPhone。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"deviceName", @"iPhone");
        field.placeholder = @"1 到 32 个字符";
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *name = [alert.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (!name.length || name.length > 32) {
            [self presentMessage:@"设备名称必须为 1 到 32 个字符。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"deviceName": name})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editIdentifiers {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"修改标识符"
                                                                   message:@"只接受标准 UUID；插件不会自动随机生成。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"idfv", @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
        field.placeholder = @"IDFV";
        field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"idfa", @"FEDCBA98-7654-3210-FEDC-BA9876543210");
        field.placeholder = @"IDFA";
        field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *idfv = alert.textFields[0].text.uppercaseString;
        NSString *idfa = alert.textFields[1].text.uppercaseString;
        if (![[NSUUID alloc] initWithUUIDString:idfv] || ![[NSUUID alloc] initWithUUIDString:idfa]) {
            [self presentMessage:@"IDFV 和 IDFA 都必须是有效 UUID。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"idfv": idfv, @"idfa": idfa})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)randomizeBasicProfile {
    NSDictionary *values = BDSRandomBasicProfileValues();
    BOOL saved = saveConfigValues(values);
    if (!saved) {
        [self presentMessage:@"配置文件写入失败，基础参数没有更换。" title:@"保存失败"];
        return;
    }
    NSString *message = [NSString stringWithFormat:
        @"已随机并保存基础参数；高级参数没有改动。\n"
         "请彻底关闭 App 后重新打开。\n\n"
         "机型：%@\n系统：%@ (%@)\n"
         "内存：%@ MB\n磁盘：%@ GB\n设备名称：%@",
        values[@"deviceProfileName"], values[@"systemVersion"], values[@"systemBuild"],
        values[@"memorySize"], values[@"diskSize"], values[@"deviceName"]];
    [self presentMessage:message title:@"基础参数已更换"];
}

- (void)randomizeAdvancedProfile {
    NSDictionary *values = BDSRandomIdentityValues();
    BOOL saved = saveConfigValues(values);
    if (!saved) {
        [self presentMessage:@"配置文件写入失败，高级参数没有更换。" title:@"保存失败"];
        return;
    }
    NSString *message = [NSString stringWithFormat:
        @"已随机并保存高级参数；基础参数没有改动。\n"
         "请彻底关闭 App 后重新打开。\n\n"
         "IDFA：%@\nIDFV：%@\nCUID：%@\nUTDID：%@\nDeviceID：%@",
        values[@"idfa"], values[@"idfv"], values[@"cuid"],
        values[@"utdid"], values[@"deviceID"]];
    [self presentMessage:message title:@"高级参数已更换"];
}

- (void)showOptionalSwitches {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"基础功能设置"
                                                                   message:@"屏幕始终保持本机真实尺寸，不在这里显示。修改后重启生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"key": @"enabled", @"name": @"基础功能总开关"},
        @{@"key": @"spoofAdvertisingIdentifiers", @"name": @"广告标识符"},
        @{@"key": @"spoofProcessHardware", @"name": @"主机名与内存"},
        @{@"key": @"spoofLocale", @"name": @"语言地区"},
        @{@"key": @"spoofCarrier", @"name": @"运营商"},
        @{@"key": @"spoofStorage", @"name": @"磁盘容量"}
    ];
    for (NSDictionary *item in items) {
        NSString *key = item[@"key"];
        NSString *title = [NSString stringWithFormat:@"%@：%@", item[@"name"], BDSOnOff(cfgBool(key, NO))];
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            [self showRestartNotice:saveConfigValues(@{key: @(!cfgBool(key, NO))})];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self openPanel]; });
    }]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showOptionalEditors {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"编辑基础参数"
                                                                   message:@"这里只修改本机公开 API 的测试值；对应开关开启并重启后生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"name": @"主机名与内存", @"selector": NSStringFromSelector(@selector(editProcessHardware))},
        @{@"name": @"语言地区与运营商", @"selector": NSStringFromSelector(@selector(editLocaleCarrier))},
        @{@"name": @"屏幕与磁盘", @"selector": NSStringFromSelector(@selector(editScreenStorage))}
    ];
    for (NSDictionary *item in items) {
        [sheet addAction:[UIAlertAction actionWithTitle:item[@"name"] style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            SEL selector = NSSelectorFromString(item[@"selector"]);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                if ([self respondsToSelector:selector]) {
                    ((void (*)(id, SEL))objc_msgSend)(self, selector);
                }
            });
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showAdvancedSwitches {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"高级功能设置"
                                                                   message:@"高级功能默认全部开启，修改后重启生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"key": @"spoofBaiduSDK", @"name": @"百度 SDK 标识（CUID/UTDID/DeviceID）"},
        @{@"key": @"spoofSysctl", @"name": @"sysctlbyname（hw.machine 等）"},
        @{@"key": @"spoofKeychain", @"name": @"Keychain 拦截"},
        @{@"key": @"spoofUserAgent", @"name": @"User-Agent 替换"},
        @{@"key": @"bypassJailbreakDetect", @"name": @"越狱检测绕过（含镜像名/C函数/NSBundle）"}
    ];
    for (NSDictionary *item in items) {
        NSString *key = item[@"key"];
        NSString *title = [NSString stringWithFormat:@"%@：%@", item[@"name"], BDSOnOff(cfgBool(key, NO))];
        [sheet addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            [self showRestartNotice:saveConfigValues(@{key: @(!cfgBool(key, NO))})];
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"编辑高级参数  ›"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self showAdvancedEditors];
        });
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"返回" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        (void)action;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self openPanel]; });
    }]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)showAdvancedEditors {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"编辑高级参数"
                                                                   message:@"修改百度 SDK 标识和硬件底层参数；对应开关开启并重启后生效。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSDictionary *> *items = @[
        @{@"name": @"百度 CUID / UTDID / DeviceID", @"selector": NSStringFromSelector(@selector(editBaiduIdentifiers))},
        @{@"name": @"sysctl 硬件参数", @"selector": NSStringFromSelector(@selector(editSysctlParams))},
        @{@"name": @"自定义 User-Agent", @"selector": NSStringFromSelector(@selector(editUserAgent))}
    ];
    for (NSDictionary *item in items) {
        [sheet addAction:[UIAlertAction actionWithTitle:item[@"name"] style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            SEL selector = NSSelectorFromString(item[@"selector"]);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                if ([self respondsToSelector:selector]) {
                    ((void (*)(id, SEL))objc_msgSend)(self, selector);
                }
            });
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (sheet.popoverPresentationController) {
        sheet.popoverPresentationController.sourceView = presenter.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(presenter.view.bounds), CGRectGetMidY(presenter.view.bounds), 1, 1);
    }
    [presenter presentViewController:sheet animated:YES completion:nil];
}

- (void)editBaiduIdentifiers {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"百度 SDK 标识"
                                                                   message:@"CUID/UTDID 为 32 位十六进制；DeviceID 为 UUID 格式。每台手机必须不同。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    NSArray<NSDictionary *> *fields = @[
        @{@"key": @"cuid", @"default": @"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6", @"placeholder": @"CUID（32位十六进制）"},
        @{@"key": @"utdid", @"default": @"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", @"placeholder": @"UTDID（32位十六进制）"},
        @{@"key": @"deviceID", @"default": @"A1B2C3D4-E5F6-A7B8-C9D0-E1F2A3B4C5D6", @"placeholder": @"DeviceID（UUID）"}
    ];
    for (NSDictionary *info in fields) {
        [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.text = cfgStr(info[@"key"], info[@"default"]);
            field.placeholder = info[@"placeholder"];
            field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        }];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *cuid = alert.textFields[0].text.uppercaseString;
        NSString *utdid = alert.textFields[1].text.lowercaseString;
        NSString *deviceID = alert.textFields[2].text.uppercaseString;
        NSCharacterSet *hexUpper = [NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEF"];
        NSCharacterSet *hexLower = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
        BOOL cuidValid = cuid.length == 32 && [cuid rangeOfCharacterFromSet:hexUpper.invertedSet].location == NSNotFound;
        BOOL utdidValid = utdid.length == 32 && [utdid rangeOfCharacterFromSet:hexLower.invertedSet].location == NSNotFound;
        BOOL deviceIDValid = [[NSUUID alloc] initWithUUIDString:deviceID] != nil;
        if (!cuidValid || !utdidValid || !deviceIDValid) {
            [self presentMessage:@"CUID/UTDID 必须是 32 位十六进制，DeviceID 必须是有效 UUID。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"cuid": cuid, @"utdid": utdid, @"deviceID": deviceID})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editSysctlParams {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"sysctl 硬件参数"
                                                                   message:@"这些值必须与设备型号匹配，否则容易被识别。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    NSArray<NSDictionary *> *fields = @[
        @{@"key": @"hwMachine", @"default": @"iPhone10,1", @"placeholder": @"hw.machine，例如 iPhone10,1"},
        @{@"key": @"hwModel", @"default": @"D20AP", @"placeholder": @"hw.model，例如 D20AP"},
        @{@"key": @"kernOSVersion", @"default": @"19H117", @"placeholder": @"kern.osversion，例如 19H117"}
    ];
    for (NSDictionary *info in fields) {
        [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.text = cfgStr(info[@"key"], info[@"default"]);
            field.placeholder = info[@"placeholder"];
            field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        }];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *machine = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *model = [alert.textFields[1].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSString *osver = [alert.textFields[2].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].uppercaseString;
        if (!machine.length || machine.length > 32 || !model.length || model.length > 32 || !osver.length || osver.length > 16) {
            [self presentMessage:@"请检查各参数长度（machine/model 不超过 32，osversion 不超过 16）。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"hwMachine": machine, @"hwModel": model, @"kernOSVersion": osver})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editUserAgent {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"自定义 User-Agent"
                                                                   message:@"留空则根据系统版本自动生成。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"userAgent", @"");
        field.placeholder = @"留空自动生成";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *ua = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        [self showRestartNotice:saveConfigValues(@{@"userAgent": ua ?: @""})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editProcessHardware {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"主机名与内存"
                                                                   message:@"内存单位为 MB，建议只用于兼容性测试。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = cfgStr(@"kernHostname", @"iPhone");
        field.placeholder = @"主机名（1 到 64 个字符）";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = [NSString stringWithFormat:@"%ld", (long)cfgInt(@"memorySize", 2048)];
        field.placeholder = @"内存 MB（512 到 16384）";
        field.keyboardType = UIKeyboardTypeNumberPad;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSString *host = [alert.textFields[0].text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSInteger memory = alert.textFields[1].text.integerValue;
        if (!host.length || host.length > 64 || memory < 512 || memory > 16384) {
            [self presentMessage:@"主机名须为 1 到 64 个字符，内存须为 512 到 16384 MB。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{@"kernHostname": host, @"memorySize": @(memory)})];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editLocaleCarrier {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"语言地区与运营商"
                                                                   message:@"依次填写 Locale、运营商、MCC、MNC、国家码。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    NSArray<NSDictionary *> *fields = @[
        @{@"key": @"localeIdentifier", @"default": @"zh_CN", @"placeholder": @"Locale，例如 zh_CN"},
        @{@"key": @"carrierName", @"default": @"中国移动", @"placeholder": @"运营商名称"},
        @{@"key": @"mcc", @"default": @"460", @"placeholder": @"MCC，例如 460"},
        @{@"key": @"mnc", @"default": @"00", @"placeholder": @"MNC，例如 00"},
        @{@"key": @"isoCountryCode", @"default": @"cn", @"placeholder": @"国家码，例如 cn"}
    ];
    for (NSDictionary *info in fields) {
        [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.text = cfgStr(info[@"key"], info[@"default"]);
            field.placeholder = info[@"placeholder"];
            field.autocapitalizationType = UITextAutocapitalizationTypeNone;
            if ([info[@"key"] isEqualToString:@"mcc"] || [info[@"key"] isEqualToString:@"mnc"]) {
                field.keyboardType = UIKeyboardTypeNumberPad;
            }
        }];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSMutableArray<NSString *> *values = [NSMutableArray array];
        for (UITextField *field in alert.textFields) {
            [values addObject:[field.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] ?: @""];
        }
        NSString *locale = values[0];
        NSString *carrier = values[1];
        NSString *mcc = values[2];
        NSString *mnc = values[3];
        NSString *country = values[4].lowercaseString;
        NSCharacterSet *nonDigits = NSCharacterSet.decimalDigitCharacterSet.invertedSet;
        BOOL valid = locale.length >= 2 && locale.length <= 16 && carrier.length >= 1 && carrier.length <= 32 &&
                     mcc.length == 3 && [mcc rangeOfCharacterFromSet:nonDigits].location == NSNotFound &&
                     mnc.length >= 2 && mnc.length <= 3 && [mnc rangeOfCharacterFromSet:nonDigits].location == NSNotFound &&
                     country.length == 2 && [country rangeOfCharacterFromSet:NSCharacterSet.letterCharacterSet.invertedSet].location == NSNotFound;
        if (!valid) {
            [self presentMessage:@"请检查 Locale、运营商名称、3 位 MCC、2 到 3 位 MNC 和 2 位国家码。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{
            @"localeIdentifier": locale, @"carrierName": carrier,
            @"mcc": mcc, @"mnc": mnc, @"isoCountryCode": country
        })];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)editScreenStorage {
    UIViewController *presenter = BDSTopController();
    if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"屏幕与磁盘"
                                                                   message:@"屏幕参数会影响布局，建议先记录原值。磁盘单位为 GB。"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    NSArray<NSDictionary *> *fields = @[
        @{@"key": @"screenWidth", @"default": @375, @"placeholder": @"逻辑宽度"},
        @{@"key": @"screenHeight", @"default": @667, @"placeholder": @"逻辑高度"},
        @{@"key": @"screenScale", @"default": @2, @"placeholder": @"缩放倍数"},
        @{@"key": @"diskSize", @"default": @64, @"placeholder": @"磁盘 GB"}
    ];
    for (NSDictionary *info in fields) {
        [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
            field.text = [NSString stringWithFormat:@"%ld", (long)cfgInt(info[@"key"], [info[@"default"] integerValue])];
            field.placeholder = info[@"placeholder"];
            field.keyboardType = UIKeyboardTypeNumberPad;
        }];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        (void)action;
        NSInteger width = alert.textFields[0].text.integerValue;
        NSInteger height = alert.textFields[1].text.integerValue;
        NSInteger scale = alert.textFields[2].text.integerValue;
        NSInteger disk = alert.textFields[3].text.integerValue;
        if (width < 200 || width > 1500 || height < 200 || height > 3000 ||
            scale < 1 || scale > 4 || disk < 8 || disk > 2048) {
            [self presentMessage:@"宽度须为 200–1500，高度 200–3000，缩放 1–4，磁盘 8–2048 GB。" title:@"格式错误"];
            return;
        }
        [self showRestartNotice:saveConfigValues(@{
            @"screenWidth": @(width), @"screenHeight": @(height),
            @"nativeScreenWidth": @(width * scale),
            @"nativeScreenHeight": @(height * scale),
            @"screenScale": @(scale), @"diskSize": @(disk)
        })];
    }]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

- (void)showSelfTest {
    UIDevice *device = UIDevice.currentDevice;
    NSProcessInfo *process = NSProcessInfo.processInfo;
    UIScreen *screen = UIScreen.mainScreen;

    typedef NSString *(*StringGetterIMP)(id, SEL);
    typedef NSUUID *(*UUIDGetterIMP)(id, SEL);
    typedef unsigned long long (*MemoryGetterIMP)(id, SEL);
    typedef CGRect (*BoundsGetterIMP)(id, SEL);
    typedef CGFloat (*ScaleGetterIMP)(id, SEL);

    NSString *currentVersion = device.systemVersion ?: @"nil";
    NSString *realVersion = orig_systemVersion
        ? ((StringGetterIMP)orig_systemVersion)(device, @selector(systemVersion)) : currentVersion;
    NSString *currentName = device.name ?: @"nil";
    NSString *realName = orig_name ? ((StringGetterIMP)orig_name)(device, @selector(name)) : currentName;
    NSString *currentIDFV = device.identifierForVendor.UUIDString ?: @"nil";
    NSUUID *realUUID = orig_identifierForVendor
        ? ((UUIDGetterIMP)orig_identifierForVendor)(device, @selector(identifierForVendor)) : device.identifierForVendor;
    NSString *realIDFV = realUUID.UUIDString ?: @"nil";
    NSString *currentProcess = process.operatingSystemVersionString ?: @"nil";
    NSString *realProcess = orig_operatingSystemVersionString
        ? ((StringGetterIMP)orig_operatingSystemVersionString)(process, @selector(operatingSystemVersionString)) : currentProcess;
    unsigned long long currentMemory = process.physicalMemory / (1024ULL * 1024ULL);
    unsigned long long realMemory = orig_physicalMemory
        ? ((MemoryGetterIMP)orig_physicalMemory)(process, @selector(physicalMemory)) / (1024ULL * 1024ULL) : currentMemory;
    CGRect currentBounds = screen.bounds;
    CGRect realBounds = orig_bounds ? ((BoundsGetterIMP)orig_bounds)(screen, @selector(bounds)) : currentBounds;
    CGFloat currentScale = screen.scale;
    CGFloat realScale = orig_scale ? ((ScaleGetterIMP)orig_scale)(screen, @selector(scale)) : currentScale;

    NSString *message = [NSString stringWithFormat:
        @"状态：%@\n\n"
         @"iOS\n原始 %@\n配置 %@ (%@)\n当前 %@\n\n"
         @"设备名称\n原始 %@\n配置 %@\n当前 %@\n\n"
         @"IDFV\n原始 %@\n配置 %@\n当前 %@\n\n"
         @"NSProcessInfo\n原始 %@\n当前 %@\n\n"
         @"内存(MB)\n原始 %llu\n配置 %ld\n当前 %llu\n\n"
         @"屏幕(points / scale)\n原始 %.0fx%.0f / %.2f\n配置 %ldx%ld / %ld\n当前 %.0fx%.0f / %.2f",
        cfgBool(@"enabled", NO) ? @"基础功能已开启" : @"基础功能已关闭",
        realVersion, cfgStr(@"systemVersion", @"15.7.1"), cfgStr(@"systemBuild", @"19H117"), currentVersion,
        realName, cfgStr(@"deviceName", @"iPhone"), currentName,
        realIDFV, cfgStr(@"idfv", @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890"), currentIDFV,
        realProcess, currentProcess,
        realMemory, (long)cfgInt(@"memorySize", 2048), currentMemory,
        CGRectGetWidth(realBounds), CGRectGetHeight(realBounds), realScale,
        (long)cfgInt(@"screenWidth", 375), (long)cfgInt(@"screenHeight", 667), (long)cfgInt(@"screenScale", 2),
        CGRectGetWidth(currentBounds), CGRectGetHeight(currentBounds), currentScale];

    NSMutableString *advanced = [NSMutableString stringWithString:@"\n\n--- 高级功能 ---"];

    [advanced appendFormat:@"\n百度SDK：%@", cfgBool(@"spoofBaiduSDK", NO) ? @"开" : @"关"];
    if (cfgBool(@"spoofBaiduSDK", NO)) {
        NSArray *classNames = @[@"CuidSDK", @"CuidSDK18BBADevAccountPatch", @"UTDIDModule", @"MobStat", @"DeviceIdentifierFetcher"];
        for (NSString *cn in classNames) {
            Class c = objc_getClass(cn.UTF8String);
            if (c) {
                NSUInteger hooked = 0;
                [g_baiduLock lock];
                for (NSString *key in g_baiduHookedKeys) {
                    if ([key hasPrefix:[cn stringByAppendingString:@"."]]) hooked++;
                }
                [g_baiduLock unlock];
                [advanced appendFormat:@"\n  %@：已hook %lu个方法", cn, (unsigned long)hooked];
            } else {
                [advanced appendFormat:@"\n  %@：类不存在", cn];
            }
        }
    }

    [advanced appendFormat:@"\nsysctlbyname：%@", cfgBool(@"spoofSysctl", NO) ? @"开" : @"关"];
    if (cfgBool(@"spoofSysctl", NO)) {
        char buf[64] = {0};
        size_t len = sizeof(buf);
        if (sysctlbyname("hw.machine", buf, &len, NULL, 0) == 0) {
            [advanced appendFormat:@"\n  hw.machine：%s", buf];
        }
        len = sizeof(buf); memset(buf, 0, sizeof(buf));
        if (sysctlbyname("kern.osversion", buf, &len, NULL, 0) == 0) {
            [advanced appendFormat:@"\n  kern.osversion：%s", buf];
        }
    }

    [advanced appendFormat:@"\nKeychain 拦截：%@", cfgBool(@"spoofKeychain", NO) ? @"开" : @"关"];

    [advanced appendFormat:@"\nUser-Agent：%@", cfgBool(@"spoofUserAgent", NO) ? @"开" : @"关"];
    if (cfgBool(@"spoofUserAgent", NO)) {
        WKWebView *wv = [[WKWebView alloc] init];
        NSString *ua = [wv performSelector:@selector(customUserAgent)];
        [advanced appendFormat:@"\n  WKWebView getter：%@", ua ?: @"nil（App未设置）"];
    }

    [advanced appendFormat:@"\n越狱绕过：%@", cfgBool(@"bypassJailbreakDetect", NO) ? @"开" : @"关"];
    if (cfgBool(@"bypassJailbreakDetect", NO)) {
        // B: 镜像名过滤自检
        if (orig_dyld_get_image_name) {
            uint32_t count = _dyld_image_count();
            int suspicious = 0;
            for (uint32_t i = 0; i < count; i++) {
                const char *orig = orig_dyld_get_image_name(i);
                if (orig && bds_c_should_hide_image(orig)) suspicious++;
            }
            [advanced appendFormat:@"\n  镜像名过滤：隐藏 %u 个可疑镜像", suspicious];
        }
        [advanced appendFormat:@"\n  C函数检测：stat/access/fopen 已拦截"];
        NSArray *frameworks = [NSBundle allFrameworks];
        [advanced appendFormat:@"\n  NSBundle过滤：%lu 个 framework", (unsigned long)frameworks.count];
    }

    message = [message stringByAppendingString:advanced];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *presenter = BDSTopController();
        if (!presenter || [presenter isKindOfClass:UIAlertController.class]) return;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"公开 API 对照自检"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"复制结果" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            (void)action;
            UIPasteboard.generalPasteboard.string = message;
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleCancel handler:nil]];
        [presenter presentViewController:alert animated:YES completion:nil];
    });
}

@end

static void BDSInstallUI(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil
                                                           queue:NSOperationQueue.mainQueue
                                                      usingBlock:^(NSNotification *note) {
            (void)note;
            [[BDSUIController shared] attachButton];
        }];
        for (NSNumber *delay in @[@0.8, @2.0, @5.0]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [[BDSUIController shared] attachButton];
            });
        }
    });
}

#pragma mark - 构造函数

__attribute__((constructor))
static void bds_initialize() {
    @autoreleasepool {
        // 先加载配置
        loadConfig();

        NSString *bundleID = [NSBundle mainBundle].bundleIdentifier;
        if (![bundleID isEqualToString:@"com.baidu.BaiduMobileInfo"]) return;

        // 配置入口始终安装
        BDSInstallUI();

        if (!cfgBool(@"enabled", NO)) return;

        // 安装 C 函数 hook（fishhook GOT 替换）
        // fishhook 保存的 orig 指针直接指向 libSystem 真实地址，
        // 调用 orig 不经过 GOT，结构上不可能递归。
        // 必须在 enabled 检查之后安装，避免禁用状态下修改 GOT。
        installCHooks();

        // 同步 C 全局开关
        BDS_ATOMIC_SET(g_enabledC, 1);
        BDS_ATOMIC_SET(g_spoofSysctlC, cfgBool(@"spoofSysctl", NO) ? 1 : 0);
        BDS_ATOMIC_SET(g_bypassJailbreakC, cfgBool(@"bypassJailbreakDetect", NO) ? 1 : 0);

        // UIDevice
        Class cls = objc_getClass("UIDevice");
        hookInst(cls, @selector(systemVersion), (IMP)new_systemVersion, &orig_systemVersion);
        hookInst(cls, @selector(model), (IMP)new_model, &orig_model);
        hookInst(cls, @selector(localizedModel), (IMP)new_localizedModel, &orig_localizedModel);
        hookInst(cls, @selector(name), (IMP)new_name, &orig_name);
        hookInst(cls, @selector(systemName), (IMP)new_systemName, &orig_systemName);
        hookInst(cls, @selector(identifierForVendor), (IMP)new_identifierForVendor, &orig_identifierForVendor);

        if (cfgBool(@"spoofAdvertisingIdentifiers", YES)) {
            cls = objc_getClass("ASIdentifierManager");
            hookInst(cls, @selector(advertisingIdentifier), (IMP)new_advertisingIdentifier, &orig_advertisingIdentifier);
            hookInst(cls, @selector(isAdvertisingTrackingEnabled), (IMP)new_isAdvertisingTrackingEnabled, &orig_isAdvertisingTrackingEnabled);

            cls = objc_getClass("ATTrackingManager");
            if (cls) {
                hookClass(cls, @selector(trackingAuthorizationStatus), (IMP)new_trackingAuthorizationStatus, &orig_trackingAuthorizationStatus);
            }
        }

        // NSProcessInfo
        cls = objc_getClass("NSProcessInfo");
        hookInst(cls, @selector(operatingSystemVersion), (IMP)new_operatingSystemVersion, &orig_operatingSystemVersion);
        hookInst(cls, @selector(operatingSystemVersionString), (IMP)new_operatingSystemVersionString, &orig_operatingSystemVersionString);
        if (cfgBool(@"spoofProcessHardware", NO)) {
            hookInst(cls, @selector(hostName), (IMP)new_hostName, &orig_hostName);
            hookInst(cls, @selector(physicalMemory), (IMP)new_physicalMemory, &orig_physicalMemory);
        }

        if (cfgBool(@"spoofLocale", NO)) {
            cls = objc_getClass("NSLocale");
            hookInst(cls, @selector(localeIdentifier), (IMP)new_localeIdentifier, &orig_localeIdentifier);
        }

        if (cfgBool(@"spoofCarrier", NO)) {
            cls = objc_getClass("CTTelephonyNetworkInfo");
            hookInst(cls, @selector(subscriberCellularProvider), (IMP)new_subscriberCellularProvider, &orig_subscriberCellularProvider);
            hookInst(cls, @selector(serviceSubscriberCellularProviders), (IMP)new_serviceSubscriberCellularProviders, &orig_serviceSubscriberCellularProviders);

            cls = objc_getClass("CTCarrier");
            hookInst(cls, @selector(carrierName), (IMP)new_carrierName, &orig_carrierName);
            hookInst(cls, @selector(mobileCountryCode), (IMP)new_mobileCountryCode, &orig_mobileCountryCode);
            hookInst(cls, @selector(mobileNetworkCode), (IMP)new_mobileNetworkCode, &orig_mobileNetworkCode);
            hookInst(cls, @selector(isoCountryCode), (IMP)new_isoCountryCode, &orig_isoCountryCode);
            hookInst(cls, @selector(allowsVOIP), (IMP)new_allowsVOIP, &orig_allowsVOIP);
        }

        if (cfgBool(@"spoofScreen", NO)) {
            cls = objc_getClass("UIScreen");
            hookInst(cls, @selector(bounds), (IMP)new_bounds, &orig_bounds);
            hookInst(cls, @selector(nativeBounds), (IMP)new_nativeBounds, &orig_nativeBounds);
            hookInst(cls, @selector(scale), (IMP)new_scale, &orig_scale);
        }

        if (cfgBool(@"spoofStorage", NO)) {
            cls = objc_getClass("NSFileManager");
            hookInst(cls, @selector(attributesOfFileSystemForPath:error:), (IMP)new_attributesOfFileSystemForPath, &orig_attributesOfFileSystemForPath);
        }

        // 百度 SDK 设备标识 hook
        if (cfgBool(@"spoofBaiduSDK", NO)) {
            installBaiduSDKHooks();
        }

        // User-Agent hook
        if (cfgBool(@"spoofUserAgent", NO)) {
            cls = objc_getClass("WKWebView");
            if (cls) {
                hookInst(cls, @selector(customUserAgent), (IMP)new_wk_customUserAgent, &orig_wk_customUserAgent);
            }
            cls = objc_getClass("NSMutableURLRequest");
            if (cls) {
                hookInst(cls, @selector(setValue:forHTTPHeaderField:), (IMP)new_nsmurl_setValue, &orig_nsmurl_setValue);
                hookInst(cls, @selector(addValue:forHTTPHeaderField:), (IMP)new_nsmurl_addValue, &orig_nsmurl_addValue);
            }
        }

        // 越狱检测绕过（ObjC 层 + D: NSBundle 过滤）
        if (cfgBool(@"bypassJailbreakDetect", NO)) {
            cls = objc_getClass("NSFileManager");
            hookInst(cls, @selector(fileExistsAtPath:), (IMP)new_fileExistsAtPath, &orig_fileExistsAtPath);
            hookInst(cls, @selector(fileExistsAtPath:isDirectory:), (IMP)new_fileExistsAtPathIsDir, &orig_fileExistsAtPathIsDir);

            cls = objc_getClass("UIApplication");
            hookInst(cls, @selector(canOpenURL:), (IMP)new_canOpenURL, &orig_canOpenURL);

            // D: NSBundle 遍历过滤
            cls = objc_getClass("NSBundle");
            hookClass(cls, @selector(allFrameworks), (IMP)new_allFrameworks, &orig_allFrameworks);
            hookClass(cls, @selector(allBundles), (IMP)new_allBundles, &orig_allBundles);
            Method m = class_getClassMethod(cls, @selector(loadedBundles));
            if (m) {
                hookClass(cls, @selector(loadedBundles), (IMP)new_loadedBundles, &orig_loadedBundles);
            }
        }
    }
}
