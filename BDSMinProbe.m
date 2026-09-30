// BDSMinProbe 4.0 —— 一次性到位版本
//
// ============================================================================
// 本版把此前所有已确认的缺陷一次全部修掉：
//
// 【崩溃类】
//  1. fishhook 只扫 __DATA / __DATA_CONST。
//     __AUTH / __AUTH_CONST 的 GOT 指针在 arm64e 上带 PAC 签名，
//     写入未签名指针会在调用时认证失败崩溃。（复用主插件验证过的实现）
//  2. 不注册 _dyld_register_func_for_add_image 回调。
//     该回调在 dlopen 执行中、dyld 持锁时触发，此时不能做系统调用、
//     新镜像 dyld 结构也可能未就绪。要 hook 的 libsystem 函数启动时
//     全部已加载，构造阶段扫一遍即可。
//  3. 符号名偏移做纯算术边界校验（strsize + __LINKEDIT 区间），零系统调用。
//  4. C hook 全部判空原函数指针。
//  5. 对象返回值直接发消息读（返回的 id 已经过 objc_msgSend 认证，是安全的）。
//     绝不对可能失效的指针发消息（那会在 objc_retain 崩）。
//  6. bfp_rec 内部不调用任何被 hook 的函数；递归锁 + 递归守卫。
//
// 【UI 类】
//  7. 悬浮按钮用「只有按钮大小」的独立 UIWindow —— 这是关键。
//     全屏窗口无论怎么写 hitTest 都会吞掉整屏触摸（3.1 实测 App 点不动）。
//     窗口只覆盖按钮那一小块，窗口外的触摸根本不会命中它，天然穿透。
//  8. 拖动 = 移动窗口本身（标准做法）。
//  9. 窗口层级极高，压过百度自己的开屏/广告窗口；2 秒心跳维持。
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Photos/Photos.h>
#import <PhotosUI/PhotosUI.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <dlfcn.h>
#import <dirent.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/time.h>
#import <sys/types.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <net/if.h>
#import <net/if_dl.h>
#import <string.h>
#import <errno.h>
#import <stdlib.h>
#import <time.h>

static NSString * const BFPVersion = @"5.3";

#pragma mark - 记录器

static NSMutableDictionary<NSString *, NSMutableDictionary *> *g_rec;
static NSRecursiveLock *g_lock;
static CFAbsoluteTime g_startTime;
static NSUInteger g_totalRecords;
static int g_depth;
static const NSUInteger kMaxPerKey = 200;

static void bfp_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_rec = [NSMutableDictionary dictionary];
        g_lock = [[NSRecursiveLock alloc] init];
        g_startTime = CFAbsoluteTimeGetCurrent();
    });
}

// 【硬性约束】本函数内不得调用任何被本探针 hook 的函数，
// 否则会递归回自己（1.3 版的自死锁就是这么来的）。
static void bfp_rec(NSString *key, NSString *value) {
    if (!key) return;
    bfp_init();
    if (g_depth > 0) return;
    g_depth++;
    [g_lock lock];
    NSMutableDictionary *e = g_rec[key];
    if (!e) {
        e = [NSMutableDictionary dictionary];
        e[@"n"] = @0;
        e[@"samples"] = [NSMutableArray array];
        g_rec[key] = e;
    }
    e[@"n"] = @([e[@"n"] unsignedIntegerValue] + 1);
    NSArray *s = e[@"samples"];
    if (s.count < kMaxPerKey && value.length) {
        NSString *v = value.length > 200 ? [value substringToIndex:200] : value;
        if (![s containsObject:v]) [(NSMutableArray *)s addObject:v];
    }
    g_totalRecords++;
    [g_lock unlock];
    g_depth--;
}

static void bfp_rec_int(NSString *key, long long v) {
    bfp_rec(key, [NSString stringWithFormat:@"%lld", v]);
}

static void bfp_rec_str(NSString *key, const char *c) {
    if (!c) { bfp_rec(key, @"(null)"); return; }
    bfp_rec(key, [NSString stringWithUTF8String:c]);
}

#pragma mark - 启动进度标记

static void bfp_marker(const char *stage) {
    @autoreleasepool {
        NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                            NSUserDomainMask, YES);
        if (dirs.count == 0) return;
        NSString *dir = [NSString stringWithFormat:@"%@/probe_marker", dirs.firstObject];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                 withIntermediateDirectories:YES attributes:nil error:NULL];
        NSString *f = [NSString stringWithFormat:@"%@/%s.txt", dir, stage];
        [[NSString stringWithFormat:@"stage=%s", stage]
            writeToFile:f atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
}


#pragma mark - hook 装载诊断（回答"没装上"还是"没被调用"）

// 之前的探针只有 rebind 失败计数，分不清两种情况：
//   A. fishhook 根本没装上这个符号 -> 我的替换函数从未被调用
//   B. 装上了，但 App 确实没调用
// 这两种要采取的行动完全不同，所以必须记录每个符号的真实状态。

#define BFP_MAX_HOOKS 24

typedef struct {
    const char *name;
    int hooked;        // fishhook 是否改写了 GOT
    int origFilled;    // 原函数指针是否被填上
    int called;        // 替换函数是否被调用过
} bfp_hook_stat;

static bfp_hook_stat g_hookStats[BFP_MAX_HOOKS];
static int g_hookStatCount = 0;

static bfp_hook_stat *bfp_stat_for(const char *name) {
    for (int i = 0; i < g_hookStatCount; i++) {
        if (strcmp(g_hookStats[i].name, name) == 0) return &g_hookStats[i];
    }
    if (g_hookStatCount >= BFP_MAX_HOOKS) return NULL;
    bfp_hook_stat *s = &g_hookStats[g_hookStatCount++];
    s->name = name;
    s->hooked = 0;
    s->origFilled = 0;
    s->called = 0;
    return s;
}

static void bfp_mark_called(const char *name) {
    bfp_hook_stat *s = bfp_stat_for(name);
    if (s) s->called = 1;
}

// 预登记所有想 hook 的符号（即使最后没装上也要出现在报告里）。
// 上一版只登记“确实被改写成功”的符号，导致 sysctl/uname 直接消失，
// 我误读成“App 没调用”。这个坑必须堵上。
static void bfp_preregister(const char *name) {
    (void)bfp_stat_for(name);
}

#pragma mark - fishhook（复用主插件验证过的实现）

#ifdef __LP64__
typedef struct mach_header_64 bfp_mach_header_t;
typedef struct segment_command_64 bfp_segment_command_t;
typedef struct section_64 bfp_section_t;
typedef struct nlist_64 bfp_nlist_t;
#define BFP_LC_SEGMENT LC_SEGMENT_64
#else
typedef struct mach_header bfp_mach_header_t;
typedef struct segment_command bfp_segment_command_t;
typedef struct section bfp_section_t;
typedef struct nlist bfp_nlist_t;
#define BFP_LC_SEGMENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif

struct bfp_rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct bfp_rebindings_entry {
    struct bfp_rebinding *rebindings;
    size_t rebindings_nel;
    struct bfp_rebindings_entry *next;
};

static int g_bfpRebindFailures = 0;

static vm_address_t bfp_page_mask(void) {
    vm_size_t page = vm_page_size;
    if (page == 0) {
        long sp = sysconf(_SC_PAGESIZE);
        page = sp > 0 ? (vm_size_t)sp : 16384;
    }
    return (vm_address_t)(page - 1);
}

static void bfp_perform_rebinding_with_section(struct bfp_rebindings_entry *rebindings,
                                               bfp_section_t *section,
                                               intptr_t slide,
                                               bfp_nlist_t *symtab,
                                               uint32_t nsyms,
                                               char *strtab,
                                               uint32_t strsize,
                                               uint32_t *indirect_symtab,
                                               uint32_t nindirectsyms,
                                               uintptr_t le_off,
                                               uintptr_t le_size) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    uint32_t pointer_count = (uint32_t)(section->size / sizeof(void *));

    if (section->reserved1 >= nindirectsyms ||
        pointer_count > nindirectsyms - section->reserved1) {
        return;
    }

    // __LINKEDIT 运行时区间（纯算术，无系统调用）。
    // 本函数会在 dlopen 路径上被调用，绝不能做系统调用。
    uintptr_t le_start = (uintptr_t)slide + le_off;
    uintptr_t le_end = le_start + le_size;

    int protected_region = 0;
    for (uint32_t i = 0; i < pointer_count; i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        if (symtab_index >= nsyms) continue;

        uint32_t off = symtab[symtab_index].n_un.n_strx;
        if (off >= strsize || strsize - off < 2) continue;
        char *symbol_name = strtab + off;

        uintptr_t sn = (uintptr_t)symbol_name;
        if (sn < le_start || sn + 2 > le_end) continue;
        if (!symbol_name[0] || !symbol_name[1]) continue;

        for (struct bfp_rebindings_entry *cur = rebindings; cur; cur = cur->next) {
            for (size_t j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    if (!protected_region) {
                        vm_address_t pm = bfp_page_mask();
                        vm_address_t ps = (vm_address_t)indirect_symbol_bindings & ~pm;
                        vm_address_t pe = ((vm_address_t)indirect_symbol_bindings
                                           + (vm_size_t)section->size + pm) & ~pm;
                        kern_return_t vr = vm_protect(mach_task_self(), ps,
                                                      (vm_size_t)(pe - ps), NO,
                                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        if (vr != KERN_SUCCESS) { g_bfpRebindFailures++; return; }
                        protected_region = 1;
                    }
                    if (cur->rebindings[j].replaced != NULL &&
                        *(cur->rebindings[j].replaced) == NULL &&
                        indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    {
                        bfp_hook_stat *st = bfp_stat_for(cur->rebindings[j].name);
                        if (st) {
                            st->hooked = 1;
                            if (cur->rebindings[j].replaced && *(cur->rebindings[j].replaced)) {
                                st->origFilled = 1;
                            }
                        }
                    }
                    goto next_symbol;
                }
            }
        }
    next_symbol:;
    }
}

static void bfp_rebind_symbols_for_image(struct bfp_rebindings_entry *rebindings,
                                         const struct mach_header *header,
                                         intptr_t slide) {
    if (!header) return;
    if (header->magic != MH_MAGIC_64 && header->magic != MH_MAGIC) return;

    bfp_segment_command_t *cur_seg_cmd;
    bfp_segment_command_t *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(bfp_mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (bfp_segment_command_t *)cur;
        if (cur_seg_cmd->cmd == BFP_LC_SEGMENT) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) linkedit_segment = cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }
    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment) return;
    if (dysymtab_cmd->nindirectsyms == 0) { g_bfpRebindFailures++; return; }
    if (symtab_cmd->nsyms == 0 || symtab_cmd->strsize == 0) return;

    uintptr_t linkedit_base =
        (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    bfp_nlist_t *symtab = (bfp_nlist_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(bfp_mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (bfp_segment_command_t *)cur;
        if (cur_seg_cmd->cmd != BFP_LC_SEGMENT) continue;
        // 只扫 __DATA / __DATA_CONST。arm64e 上 __AUTH/__AUTH_CONST 的 GOT
        // 指针带 PAC 签名，写入未签名指针会在调用时认证失败崩溃。
        if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
            strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) continue;
        for (uint32_t j = 0; j < cur_seg_cmd->nsects; j++) {
            bfp_section_t *sect = (bfp_section_t *)(cur + sizeof(bfp_segment_command_t)) + j;
            uint8_t ty = sect->flags & SECTION_TYPE;
            if (ty == S_LAZY_SYMBOL_POINTERS || ty == S_NON_LAZY_SYMBOL_POINTERS) {
                bfp_perform_rebinding_with_section(rebindings, sect, slide, symtab,
                                                   symtab_cmd->nsyms, strtab,
                                                   symtab_cmd->strsize,
                                                   indirect_symtab, dysymtab_cmd->nindirectsyms,
                                                   (uintptr_t)linkedit_segment->fileoff,
                                                   (uintptr_t)linkedit_segment->vmsize);
            }
        }
    }
}

static struct bfp_rebindings_entry *g_head = NULL;

static int bfp_rebind_symbols(struct bfp_rebinding rb[], size_t nel) {
    struct bfp_rebindings_entry *e = malloc(sizeof(struct bfp_rebindings_entry));
    if (!e) return -1;
    e->rebindings = rb;
    e->rebindings_nel = nel;
    e->next = g_head;
    g_head = e;

    // 只扫「已加载镜像」。不注册 add_image 回调 ——
    // 那个回调在 dlopen 中、dyld 持锁时触发，本探针在那里崩过两次。
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        bfp_rebind_symbols_for_image(e, _dyld_get_image_header(i),
                                     _dyld_get_image_vmaddr_slide(i));
    }
    return 0;
}

#pragma mark - L1 硬件

static int (*o_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int m_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                          void *newp, size_t newlen) {
    bfp_mark_called("sysctlbyname");
    if (!o_sysctlbyname) { errno = ENOSYS; return -1; }
    int r = o_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    if (r == 0 && name && oldp && oldlenp && !newp) {
        size_t len = *oldlenp;
        NSString *key = [NSString stringWithFormat:@"L1 sysctl:%s", name];
        if (len == 4)      bfp_rec_int(key, *(int *)oldp);
        else if (len == 8) bfp_rec_int(key, *(long long *)oldp);
        else if (len > 0 && len < 256) {
            char buf[257] = {0};
            memcpy(buf, oldp, len < 256 ? len : 256);
            bfp_rec_str(key, buf);
        }
    }
    return r;
}


// 读对象返回值的安全做法。
//
// 【为什么上一版会把大量值记成"不可读"】
// 那些指针形如 0x9c318a9189961ca1（高位带 PAC 签名）。
// 返回给调用方的 id 是已经过 objc_msgSend 认证的合法对象指针，
// 对它发消息本身是安全的；而我用 vm_region_64 去查原始地址会失败，
// 于是误判成不可读 —— 把 model / systemVersion 这些关键值全挡在外面了。
//
// 现在：直接发消息读，用 @try 兜底（只对真·已释放对象会抛异常）。
static NSString *bfp_safe_copy(id obj) {
    if (!obj) return @"(nil)";
    NSString *out = nil;
    @try {
        // NSString / NSNumber 直接取 description；
        // 其它对象先看能否转字符串，再退化到 class 名。
        if ([obj respondsToSelector:@selector(description)]) {
            out = [NSString stringWithFormat:@"%@", obj];
        }
    } @catch (NSException *e) {
        out = [NSString stringWithFormat:@"(异常:%@)", e.name ?: @"?"];
    }
    if (!out || !out.length) {
        @try {
            out = [NSString stringWithFormat:@"<%@>",
                   NSStringFromClass([obj class])];
        } @catch (NSException *e2) {
            out = @"(无法读取)";
        }
    }
    if (out.length > 200) out = [out substringToIndex:200];
    return out;
}
static IMP o_identifierForVendor, o_systemVersion, o_model, o_systemName, o_deviceName;
static IMP o_physicalMemory, o_processorCount, o_hostName, o_systemUptime;
static IMP o_localeIdentifier, o_preferredLanguages, o_localTimeZone, o_systemTimeZone;
static IMP o_batteryLevel, o_batteryState;

#define BFP_STR_GETTER(fn, orig, key)                       \
    static id fn(id s, SEL c) {                             \
        id r = orig ? ((id (*)(id, SEL))orig)(s, c) : nil;  \
        bfp_rec(key, bfp_safe_copy(r));                     \
        return r;                                           \
    }

BFP_STR_GETTER(h_systemVersion, o_systemVersion, @"L6 UIDevice.systemVersion")
BFP_STR_GETTER(h_systemName, o_systemName, @"L6 UIDevice.systemName")
BFP_STR_GETTER(h_model, o_model, @"L6 UIDevice.model")
BFP_STR_GETTER(h_deviceName, o_deviceName, @"L6 UIDevice.name")
BFP_STR_GETTER(h_identifierForVendor, o_identifierForVendor, @"L6 UIDevice.identifierForVendor")
BFP_STR_GETTER(h_hostName, o_hostName, @"L6 NSProcessInfo.hostName")
BFP_STR_GETTER(h_localeIdentifier, o_localeIdentifier, @"L6 NSLocale.localeIdentifier")
BFP_STR_GETTER(h_localTimeZone, o_localTimeZone, @"L6 NSTimeZone.localTimeZone")
BFP_STR_GETTER(h_systemTimeZone, o_systemTimeZone, @"L6 NSTimeZone.systemTimeZone")

static id h_preferredLanguages(id s, SEL c) {
    id r = o_preferredLanguages ? ((id (*)(id, SEL))o_preferredLanguages)(s, c) : nil;
    NSString *d = @"(nil)";
    @try {
        if (r && [r respondsToSelector:@selector(count)]) {
            d = [NSString stringWithFormat:@"%lu \u9879", (unsigned long)[r count]];
        }
    } @catch (NSException *e) { d = @"(\u5f02\u5e38)"; }
    bfp_rec(@"L6 NSLocale.preferredLanguages", d);
    return r;
}

static unsigned long long h_physicalMemory(id s, SEL c) {
    unsigned long long r = o_physicalMemory
        ? ((unsigned long long (*)(id, SEL))o_physicalMemory)(s, c) : 0;
    bfp_rec_int(@"L6 NSProcessInfo.physicalMemory", (long long)r);
    return r;
}
static unsigned long long h_processorCount(id s, SEL c) {
    unsigned long long r = o_processorCount
        ? ((unsigned long long (*)(id, SEL))o_processorCount)(s, c) : 0;
    bfp_rec_int(@"L6 NSProcessInfo.processorCount", (long long)r);
    return r;
}
static double h_systemUptime(id s, SEL c) {
    double r = o_systemUptime ? ((double (*)(id, SEL))o_systemUptime)(s, c) : 0;
    bfp_rec(@"L6 NSProcessInfo.systemUptime", [NSString stringWithFormat:@"%.0f", r]);
    return r;
}
static float h_batteryLevel(id s, SEL c) {
    float r = o_batteryLevel ? ((float (*)(id, SEL))o_batteryLevel)(s, c) : 0;
    bfp_rec(@"L6 UIDevice.batteryLevel", [NSString stringWithFormat:@"%.2f", r]);
    return r;
}
static long long h_batteryState(id s, SEL c) {
    long long r = o_batteryState ? ((long long (*)(id, SEL))o_batteryState)(s, c) : 0;
    bfp_rec_int(@"L6 UIDevice.batteryState", r);
    return r;
}

static void bfp_hook(Class cls, SEL sel, IMP newImp, IMP *orig) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (orig) *orig = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

static void bfp_install_getters(void) {
    Class d = objc_getClass("UIDevice");
    bfp_hook(d, @selector(systemVersion), (IMP)h_systemVersion, &o_systemVersion);
    bfp_hook(d, @selector(systemName), (IMP)h_systemName, &o_systemName);
    bfp_hook(d, @selector(model), (IMP)h_model, &o_model);
    bfp_hook(d, @selector(name), (IMP)h_deviceName, &o_deviceName);
    bfp_hook(d, @selector(identifierForVendor), (IMP)h_identifierForVendor, &o_identifierForVendor);
    bfp_hook(d, @selector(batteryLevel), (IMP)h_batteryLevel, &o_batteryLevel);
    bfp_hook(d, @selector(batteryState), (IMP)h_batteryState, &o_batteryState);

    Class p = objc_getClass("NSProcessInfo");
    bfp_hook(p, @selector(physicalMemory), (IMP)h_physicalMemory, &o_physicalMemory);
    bfp_hook(p, @selector(processorCount), (IMP)h_processorCount, &o_processorCount);
    bfp_hook(p, @selector(hostName), (IMP)h_hostName, &o_hostName);
    bfp_hook(p, @selector(systemUptime), (IMP)h_systemUptime, &o_systemUptime);

    Class l = objc_getClass("NSLocale");
    bfp_hook(l, @selector(localeIdentifier), (IMP)h_localeIdentifier, &o_localeIdentifier);
    bfp_hook(l, @selector(preferredLanguages), (IMP)h_preferredLanguages, &o_preferredLanguages);

    Class t = objc_getClass("NSTimeZone");
    bfp_hook(t, @selector(localTimeZone), (IMP)h_localTimeZone, &o_localTimeZone);
    bfp_hook(t, @selector(systemTimeZone), (IMP)h_systemTimeZone, &o_systemTimeZone);
}

#pragma mark - 报告

// 写报告到多个位置，哪个成功算哪个。
//
// 【为什么写多份】App 沙盒 Documents 需要 Filza 才能取；
// 而 /var/mobile/Media/ 是 AFC 可访问区（pymobiledevice3 afc pull 直接能拉），
// 越狱设备上 App 通常有权限写那里。多写几处，取到一份即可。

#pragma mark - 把报告存进相册（免 Filza、免手工转发）

// 为什么走相册：AFC 的根是 /var/mobile/Media，App 沙盒不在里面，
// 沙盒里的 txt 我在电脑端读不到。而「照片」就在 /var/mobile/Media/DCIM/ 下，
// AFC 能读 —— 把报告做成图片存进相册，我就能直接拉走。
static UIImage *bfp_render_text_image(NSString *txt) {
    UIFont *font = [UIFont monospacedSystemFontOfSize:22 weight:UIFontWeightRegular];
    CGFloat w = 2200.0, pad = 24.0;
    NSDictionary *attrs = @{ NSFontAttributeName: font,
                             NSForegroundColorAttributeName: UIColor.blackColor };

    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    for (NSString *ln in [txt componentsSeparatedByString:@"\n"]) {
        if (ln.length <= 100) { [lines addObject:ln]; continue; }
        NSUInteger i = 0;
        while (i < ln.length) {
            NSUInteger n = MIN((NSUInteger)100, ln.length - i);
            [lines addObject:[ln substringWithRange:NSMakeRange(i, n)]];
            i += n;
        }
    }
    CGFloat lh = ceil(font.lineHeight) + 1;
    CGFloat h = pad * 2 + lh * lines.count;
    if (h > 7000) h = 7000;
    if (h < 300) h = 300;

    UIGraphicsBeginImageContextWithOptions(CGSizeMake(w, h), YES, 1.0);
    [[UIColor whiteColor] setFill];
    UIRectFill(CGRectMake(0, 0, w, h));
    CGFloat y = pad;
    for (NSString *ln in lines) {
        if (y + lh > h - pad) break;
        [ln drawAtPoint:CGPointMake(pad, y) withAttributes:attrs];
        y += lh;
    }
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return img;
}

// 用 UIActivityViewController 保存到相册。
// 选「存储图像」即可写入 /var/mobile/Media/DCIM/，AFC 能读到。
static void bfp_save_image_to_photos(UIImage *img, UIViewController *presenter) {
    if (!img || !presenter) return;
    UIActivityViewController *av =
        [[UIActivityViewController alloc] initWithActivityItems:@[img] applicationActivities:nil];
    // iPad 需要 popover 锚点
    av.popoverPresentationController.sourceView = presenter.view;
    av.popoverPresentationController.sourceRect =
        CGRectMake(presenter.view.bounds.size.width / 2,
                   presenter.view.bounds.size.height / 2, 1, 1);
    [presenter presentViewController:av animated:YES completion:nil];
}


#pragma mark - 局域网 HTTP 服务（报告直接取，不碰文件系统）

// 为什么加这个：前面所有"把文件送到电脑"的办法都受 iOS 沙盒限制。
// 最直接的办法是——让手机自己把报告挂在局域网上，电脑用浏览器/curl 取。
// 只用 BSD socket，不依赖任何外部库，也不碰剪贴板/相册/文件系统。
#include <sys/socket.h>
#include <netinet/in.h>

static NSString *g_httpBody = nil;
static int g_httpPort = 0;

static void bfp_start_http(NSString *body) {
    g_httpBody = [body copy];

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return;
    int on = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(0);                 // 让内核分配端口
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(srv); return; }

    struct sockaddr_in got;
    socklen_t glen = sizeof(got);
    if (getsockname(srv, (struct sockaddr *)&got, &glen) != 0) { close(srv); return; }
    g_httpPort = ntohs(got.sin_port);

    if (listen(srv, 4) != 0) { close(srv); return; }

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        for (;;) {
            int cli = accept(srv, NULL, NULL);
            if (cli < 0) continue;
            char buf[1024];
            recv(cli, buf, sizeof(buf) - 1, 0);      // 请求头不关心
            NSData *bd = [g_httpBody dataUsingEncoding:NSUTF8StringEncoding];
            NSString *hdr = [NSString stringWithFormat:
                @"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                @"Content-Length: %lu\r\nConnection: close\r\n\r\n",
                (unsigned long)bd.length];
            send(cli, hdr.UTF8String, strlen(hdr.UTF8String), 0);
            send(cli, bd.bytes, bd.length, 0);
            close(cli);
        }
    });
}

// 取本机 Wi-Fi 地址，拼出可访问 URL
static NSString *bfp_local_url(void) {
    NSString *ip = nil;
    struct ifaddrs *ifa0 = NULL;
    if (getifaddrs(&ifa0) == 0) {
        for (struct ifaddrs *i = ifa0; i; i = i->ifa_next) {
            if (!i->ifa_name || !i->ifa_addr) continue;
            if (i->ifa_addr->sa_family != AF_INET) continue;
            if (strcmp(i->ifa_name, "en0") != 0) continue;
            char b[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &((struct sockaddr_in *)i->ifa_addr)->sin_addr, b, sizeof(b));
            ip = [NSString stringWithUTF8String:b];
            break;
        }
        freeifaddrs(ifa0);
    }
    if (!ip || g_httpPort == 0) return nil;
    return [NSString stringWithFormat:@"http://%@:%d/", ip, g_httpPort];
}


#pragma mark - 分享 TXT 文件（隔空投送 / 存储到文件 / 发微信都行）

// 关键：UIActivityViewController 传「文件 URL」而不是「字符串」，
// 这样隔空投送过去的是一个真正的 .txt 文件，电脑端直接能打开。
// 文件放 tmp 目录：App 自己可写，且分享面板会把它当附件投送。
static NSURL *bfp_make_share_txt(NSString *txt) {
    NSString *name = [NSString stringWithFormat:@"bds_probe_%@.txt",
                      [[NSDateFormatter new] stringFromDate:[NSDate date]]
                          ?: @""];
    // 文件名只保留安全字符
    NSMutableString *safe = [NSMutableString string];
    for (NSUInteger i = 0; i < name.length; i++) {
        unichar c = [name characterAtIndex:i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-') {
            [safe appendFormat:@"%C", c];
        } else {
            [safe appendString:@"_"];
        }
    }
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:safe];
    NSError *err = nil;
    if (![txt writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&err]) {
        return nil;
    }
    return [NSURL fileURLWithPath:path];
}

static void bfp_share_txt(NSString *txt, UIViewController *presenter, UIView *anchor) {
    if (!presenter) return;
    NSURL *u = bfp_make_share_txt(txt);
    if (!u) {
        UIAlertController *e = [UIAlertController
            alertControllerWithTitle:@"\u751f\u6210\u6587\u4ef6\u5931\u8d25"
                             message:@"\u65e0\u6cd5\u5199\u5165\u4e34\u65f6\u76ee\u5f55"
                      preferredStyle:UIAlertControllerStyleAlert];
        [e addAction:[UIAlertAction actionWithTitle:@"\u597d"
                                             style:UIAlertActionStyleCancel handler:nil]];
        [presenter presentViewController:e animated:YES completion:nil];
        return;
    }
    UIActivityViewController *av = [[UIActivityViewController alloc]
        initWithActivityItems:@[u] applicationActivities:nil];
    if (av.popoverPresentationController) {
        av.popoverPresentationController.sourceView = anchor ?: presenter.view;
        av.popoverPresentationController.sourceRect =
            anchor ? anchor.bounds
                   : CGRectMake(presenter.view.bounds.size.width / 2,
                                presenter.view.bounds.size.height / 2, 1, 1);
    }
    [presenter presentViewController:av animated:YES completion:nil];
}

static NSArray<NSString *> *bfp_write_file(NSString *txt) {
    NSMutableArray *written = [NSMutableArray array];
    NSString *name = [NSString stringWithFormat:@"minprobe_%.0f.txt",
                      [[NSDate date] timeIntervalSince1970]];

    NSMutableArray *dirs = [NSMutableArray array];
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                         NSUserDomainMask, YES).firstObject;
    if (docs) [dirs addObject:docs];
    // AFC 可读区候选。App 沙盒通常写不进去，所以多试几个位置：
    //   /tmp 与 /var/tmp 在越狱设备上常与 AFC 区互通（/var 是 /private/var 的符号链接）
    [dirs addObject:@"/tmp"];
    [dirs addObject:@"/var/tmp"];
    [dirs addObject:@"/var/mobile/Media/DCIM"];
    [dirs addObject:@"/var/mobile/Media/Books"];
    [dirs addObject:@"/var/mobile/Media"];
    [dirs addObject:@"/var/mobile/Documents"];
    [dirs addObject:NSHomeDirectory()];

    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *d in dirs) {
        if (!d.length) continue;
        if (![fm fileExistsAtPath:d]) {
            [fm createDirectoryAtPath:d withIntermediateDirectories:YES
                           attributes:nil error:NULL];
        }
        NSString *p = [d stringByAppendingPathComponent:name];
        NSError *err = nil;
        if ([txt writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:&err]) {
            [written addObject:p];
        }
    }
    return written;
}

static NSString *bfp_report(void) {
    bfp_init();
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"BDSMinProbe %@\n", BFPVersion];
    [o appendFormat:@"\u65f6\u95f4      : %@\n", [NSDate date]];
    [o appendFormat:@"BundleID  : %@\n", NSBundle.mainBundle.bundleIdentifier ?: @"?"];
    [o appendFormat:@"\u8fdb\u7a0b      : %@\n", NSProcessInfo.processInfo.processName ?: @"?"];
    [o appendFormat:@"\u8bb0\u5f55\u6761\u6570  : %lu\n", (unsigned long)g_totalRecords];
    [o appendFormat:@"rebind\u5931\u8d25: %d\n", g_bfpRebindFailures];
    [o appendString:@"\n--- hook \u88c5\u8f7d\u72b6\u6001\uff08\u88c5\u4e0a vs \u88ab\u8c03\u7528\uff09---\n"];
    [o appendString:@"  \u7b26\u53f7                     \u88c5\u4e0a  \u539f\u6307\u9488  \u88ab\u8c03\u7528\n"];
    for (int i = 0; i < g_hookStatCount; i++) {
        bfp_hook_stat *s = &g_hookStats[i];
        [o appendFormat:@"  %-22s  %-4s  %-6s  %s\n",
            s->name,
            s->hooked ? "YES" : "NO",
            s->origFilled ? "YES" : "NO",
            s->called ? "YES" : "NO"];
    }
    [o appendString:@"\n  \u8bf4\u660e\uff1a\n"
                @"    \u88c5\u4e0a=NO  -> fishhook \u6ca1\u5728\u5df2\u52a0\u8f7d\u955c\u50cf\u7684 GOT \u91cc\u627e\u5230\u8fd9\u4e2a\u7b26\u53f7\n"
                @"                 \uff08\u53ef\u80fd\u5728 __AUTH_CONST\uff0c\u5e26 PAC \u4e0d\u80fd\u6539\uff1b"
                @"\u6216 App \u6839\u672c\u6ca1\u5bfc\u5165\uff09\n"
                @"    \u88ab\u8c03\u7528=NO -> \u94a9\u5b50\u5df2\u88c5\u4e0a\uff0c\u4f46 App \u786e\u5b9e\u6ca1\u8c03\u7528\n"
                @"    \u539f\u6307\u9488=NO -> \u539f\u51fd\u6570\u5730\u5740\u672a\u586b\u4e0a\uff0c"
                @"\u66ff\u6362\u51fd\u6570\u4f1a\u76f4\u63a5\u8fd4\u56de\u5931\u8d25\n"];

    [g_lock lock];
    NSDictionary *snap = [g_rec copy];
    NSArray *jb = g_jbPaths ? [[g_jbPaths allObjects] sortedArrayUsingSelector:@selector(compare:)] : @[];
    [g_lock unlock];

    NSArray *keys = [[snap allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *L[7];
    for (int i = 0; i < 7; i++) L[i] = [NSMutableArray array];
    for (NSString *k in keys) {
        if ([k hasPrefix:@"L6"]) { [L[6] addObject:k]; continue; }
        if ([k hasPrefix:@"L"] && k.length > 1) {
            int idx = [[k substringWithRange:NSMakeRange(1, 1)] intValue];
            if (idx >= 1 && idx <= 5) [L[idx] addObject:k];
        }
    }
    NSArray *titles = @[@"", @"L1 \u786c\u4ef6 (sysctl/uname)",
                        @"L2 \u6587\u4ef6\u4e0e\u8d8a\u72f1\u8def\u5f84", @"L3 \u7f51\u7edc",
                        @"L4 \u52a8\u6001\u5e93\u679a\u4e3e", @"L5 \u65f6\u95f4",
                        @"L6 \u5173\u952e getter"];

    for (int i = 1; i <= 6; i++) {
        [o appendFormat:@"\n========== %@ ==========\n", titles[i]];
        if (i == 2 && jb.count) {
            [o appendFormat:@"\n[\u547d\u4e2d\u8d8a\u72f1\u7279\u5f81\u7684\u8def\u5f84] %lu \u6761\n",
             (unsigned long)jb.count];
            for (NSString *p in jb) [o appendFormat:@"  %@\n", p];
        }
        if (!L[i].count) { [o appendString:@"  (\u672c\u6b21\u672a\u88ab\u8c03\u7528)\n"]; continue; }
        for (NSString *k in L[i]) {
            NSDictionary *e = snap[k];
            [o appendFormat:@"\n%@\n    \u6b21\u6570=%@\n", k, e[@"n"]];
            NSInteger shown = 0;
            for (NSString *v in e[@"samples"]) {
                [o appendFormat:@"    %@\n", v];
                if (++shown >= 25) { [o appendString:@"    ...\n"]; break; }
            }
        }
    }
    return o;
}

#pragma mark - 悬浮按钮（只有按钮大小的独立窗口 —— 天然穿透）

// 【关键设计】窗口尺寸 = 按钮尺寸。
// 全屏窗口无论怎么写 hitTest 都会吞掉整屏触摸（3.1 实测：App 点不动）。
// 窗口只覆盖按钮那一小块，窗口外的触摸根本不会命中它，天然穿透，无需技巧。
@interface BFPProbeWindow : UIWindow
@end

@implementation BFPProbeWindow
- (BOOL)canBecomeKeyWindow { return NO; }
@end

@interface BFPProbeVC : UIViewController
@end

@implementation BFPProbeVC
- (void)loadView {
    UIView *v = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 72, 72)];
    v.backgroundColor = [UIColor clearColor];
    self.view = v;
}
@end

static UIWindow *g_probeWindow;
static UIButton *g_probeButton;

static void bfp_show_panel(void);

@interface UIButton (BFP)
- (void)bfp_tap;
- (void)bfp_drag:(UIPanGestureRecognizer *)g;
@end
@implementation UIButton (BFP)
- (void)bfp_tap { bfp_show_panel(); }
- (void)bfp_drag:(UIPanGestureRecognizer *)g {
    UIView *sv = self.superview;
    if (!sv) return;
    CGPoint tr = [g translationInView:sv];
    CGPoint o = g_probeWindow.frame.origin;
    o.x += tr.x;
    o.y += tr.y;
    CGFloat W = UIScreen.mainScreen.bounds.size.width;
    CGFloat H = UIScreen.mainScreen.bounds.size.height;
    o.x = MAX(0, MIN(W - 72, o.x));
    o.y = MAX(20, MIN(H - 72, o.y));
    CGRect f = g_probeWindow.frame;
    f.origin = o;
    g_probeWindow.frame = f;
    [g setTranslation:CGPointZero inView:sv];
}
@end

static void bfp_build_button(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (g_probeWindow) return;

        UIWindow *w = nil;
        if (@available(iOS 13.0, *)) {
            UIWindowScene *scene = nil;
            for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
                if ([s isKindOfClass:[UIWindowScene class]] &&
                    s.activationState == UISceneActivationStateForegroundActive) {
                    scene = (UIWindowScene *)s; break;
                }
            }
            if (!scene) {
                for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
                    if ([s isKindOfClass:[UIWindowScene class]]) { scene = (UIWindowScene *)s; break; }
                }
            }
            if (scene) w = [[BFPProbeWindow alloc] initWithWindowScene:scene];
        }
        if (!w) w = [[BFPProbeWindow alloc] initWithFrame:CGRectMake(8, 130, 72, 72)];

        // 窗口只有按钮大小 —— 这是穿透的关键
        w.frame = CGRectMake(8, 130, 72, 72);
        w.windowLevel = 10000000.0;
        w.backgroundColor = [UIColor clearColor];
        w.rootViewController = [[BFPProbeVC alloc] init];
        w.hidden = NO;

        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(0, 0, 72, 72);
        b.backgroundColor = [UIColor colorWithRed:0.1 green:0.55 blue:0.95 alpha:0.9];
        b.layer.cornerRadius = 36;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        b.titleLabel.numberOfLines = 3;
        b.titleLabel.textAlignment = NSTextAlignmentCenter;
        [b setTitle:@"\u63a2\u9488\n\u70b9\u8fd9" forState:UIControlStateNormal];
        [b addTarget:b action:@selector(bfp_tap) forControlEvents:UIControlEventTouchUpInside];
        [b addGestureRecognizer:[[UIPanGestureRecognizer alloc]
                                 initWithTarget:b action:@selector(bfp_drag:)]];
        [w.rootViewController.view addSubview:b];

        g_probeWindow = w;
        g_probeButton = b;
        bfp_marker("05_button_created");

        [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:YES block:^(NSTimer *tm) {
            (void)tm;
            UIWindow *pw = g_probeWindow;
            if (!pw) return;
            if (pw.windowLevel < 10000000.0) pw.windowLevel = 10000000.0;
            if (pw.hidden) pw.hidden = NO;
        }];
    });
}

static void bfp_show_panel(void) {
    UIViewController *top = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if (![s isKindOfClass:[UIWindowScene class]]) continue;
        for (UIWindow *win in ((UIWindowScene *)s).windows) {
            if (win.rootViewController && win != g_probeWindow) {
                top = win.rootViewController;
                break;
            }
        }
        if (top) break;
    }
    if (!top) top = g_probeWindow.rootViewController;
    while (top.presentedViewController) top = top.presentedViewController;
    if (!top || [top isKindOfClass:UIAlertController.class]) return;

    NSString *txt = bfp_report();
    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:@"BDS \u63a2\u9488\u62a5\u544a"
                         message:[txt substringToIndex:MIN((NSUInteger)2500, txt.length)]
                  preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"\u5199\u6587\u4ef6" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction *x) {
        (void)x;
        NSArray *paths = bfp_write_file(txt);
        NSString *msg = paths.count
            ? [paths componentsJoinedByString:@"\n"]
            : @"\u5199\u5165\u5931\u8d25\uff08\u6ca1\u6709\u53ef\u5199\u76ee\u5f55\uff09";
        UIAlertController *b2 = [UIAlertController
            alertControllerWithTitle:[NSString stringWithFormat:@"\u5df2\u5199\u5165 %lu \u5904", (unsigned long)paths.count]
                             message:msg
                      preferredStyle:UIAlertControllerStyleAlert];
        [b2 addAction:[UIAlertAction actionWithTitle:@"\u597d"
                                              style:UIAlertActionStyleCancel handler:nil]];
        [top presentViewController:b2 animated:YES completion:nil];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"\u5206\u4eabTXT" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction *x) {
        (void)x;
        // 隔空投送 / 存储到"文件" / 发微信 —— 投送的是真正的 .txt
        bfp_share_txt(txt, top, nil);
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"\u590d\u5236" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction *x) {
        (void)x;
        UIPasteboard.generalPasteboard.string = txt;
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"\u5f00\u670d\u52a1\u5668" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction *x) {
        (void)x;
        bfp_start_http(txt);
        NSString *u = bfp_local_url();
        UIAlertController *c3 = [UIAlertController
            alertControllerWithTitle:@"\u670d\u52a1\u5668\u5df2\u5f00"
                             message:(u ? [NSString stringWithFormat:
                                      @"\u7535\u8111\u6d4f\u89c8\u5668\u6253\u5f00\uff1a\n%@\n\n"
                                      @"\uff08\u624b\u673a\u4e0e\u7535\u8111\u9700\u5728\u540c\u4e00 Wi-Fi\uff09", u]
                                    : @"\u672a\u53d6\u5230 Wi-Fi \u5730\u5740")
                      preferredStyle:UIAlertControllerStyleAlert];
        [c3 addAction:[UIAlertAction actionWithTitle:@"\u597d" style:UIAlertActionStyleCancel handler:nil]];
        [top presentViewController:c3 animated:YES completion:nil];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"\u5173\u95ed" style:UIAlertActionStyleCancel handler:nil]];
    [top presentViewController:a animated:YES completion:nil];
}

#pragma mark - 入口

__attribute__((constructor))
static void bfp_start(void) {
    bfp_marker("00_enter");
    bfp_init();
    bfp_marker("01_inited");
    bfp_install_c_hooks();
    bfp_marker("02_c_hooks");
    bfp_install_getters();
    bfp_marker("03_getters");
    bfp_build_button();
    bfp_marker("04_done");
}
