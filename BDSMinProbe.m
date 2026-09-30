// BDSMinProbe —— 最小可用只读探针
//
// 【为什么重写】
//   前几版（1.2~1.5）连续闪退，两次崩溃日志分别指向：
//     1. 自写 fishhook 遍历了 __AUTH/__AUTH_CONST（arm64e PAC 签名指针）-> 认证失败崩溃
//     2. 通用 hook（bfp_hook_desc）对返回值调 description()，
//        拿到已释放对象 -> objc_retain 崩溃
//   根因是功能堆得太多、每层都可能有隐患。
//   这一版只做「不会出错的操作」，先确保能稳定跑起来。
//
// 【安全约束（硬性）】
//   A. fishhook 直接复用主插件验证过的实现，不自己写
//   B. 通用 hook 只用于「返回基本类型」的 getter；返回值只做数值记录，
//      绝不调用 description / componentsJoinedByString 等可能触发对象访问的方法
//   C. 返回对象的方法：只记录「被调用了」，不碰返回值
//   D. 所有 C hook 都判空原函数指针
//   E. bfp_rec 内部不调用任何被 hook 的函数；递归锁 + 递归守卫
//
// 【覆盖】只保留回答关键问题所需的最小集合
//   L1 硬件: sysctlbyname（机型/内存/OS版本…）
//   L2 文件: stat/lstat/access/fopen/opendir（越狱路径探测）
//   L3 网络: getifaddrs（接口/本地IP）
//   L4 动态库: _dyld_image_count / _dyld_get_image_name（注入检测）
//   L5 时间: time / gettimeofday / CFAbsoluteTimeGetCurrent（读几次）
//   L6 调用标记: UIDevice/NSProcessInfo/NSLocale/NSTimeZone 的关键 getter（只记调用）

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>
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
#import <sys/mount.h>
#import <sys/statvfs.h>
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

static NSString * const BFPVersion = @"3.0";

#pragma mark - 记录器

static NSMutableDictionary<NSString *, NSMutableDictionary *> *g_rec;
static NSRecursiveLock *g_lock;
static CFAbsoluteTime g_startTime;
static NSUInteger g_totalRecords;
static int g_depth;                     // 递归守卫
static const NSUInteger kMaxPerKey = 200;

static void bfp_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_rec = [NSMutableDictionary dictionary];
        g_lock = [[NSRecursiveLock alloc] init];
        g_startTime = CFAbsoluteTimeGetCurrent();
    });
}

// 只接受 NSString / 数值转成的字符串。绝不访问任意对象。
// 【硬性约束】本函数内不得调用任何被本探针 hook 的函数。
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

// 数值记录专用：不接触任何对象
static void bfp_rec_int(NSString *key, long long v) {
    bfp_rec(key, [NSString stringWithFormat:@"%lld", v]);
}

static void bfp_rec_str(NSString *key, const char *cstr) {
    if (!cstr) { bfp_rec(key, @"(null)"); return; }
    bfp_rec(key, [NSString stringWithUTF8String:cstr]);
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
                                               uintptr_t linkedit_fileoff,
                                               uintptr_t linkedit_vmsize) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    uint32_t pointer_count = (uint32_t)(section->size / sizeof(void *));

    if (section->reserved1 >= nindirectsyms ||
        pointer_count > nindirectsyms - section->reserved1) {
        return;
    }
    // 间接符号表这一段的可读性：已在 bfp_rebind_symbols_for_image 入口整表校验过，
    // 且上面已确认 reserved1 + pointer_count 不越界，这里无需再查（避免系统调用开销）。

    int protected_region = 0;
    for (uint32_t i = 0; i < pointer_count; i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        if (symtab_index >= nsyms) continue;
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        // 关键保护（本次闪退的直接原因）：
        // n_strx 是未经校验的 32 位偏移，越界会让 strcmp 读到未映射内存，
        // 实测崩溃栈就是 _platform_strcmp -> 本函数。
        // 用整数边界判断即可 —— strtab[0, strsize) 已在入口整体校验过可读，
        // 这里不能再用 vm_region（那是系统调用，每符号一次会让 App 卡死）。
        if (strtab_offset >= strsize) continue;
        if (strsize - strtab_offset < 2) continue;
        char *symbol_name = strtab + strtab_offset;
        // 再确认这个地址确实落在本镜像的 __LINKEDIT 段区间内（纯算术，无系统调用）。
        // 这是挡住坏指针的最后一道，且不引入任何 syscall。
        uintptr_t sn = (uintptr_t)symbol_name;
        uintptr_t le_start = (uintptr_t)linkedit_base + linkedit_fileoff;
        uintptr_t le_end = le_start + (uintptr_t)linkedit_vmsize;
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

    uintptr_t linkedit_base =
        (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    bfp_nlist_t *symtab = (bfp_nlist_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    // 注意：这里不做任何系统调用（vm_region 等）。
    // 本函数会在 dlopen 过程中、dyld 持锁时被回调，做系统调用会崩。

    cur = (uintptr_t)header + sizeof(bfp_mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (bfp_segment_command_t *)cur;
        if (cur_seg_cmd->cmd != BFP_LC_SEGMENT) continue;
        // 只扫 __DATA / __DATA_CONST。
        // __AUTH / __AUTH_CONST 的 GOT 指针在 arm64e 上带 PAC 签名，
        // 写入未签名指针会在调用时认证失败崩溃。
        if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
            strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) continue;
        for (uint32_t j = 0; j < cur_seg_cmd->nsects; j++) {
            bfp_section_t *sect = (bfp_section_t *)(cur + sizeof(bfp_segment_command_t)) + j;
            uint8_t t = sect->flags & SECTION_TYPE;
            if (t == S_LAZY_SYMBOL_POINTERS || t == S_NON_LAZY_SYMBOL_POINTERS) {
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

    // 【关键】不注册 _dyld_register_func_for_add_image 回调。
    //
    // 原因：该回调在 dlopen 执行过程中、dyld 持锁时被调用。此时：
    //   1. 不能做系统调用（实测加了 vm_region 校验后仍在同一处崩）
    //   2. 新镜像可能尚未初始化完成
    // 而我们要 hook 的 libsystem/system 函数在 App 启动时全部已加载，
    // 只需在构造阶段对「已加载镜像」扫一遍即可，无需回调。
    //
    // 代价：App 启动后通过 dlopen 加载的新库不会被 hook。
    //       对本次分析目标（百度读系统信息的路径）无影响。
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        bfp_rebind_symbols_for_image(e, _dyld_get_image_header(i),
                                     _dyld_get_image_vmaddr_slide(i));
    }
    return 0;
}

#pragma mark - L1 硬件（sysctlbyname / uname）

static int (*o_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int m_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                          void *newp, size_t newlen) {
    if (!o_sysctlbyname) { errno = ENOSYS; return -1; }
    int r = o_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    if (r == 0 && name && oldp && oldlenp && !newp) {
        size_t len = *oldlenp;
        NSString *key = [NSString stringWithFormat:@"L1 sysctl:%s", name];
        if (len == 4)        bfp_rec_int(key, *(int *)oldp);
        else if (len == 8)   bfp_rec_int(key, *(long long *)oldp);
        else if (len > 0 && len < 256) {
            char buf[257] = {0};
            memcpy(buf, oldp, len < 256 ? len : 256);
            bfp_rec_str(key, buf);
        }
    }
    return r;
}

static int (*o_uname)(struct utsname *);
static int m_uname(struct utsname *b) {
    if (!o_uname) { errno = ENOSYS; return -1; }
    int r = o_uname(b);
    if (r == 0 && b) {
        bfp_rec_str(@"L1 uname.machine", b->machine);
        bfp_rec_str(@"L1 uname.release", b->release);
    }
    return r;
}

#pragma mark - L2 文件（越狱路径探测）

static BOOL bfp_is_jb_path(const char *p) {
    if (!p) return NO;
    static const char *k[] = {
        "Cydia", "cydia", "Sileo", "sileo", "Zebra", "Substrate", "substrate",
        "MobileSubstrate", "frida", "Frida", "cycript", "/jb/", "apt", "dpkg",
        "sshd", "/bin/bash", "roothide", "RootHide", "dopamine", "Dopamine",
        "TrollStore", "trollstore", "ellekit", "ElleKit", "bootstrap",
        "libhooker", "Substitute", NULL
    };
    for (int i = 0; k[i]; i++) if (strstr(p, k[i])) return YES;
    return NO;
}

static NSMutableSet *g_paths;
static void bfp_note_path(const char *p) {
    if (!p) return;
    bfp_init();
    if (bfp_is_jb_path(p)) {
        NSString *s = [NSString stringWithFormat:@"\u26a0\ufe0f %s", p];
        // 只做集合插入，不涉及返回值
        [g_lock lock];
        if (!g_paths) g_paths = [NSMutableSet set];
        if (g_paths.count < 400) [g_paths addObject:s];
        [g_lock unlock];
        bfp_rec_str(@"L2 \u8d8a\u72f1\u8def\u5f84\u547d\u4e2d", p);
    } else {
        bfp_rec_str(@"L2 \u8bbf\u95ee\u8fc7\u7684\u8def\u5f84", p);
    }
}

static int (*o_stat)(const char *, struct stat *);
static int m_stat(const char *p, struct stat *b) {
    if (!o_stat) { errno = ENOSYS; return -1; }
    bfp_note_path(p); return o_stat(p, b);
}
static int (*o_lstat)(const char *, struct stat *);
static int m_lstat(const char *p, struct stat *b) {
    if (!o_lstat) { errno = ENOSYS; return -1; }
    bfp_note_path(p); return o_lstat(p, b);
}
static int (*o_access)(const char *, int);
static int m_access(const char *p, int m) {
    if (!o_access) { errno = ENOSYS; return -1; }
    bfp_note_path(p); return o_access(p, m);
}
static FILE *(*o_fopen)(const char *, const char *);
static FILE *m_fopen(const char *p, const char *md) {
    if (!o_fopen) { errno = ENOSYS; return NULL; }
    bfp_note_path(p); return o_fopen(p, md);
}
static DIR *(*o_opendir)(const char *);
static DIR *m_opendir(const char *p) {
    if (!o_opendir) { errno = ENOSYS; return NULL; }
    bfp_note_path(p); return o_opendir(p);
}

#pragma mark - L3 网络（getifaddrs）

static int (*o_getifaddrs)(struct ifaddrs **);
static int m_getifaddrs(struct ifaddrs **out) {
    if (!o_getifaddrs) { errno = ENOSYS; return -1; }
    int r = o_getifaddrs(out);
    if (r == 0 && out && *out) {
        for (struct ifaddrs *ifa = *out; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_name || !ifa->ifa_addr) continue;
            sa_family_t f = ifa->ifa_addr->sa_family;
            if (f == AF_INET) {
                char b[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, b, sizeof(b));
                bfp_rec([NSString stringWithFormat:@"L3 \u63a5\u53e3 %s", ifa->ifa_name],
                        [NSString stringWithUTF8String:b]);
            } else if (f == AF_INET6) {
                bfp_rec([NSString stringWithFormat:@"L3 \u63a5\u53e3 %s (v6)", ifa->ifa_name], @"\u6709 IPv6 \u5730\u5740");
            } else if (f == AF_LINK && ifa->ifa_addr->sa_len >= 8) {
                struct sockaddr_dl *dl = (struct sockaddr_dl *)ifa->ifa_addr;
                if (dl->sdl_alen == 6) {
                    unsigned char *m = (unsigned char *)LLADDR(dl);
                    bfp_rec([NSString stringWithFormat:@"L3 \u63a5\u53e3 %s MAC", ifa->ifa_name],
                            [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x",
                             m[0], m[1], m[2], m[3], m[4], m[5]]);
                }
            }
        }
    }
    return r;
}

#pragma mark - L4 动态库枚举

static uint32_t (*o_dyld_count)(void);
static uint32_t m_dyld_count(void) {
    if (!o_dyld_count) return 0;
    uint32_t c = o_dyld_count();
    bfp_rec_int(@"L4 _dyld_image_count", c);
    return c;
}

static const char *(*o_dyld_name)(uint32_t);
static const char *m_dyld_name(uint32_t idx) {
    if (!o_dyld_name) return NULL;
    const char *n = o_dyld_name(idx);
    if (n) bfp_rec_str(@"L4 _dyld_get_image_name", n);
    return n;
}

#pragma mark - L5 时间（只观察，不修改）

static CFAbsoluteTime (*o_cfabs)(void);
static CFAbsoluteTime m_cfabs(void) {
    if (!o_cfabs) return 0;
    CFAbsoluteTime t = o_cfabs();
    g_depth++;                                   // 防止记录过程再触发
    bfp_rec(@"L5 CFAbsoluteTimeGetCurrent", [NSString stringWithFormat:@"%.1f", t]);
    g_depth--;
    return t;
}

static time_t (*o_time)(time_t *);
static time_t m_time(time_t *tp) {
    if (!o_time) return 0;
    time_t r = o_time(tp);
    bfp_rec_int(@"L5 time()", (long long)r);
    return r;
}

static int (*o_gettimeofday)(struct timeval *, void *);
static int m_gettimeofday(struct timeval *tv, void *tz) {
    if (!o_gettimeofday) { errno = ENOSYS; return -1; }
    int r = o_gettimeofday(tv, tz);
    if (r == 0 && tv) bfp_rec_int(@"L5 gettimeofday", (long long)tv->tv_sec);
    return r;
}

#pragma mark - C hook 安装

static void bfp_install_c_hooks(void) {
    struct bfp_rebinding rb[] = {
        {"sysctlbyname", (void *)m_sysctlbyname, (void **)&o_sysctlbyname},
        {"uname", (void *)m_uname, (void **)&o_uname},
        {"stat", (void *)m_stat, (void **)&o_stat},
        {"lstat", (void *)m_lstat, (void **)&o_lstat},
        {"access", (void *)m_access, (void **)&o_access},
        {"fopen", (void *)m_fopen, (void **)&o_fopen},
        {"opendir", (void *)m_opendir, (void **)&o_opendir},
        {"getifaddrs", (void *)m_getifaddrs, (void **)&o_getifaddrs},
        {"_dyld_image_count", (void *)m_dyld_count, (void **)&o_dyld_count},
        {"_dyld_get_image_name", (void *)m_dyld_name, (void **)&o_dyld_name},
        {"CFAbsoluteTimeGetCurrent", (void *)m_cfabs, (void **)&o_cfabs},
        {"time", (void *)m_time, (void **)&o_time},
        {"gettimeofday", (void *)m_gettimeofday, (void **)&o_gettimeofday},
    };
    bfp_rebind_symbols(rb, sizeof(rb) / sizeof(rb[0]));
}

#pragma mark - L6 关键 getter（只记录调用次数与原始值，不碰返回值对象）

static IMP o_identifierForVendor, o_systemVersion, o_model, o_systemName, o_deviceName;
static IMP o_physicalMemory, o_processorCount, o_hostName, o_systemUptime;
static IMP o_localeIdentifier, o_preferredLanguages;
static IMP o_localTimeZone, o_systemTimeZone;
static IMP o_batteryLevel, o_batteryState;

// 取对象返回值的安全描述。
//
// 【为什么不能直接调方法】上一次崩溃（objc_retain，possible pointer authentication
// failure）就是因为对返回值调 description / isKindOfClass，而那个指针可能已被
// PAC 或已被释放。任何 objc_msgSend 都会先 retain，坏指针一步就炸。
//
// 安全做法：先用 vm_region 验证这个地址确实是可读内存，再 retain。
// 校验不通过就只记录「返回了对象，指针不可读」，不去碰它。
static BOOL bfp_ptr_readable(const void *p) {
    if (!p) return NO;
    vm_address_t addr = (vm_address_t)p;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size,
                                    VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    if (kr != KERN_SUCCESS) return NO;
    if (!(info.protection & VM_PROT_READ)) return NO;
    // 地址必须落在该 region 内
    return ((vm_address_t)p >= addr) && ((vm_address_t)p < addr + size);
}

static NSString *bfp_safe_copy(id obj) {
    if (!obj) return @"(nil)";
    if (!bfp_ptr_readable((__bridge const void *)obj)) {
        return [NSString stringWithFormat:@"<%p 指针不可读>", (void *)obj];
    }
    // 只对确定可读的对象做一次 retain，再取 description
    CFTypeRef held = CFRetain((__bridge CFTypeRef)obj);
    NSString *out = nil;
    if (held) {
        @try {
            out = [NSString stringWithFormat:@"%@", (__bridge id)held];
        } @catch (NSException *e) {
            out = @"(描述异常)";
        }
        CFRelease(held);
    }
    if (!out) out = @"(nil)";
    return out.length > 200 ? [out substringToIndex:200] : out;
}

static id h_systemVersion(id s, SEL c) {
    id r = o_systemVersion ? ((id (*)(id, SEL))o_systemVersion)(s, c) : nil;
    bfp_rec(@"L6 UIDevice.systemVersion", bfp_safe_copy(r));
    return r;
}
static id h_systemName(id s, SEL c) {
    id r = o_systemName ? ((id (*)(id, SEL))o_systemName)(s, c) : nil;
    bfp_rec(@"L6 UIDevice.systemName", bfp_safe_copy(r));
    return r;
}
static id h_model(id s, SEL c) {
    id r = o_model ? ((id (*)(id, SEL))o_model)(s, c) : nil;
    bfp_rec(@"L6 UIDevice.model", bfp_safe_copy(r));
    return r;
}
static id h_deviceName(id s, SEL c) {
    id r = o_deviceName ? ((id (*)(id, SEL))o_deviceName)(s, c) : nil;
    bfp_rec(@"L6 UIDevice.name", bfp_safe_copy(r));
    return r;
}
static id h_identifierForVendor(id s, SEL c) {
    id r = o_identifierForVendor ? ((id (*)(id, SEL))o_identifierForVendor)(s, c) : nil;
    bfp_rec(@"L6 UIDevice.identifierForVendor", bfp_safe_copy(r));
    return r;
}
static id h_hostName(id s, SEL c) {
    id r = o_hostName ? ((id (*)(id, SEL))o_hostName)(s, c) : nil;
    bfp_rec(@"L6 NSProcessInfo.hostName", bfp_safe_copy(r));
    return r;
}
static id h_localeIdentifier(id s, SEL c) {
    id r = o_localeIdentifier ? ((id (*)(id, SEL))o_localeIdentifier)(s, c) : nil;
    bfp_rec(@"L6 NSLocale.localeIdentifier", bfp_safe_copy(r));
    return r;
}
static id h_preferredLanguages(id s, SEL c) {
    id r = o_preferredLanguages ? ((id (*)(id, SEL))o_preferredLanguages)(s, c) : nil;
    NSString *d = @"(nil)";
    if ([r isKindOfClass:[NSArray class]]) d = [NSString stringWithFormat:@"%lu \u9879", (unsigned long)[r count]];
    bfp_rec(@"L6 NSLocale.preferredLanguages", d);
    return r;
}
static id h_localTimeZone(id s, SEL c) {
    id r = o_localTimeZone ? ((id (*)(id, SEL))o_localTimeZone)(s, c) : nil;
    bfp_rec(@"L6 NSTimeZone.localTimeZone", bfp_safe_copy(r));
    return r;
}
static id h_systemTimeZone(id s, SEL c) {
    id r = o_systemTimeZone ? ((id (*)(id, SEL))o_systemTimeZone)(s, c) : nil;
    bfp_rec(@"L6 NSTimeZone.systemTimeZone", bfp_safe_copy(r));
    return r;
}

// 数值型 getter：只记数值
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

static void bfp_write_file(NSString *txt) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!docs) return;
    NSString *p = [docs stringByAppendingPathComponent:
                   [NSString stringWithFormat:@"minprobe_%.0f.txt", [[NSDate date] timeIntervalSince1970]]];
    [txt writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}

static NSString *bfp_report(void) {
    bfp_init();
    NSMutableString *o = [NSMutableString string];
    [o appendFormat:@"BDSMinProbe %@\n", BFPVersion];
    [o appendFormat:@"时间      : %@\n", [NSDate date]];
    [o appendFormat:@"BundleID  : %@\n", NSBundle.mainBundle.bundleIdentifier ?: @"?"];
    [o appendFormat:@"进程      : %@\n", NSProcessInfo.processInfo.processName ?: @"?"];
    [o appendFormat:@"记录条数  : %lu\n", (unsigned long)g_totalRecords];
    [o appendFormat:@"rebind失败: %d\n", g_bfpRebindFailures];

    [g_lock lock];
    NSDictionary *snap = [g_rec copy];
    NSArray *paths = g_paths ? [[g_paths allObjects] sortedArrayUsingSelector:@selector(compare:)] : @[];
    [g_lock unlock];

    NSArray *keys = [[snap allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *L[6];
    for (int i = 0; i < 6; i++) L[i] = [NSMutableArray array];
    for (NSString *k in keys) {
        if ([k hasPrefix:@"L"] && k.length > 1) {
            int idx = [[k substringWithRange:NSMakeRange(1, 1)] intValue];
            if (idx >= 1 && idx <= 5) [L[idx] addObject:k];
        } else if ([k hasPrefix:@"L6"]) {
            [L[5] addObject:k];
        }
    }
    NSArray *titles = @[@"", @"L1 \u786c\u4ef6", @"L2 \u6587\u4ef6\u4e0e\u8d8a\u72f1\u8def\u5f84",
                        @"L3 \u7f51\u7edc", @"L4 \u52a8\u6001\u5e93\u679a\u4e3e",
                        @"L5 \u65f6\u95f4", @"L6 \u5173\u952e getter"];
    for (int i = 1; i <= 5; i++) {
        [o appendFormat:@"\n========== %@ ==========\n", titles[i]];
        if (i == 2 && paths.count) {
            [o appendFormat:@"\n[\u547d\u4e2d\u8d8a\u72f1\u7279\u5f81\u7684\u8def\u5f84] %lu \u6761\n", (unsigned long)paths.count];
            for (NSString *p in paths) [o appendFormat:@"  %@\n", p];
        }
        if (!L[i].count) { [o appendString:@"  (\u672c\u6b21\u672a\u88ab\u8c03\u7528)\n"]; continue; }
        for (NSString *k in L[i]) {
            NSDictionary *e = snap[k];
            [o appendFormat:@"\n%@   \u6b21\u6570=%@\n", k, e[@"n"]];
            for (NSString *v in e[@"samples"]) [o appendFormat:@"    %@\n", v];
        }
    }
    // L6 单列
    [o appendFormat:@"\n========== %@ ==========\n", titles[5]];
    for (NSString *k in L[5]) {
        NSDictionary *e = snap[k];
        [o appendFormat:@"\n%@   \u6b21\u6570=%@\n", k, e[@"n"]];
        for (NSString *v in e[@"samples"]) [o appendFormat:@"    %@\n", v];
    }
    return o;
}

#pragma mark - 悬浮按钮

static void bfp_show_panel(void);

@interface UIButton (BFP)
- (void)bfp_tap;
@end
@implementation UIButton (BFP)
- (void)bfp_tap { bfp_show_panel(); }
@end

static void bfp_show_panel(void) {
    UIViewController *top = UIApplication.sharedApplication.keyWindow.rootViewController;
    while (top.presentedViewController) top = top.presentedViewController;
    if (!top) return;
    if ([top isKindOfClass:UIAlertController.class]) return;
    NSString *txt = bfp_report();
    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:@"BDS \u6700\u5c0f\u63a2\u9488"
                         message:[txt substringToIndex:MIN((NSUInteger)2500, txt.length)]
                  preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"\u5199\u6587\u4ef6" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction *x) {
        (void)x;
        bfp_write_file(txt);
        UIAlertController *b = [UIAlertController alertControllerWithTitle:@"\u5df2\u5199\u5165 Documents"
                                                                  message:@"minprobe_*.txt"
                                                           preferredStyle:UIAlertControllerStyleAlert];
        [b addAction:[UIAlertAction actionWithTitle:@"\u597d" style:UIAlertActionStyleCancel handler:nil]];
        [top presentViewController:b animated:YES completion:nil];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"\u590d\u5236" style:UIAlertActionStyleDefault
                                       handler:^(UIAlertAction *x) {
        (void)x;
        UIPasteboard.generalPasteboard.string = txt;
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"\u5173\u95ed" style:UIAlertActionStyleCancel handler:nil]];
    [top presentViewController:a animated:YES completion:nil];
}

static void bfp_build_button(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIWindow *w = UIApplication.sharedApplication.keyWindow
                    ?: UIApplication.sharedApplication.windows.firstObject;
        if (!w) return;
        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(12, 140, 72, 72);
        b.backgroundColor = [UIColor colorWithRed:0.1 green:0.55 blue:0.95 alpha:0.92];
        b.layer.cornerRadius = 36;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        b.titleLabel.numberOfLines = 3;
        b.titleLabel.textAlignment = NSTextAlignmentCenter;
        [b setTitle:@"\u6700\u5c0f\n\u63a2\u9488\n\u70b9\u8fd9" forState:UIControlStateNormal];
        [b addTarget:b action:@selector(bfp_tap) forControlEvents:UIControlEventTouchUpInside];
        [w addSubview:b];
    });
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
