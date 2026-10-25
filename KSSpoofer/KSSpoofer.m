//
//  KSSpoofer.m —— 快手设备信息伪装
//
//  功能（对齐极速/网盘插件的最小集）：
//    ① 设备信息 hook：UIDevice / NSProcessInfo / sysctlbyname / 磁盘
//    ② 悬浮球 + 面板：显示当前伪装值
//    ③ 一键随机：生成全新机型/系统/内存/磁盘/身份串
//    ④ 配置按容器独立：Documents/ksspoofer_config.plist
//
//  不做：上报拦截、越狱检测绕过、网络层
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/vm_page_size.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>

#pragma mark - fishhook（自 BDSpoofer 内嵌实现）

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

// fishhook 写入时的诊断：vm_protect 失败与 chained fixups 都会让 C 层 hook 静默失效。
static int g_bdsRebindFailures = 0;
static kern_return_t g_bdsLastRebindFailure = KERN_SUCCESS;

static vm_address_t bds_page_mask(void) {
    vm_size_t page = vm_page_size;
    if (page == 0) {
        long sysPage = sysconf(_SC_PAGESIZE);
        page = sysPage > 0 ? (vm_size_t)sysPage : 16384;
    }
    return (vm_address_t)(page - 1);
}

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
                                               uint32_t nsyms,
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
        if (symtab_index >= nsyms) continue;  // 符号表越界，跳过
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        if (!symbol_name[0] || !symbol_name[1]) continue;
        struct bds_rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    // 延迟到真正需要写入时才解除该 GOT 区域的写保护
                    // 地址与长度按页对齐，否则 vm_protect 可能整体失败。
                    if (!protected_region) {
                        vm_address_t page_mask = bds_page_mask();
                        vm_address_t page_start = (vm_address_t)indirect_symbol_bindings & ~page_mask;
                        vm_address_t page_end = ((vm_address_t)indirect_symbol_bindings
                            + (vm_size_t)section->size + page_mask) & ~page_mask;
                        kern_return_t vr = vm_protect(mach_task_self(), page_start,
                            (vm_size_t)(page_end - page_start), NO,
                            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        if (vr != KERN_SUCCESS) {
                            g_bdsRebindFailures++;
                            g_bdsLastRebindFailure = vr;
                            return;
                        }
                        protected_region = 1;
                    }
                    // 记录原函数地址：与官方 fishhook 一致，不挑节类型
                    // （惰性槽位里的值同样可用）。只加两条保险：
                    // 槽位里不能已经是替换目标，且已经记到过就不再覆写。
                    // 注意：这里不能加 “只从 S_NON_LAZY 槽位取” 的限制，
                    // 否则惰性槽位永远记不到原函数，orig_* 保持 NULL，
                    // 替换函数会一律返回失败（stat/access 报错、dlopen 返回 NULL），
                    // 表现为 App 一启动就闪退。
                    if (cur->rebindings[j].replaced != NULL &&
                        *(cur->rebindings[j].replaced) == NULL &&
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
    // chained fixups 镜像的间接符号表为空：以前静默跳过，现在记一笔。
    if (dysymtab_cmd->nindirectsyms == 0) { g_bdsRebindFailures++; return; }

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
                                                       symtab, symtab_cmd->nsyms,
                                                       strtab, indirect_symtab,
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

#pragma mark - 配置

static NSDictionary *g_cfg = nil;
static NSMutableDictionary *g_mut = nil;

static NSString *KSConfigPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"ksspoofer_config.plist"];
}

static BOOL cfgBool(NSString *k, BOOL d) {
    id v = g_cfg[k];
    return [v isKindOfClass:NSNumber.class] ? [v boolValue] : d;
}
static NSString *cfgStr(NSString *k, NSString *d) {
    id v = g_cfg[k];
    return ([v isKindOfClass:NSString.class] && [v length]) ? v : d;
}
static long long cfgInt(NSString *k, long long d) {
    id v = g_cfg[k];
    return [v isKindOfClass:NSNumber.class] ? [v longLongValue] : d;
}

static void KSReloadConfig(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:KSConfigPath()];
    if (![d isKindOfClass:NSDictionary.class] || d.count == 0) {
        // 容器里没有配置 → 读「快手伪装」管理器的默认身份
        NSDictionary *def = [NSDictionary dictionaryWithContentsOfFile:
            @"/var/mobile/Library/Preferences/com.bds.ksspoofer.default.plist"];
        if (![def isKindOfClass:NSDictionary.class] || def.count == 0) {
            def = [NSDictionary dictionaryWithContentsOfFile:
                @"/tmp/com.bds.ksspoofer.default.plist"];
        }
        if ([def isKindOfClass:NSDictionary.class] && def.count) d = def;
    }
    g_cfg = d ?: @{};
    g_mut = [g_cfg mutableCopy];
}

static void KSSaveConfig(void) {
    if (!g_mut) return;
    [g_mut writeToFile:KSConfigPath() atomically:YES];
    g_cfg = [g_mut copy];
}

#pragma mark - 随机身份（照搬百度极速机型池）

typedef struct {
    const char *name;
    const char *machine;
    const char *model;
    int memMB;
    int diskGroup;      // 0:64/128/256 1:128/256/512 2:128/256/512/1024 3:256/512/1024
    const char *osGroup; // "16" / "17" / "18" / "1617"
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

static void KSRandomizeIdentity(void) {
    int idx = (int)arc4random_uniform((uint32_t)kProfileCount);
    const KSProfile *p = &kProfiles[idx];

    g_mut[@"hwMachine"] = [NSString stringWithUTF8String:p->machine];
    g_mut[@"hwModel"] = [NSString stringWithUTF8String:p->model];
    g_mut[@"memoryMB"] = @(p->memMB);
    int dg = p->diskGroup;
    g_mut[@"diskGB"] = @(kDiskGroups[dg][arc4random_uniform((uint32_t)kDiskCounts[dg])]);

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
    g_mut[@"systemVersion"] = [NSString stringWithUTF8String:vs[vi]];
    g_mut[@"systemBuild"] = [NSString stringWithUTF8String:bs[vi]];

    g_mut[@"deviceName"] = @"iPhone";
    g_mut[@"idfv"] = [[NSUUID UUID] UUIDString];
    g_mut[@"idfa"] = [[NSUUID UUID] UUIDString];
    // 档案编号：1.0 起，按池顺序
    g_mut[@"profileId"] = [NSString stringWithFormat:@"1.%d", idx];
    g_mut[@"profileName"] = [NSString stringWithUTF8String:p->name];
    g_mut[@"installTimeMs"] = @0;
    g_mut[@"didResetDone"] = @NO;
    g_mut[@"kcResetDone"] = @NO;
    g_mut[@"enabled"] = @YES;
    KSSaveConfig();
}

#pragma mark - hook

static void hookInst(Class cls, SEL sel, IMP newImp, IMP *oldImp) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        if (oldImp) *oldImp = method_getImplementation(m);
        method_setImplementation(m, newImp);
    }
}

static NSString *(*o_model)(id, SEL) = NULL;
static NSString *(*o_name)(id, SEL) = NULL;
static NSString *(*o_sysVer)(id, SEL) = NULL;
static NSUInteger (*o_physMem)(id, SEL) = NULL;
static NSUInteger (*o_procCount)(id, SEL) = NULL;
static int (*o_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static id (*o_attrsOfFS)(id, SEL, NSString *) = NULL;

static NSString *ks_model(id self, SEL _cmd) {
    NSString *v = cfgStr(@"hwModel", @"");
    return v.length ? v : (o_model ? o_model(self, _cmd) : @"iPhone");
}
static NSString *ks_name(id self, SEL _cmd) {
    NSString *v = cfgStr(@"deviceName", @"");
    return v.length ? v : (o_name ? o_name(self, _cmd) : @"iPhone");
}
static NSString *ks_sysVer(id self, SEL _cmd) {
    NSString *v = cfgStr(@"systemVersion", @"");
    return v.length ? v : (o_sysVer ? o_sysVer(self, _cmd) : @"17.0.1");
}
static NSUInteger ks_physMem(id self, SEL _cmd) {
    long long mb = cfgInt(@"memoryMB", 0);
    if (mb > 0) return (NSUInteger)(mb * 1024ULL * 1024ULL);
    return o_physMem ? o_physMem(self, _cmd) : 0;
}
static NSUInteger ks_procCount(id self, SEL _cmd) {
    return o_procCount ? o_procCount(self, _cmd) : 6;
}

static int ks_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                           void *newp, size_t newlen) {
    if (name && oldp && oldlenp) {
        if (strcmp(name, "hw.machine") == 0) {
            NSString *v = cfgStr(@"hwMachine", @"");
            if (v.length) {
                const char *s = v.UTF8String;
                size_t n = strlen(s) + 1;
                if (*oldlenp >= n) { memcpy(oldp, s, n); *oldlenp = n; return 0; }
            }
        } else if (strcmp(name, "hw.model") == 0) {
            NSString *v = cfgStr(@"hwModel", @"");
            if (v.length) {
                const char *s = v.UTF8String;
                size_t n = strlen(s) + 1;
                if (*oldlenp >= n) { memcpy(oldp, s, n); *oldlenp = n; return 0; }
            }
        } else if (strcmp(name, "hw.memsize") == 0) {
            long long mb = cfgInt(@"memoryMB", 0);
            if (mb > 0 && *oldlenp >= sizeof(uint64_t)) {
                uint64_t v = (uint64_t)(mb * 1024ULL * 1024ULL);
                memcpy(oldp, &v, sizeof(v));
                *oldlenp = sizeof(v);
                return 0;
            }
        } else if (strcmp(name, "hw.ncpu") == 0) {
            if (*oldlenp >= sizeof(int)) {
                int v = 6;
                memcpy(oldp, &v, sizeof(v));
                *oldlenp = sizeof(v);
                return 0;
            }
        }
    }
    return o_sysctlbyname ? o_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
}

static id ks_attrsOfFS(id self, SEL _cmd, NSString *path) {
    id d = o_attrsOfFS ? o_attrsOfFS(self, _cmd, path) : nil;
    long long gb = cfgInt(@"diskGB", 0);
    if (gb > 0 && [d isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *m = [d mutableCopy];
        m[NSFileSystemSize] = @(gb * 1024ULL * 1024ULL * 1024ULL);
        return m;
    }
    return d;
}

static double ks_zero_double(id self, SEL _cmd) { return 0.0; }
static BOOL ks_yes_bool(id self, SEL _cmd) { return YES; }
static long long ks_fake_ll(id self, SEL _cmd);

static NSMutableArray<NSString *> *g_installHits = nil;

// 伪装的安装时间戳（毫秒）：
//   · 优先读配置（installTimeMs），读到后固定不变
//   · 没有则生成：今天 00:00 ~ 现在 之间的随机时刻，存进配置
//   · 「一键随机」会把 installTimeMs 清 0，下次读取时重新生成
static long long KSFakeInstallMs(void) {
    long long v = cfgInt(@"installTimeMs", 0);
    if (v > 0) return v;

    NSDate *now = [NSDate date];
    NSDate *todayStart = [[NSCalendar currentCalendar] startOfDayForDate:now];
    NSTimeInterval start = [todayStart timeIntervalSince1970];
    NSTimeInterval end = [now timeIntervalSince1970];
    if (end <= start) end = start + 3600;
    double r = (double)arc4random_uniform(10000) / 10000.0;
    NSTimeInterval t = start + (end - start) * r;
    v = (long long)(t * 1000.0);

    if (g_mut) {
        g_mut[@"installTimeMs"] = @(v);
        KSSaveConfig();
    }
    return v;
}

static long long ks_fake_ll(id self, SEL _cmd) { return KSFakeInstallMs(); }

static BOOL KSIsInstallKey(NSString *key) {
    if (!key.length) return NO;
    if ([key containsString:@"com.kuaishou.appUsage"]) return YES;
    if ([key containsString:@"firstInstall"]) return YES;
    if ([key containsString:@"firstLaunchTime"]) return YES;
    return NO;
}

static id (*o_ud_object)(id, SEL, NSString *) = NULL;
static id (*o_ud_string)(id, SEL, NSString *) = NULL;
static double (*o_ud_double)(id, SEL, NSString *) = NULL;
static NSInteger (*o_ud_integer)(id, SEL, NSString *) = NULL;

static id ks_ud_object(id self, SEL _cmd, NSString *key) {
    if (KSIsInstallKey(key)) return @(KSFakeInstallMs());
    return o_ud_object ? o_ud_object(self, _cmd, key) : nil;
}
static id ks_ud_string(id self, SEL _cmd, NSString *key) {
    if (KSIsInstallKey(key)) return [NSString stringWithFormat:@"%lld", KSFakeInstallMs()];
    return o_ud_string ? o_ud_string(self, _cmd, key) : nil;
}
static double ks_ud_double(id self, SEL _cmd, NSString *key) {
    if (KSIsInstallKey(key)) return (double)KSFakeInstallMs();
    return o_ud_double ? o_ud_double(self, _cmd, key) : 0;
}
static NSInteger ks_ud_integer(id self, SEL _cmd, NSString *key) {
    if (KSIsInstallKey(key)) return (NSInteger)KSFakeInstallMs();
    return o_ud_integer ? o_ud_integer(self, _cmd, key) : 0;
}

// 运行时扫描：伪装「首次启动 / 重装时间戳」类方法
static void KSSpoofInstallState(void) {
    if (!g_installHits) g_installHits = [NSMutableArray array];
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *classes = (Class *)malloc(sizeof(Class) * (size_t)n);
    if (!classes) return;
    n = objc_getClassList(classes, n);
    for (int i = 0; i < n; i++) {
        unsigned mc = 0;
        Method *ms = class_copyMethodList(classes[i], &mc);
        if (!ms) continue;
        for (unsigned j = 0; j < mc; j++) {
            SEL sel = method_getName(ms[j]);
            const char *nm = sel_getName(sel);
            const char *sig = method_getTypeEncoding(ms[j]);
            if (!nm || !sig) continue;
            if (strcmp(nm, "currentInstallFirstLaunchTimeInterval") == 0 && sig[0] == 'd') {
                method_setImplementation(ms[j], (IMP)ks_zero_double);
                if (![g_installHits containsObject:@"firstLaunchInterval"])
                    [g_installHits addObject:@"firstLaunchInterval"];
            } else if ((strstr(nm, "firstLaunchTimeStamp") || strstr(nm, "firstInstallTime"))
                       && sig[0] == 'q') {
                method_setImplementation(ms[j], (IMP)ks_fake_ll);
                NSString *t = [NSString stringWithUTF8String:nm];
                if (![g_installHits containsObject:t]) [g_installHits addObject:t];
            } else if ((strcmp(nm, "isFirstLaunch") == 0 || strcmp(nm, "firstLaunch") == 0)
                       && sig[0] == 'B') {
                method_setImplementation(ms[j], (IMP)ks_yes_bool);
                NSString *t = [NSString stringWithUTF8String:nm];
                if (![g_installHits containsObject:t]) [g_installHits addObject:t];
            }
        }
        free(ms);
    }
    free(classes);
}

static OSStatus (*o_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *) = NULL;
static volatile int g_kcTotal = 0;
static volatile int g_kcMatch = 0;
static volatile int g_kcBlocked = 0;

// keychain 安装记录：伪装时让「查不到」，快手就会按新装重建（值=今天）
static OSStatus ks_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    @try {
        g_kcTotal++;
        if (query) {
            NSDictionary *q = (__bridge NSDictionary *)query;
            NSString *svc = q[(__bridge NSString *)kSecAttrService];
            NSString *acct = q[(__bridge NSString *)kSecAttrAccount];
            NSString *joined = [NSString stringWithFormat:@"%@|%@",
                                [svc isKindOfClass:NSString.class] ? svc : @"",
                                [acct isKindOfClass:NSString.class] ? acct : @""];
            if ([joined containsString:@"appUsage"] ||
                [joined containsString:@"jnkeychain"]) {
                long long ms = cfgInt(@"installTimeMs", 0);
                if (ms <= 0) {
                    KSFakeInstallMs();
                    return errSecItemNotFound;
                }
            }
            // 快手所有 keychain 持久项：首次伪装时全部查不到 →
            // 让快手按全新设备重建（did / idfa / install / cloudid / hachi ...）
            if ([joined containsString:@"com.kuaishou"] ||
                [joined containsString:@"com.kwai"] ||
                [joined containsString:@"kwai.did"] ||
                [joined containsString:@"com.gif.kscommon"]) {
                g_kcMatch++;
                if (!cfgBool(@"kcResetDone", NO)) {
                    g_kcBlocked++;
                    if (g_mut) {
                        g_mut[@"kcResetDone"] = @YES;
                        g_mut[@"didResetDone"] = @YES;
                        KSSaveConfig();
                    }
                    return errSecItemNotFound;
                }
            }
        }
    } @catch (NSException *e) {}
    return o_SecItemCopyMatching ? o_SecItemCopyMatching(query, result)
                                 : errSecItemNotFound;
}

static NSUUID *(*o_idfv)(id, SEL) = NULL;
static NSUUID *(*o_idfa)(id, SEL) = NULL;

static NSUUID *ks_idfv(id self, SEL _cmd) {
    NSString *s = cfgStr(@"idfv", @"");
    if (s.length) {
        NSUUID *u = [[NSUUID alloc] initWithUUIDString:s];
        if (u) return u;
    }
    return o_idfv ? o_idfv(self, _cmd) : nil;
}

static NSUUID *ks_idfa(id self, SEL _cmd) {
    NSString *s = cfgStr(@"idfa", @"");
    if (s.length) {
        NSUUID *u = [[NSUUID alloc] initWithUUIDString:s];
        if (u) return u;
    }
    return o_idfa ? o_idfa(self, _cmd) : nil;
}

#pragma mark - 网络抓包（不连电脑，直接看快手接口）

static NSString *KSNetLogPath(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"ksnet_log.txt"];
}

static NSMutableArray<NSString *> *g_netHits = nil;
static volatile int g_netCount = 0;

static void KSNetLog(NSString *line) {
    @try {
        if (!g_netHits) g_netHits = [NSMutableArray array];
        [g_netHits addObject:line];
        if (g_netHits.count > 200) [g_netHits removeObjectAtIndex:0];
        g_netCount++;
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:KSNetLogPath()];
        NSString *s = [line stringByAppendingString:@"\n"];
        if (!fh) {
            [s writeToFile:KSNetLogPath() atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            return;
        }
        [fh seekToEndOfFile];
        [fh writeData:[s dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
        NSDictionary *attr = [[NSFileManager defaultManager] attributesOfItemAtPath:KSNetLogPath() error:NULL];
        if ([attr fileSize] > 256 * 1024) {
            [@"" writeToFile:KSNetLogPath() atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        }
    } @catch (NSException *e) {}
}

static BOOL KSInterestingURL(NSURL *url) {
    if (!url) return NO;
    NSString *s = url.absoluteString.lowercaseString;
    if (!([s containsString:@"kuaishou"] || [s containsString:@"kwai"] ||
          [s containsString:@"gifshow"])) return NO;
    return [s containsString:@"login"] || [s containsString:@"bind"] ||
           [s containsString:@"passport"] || [s containsString:@"user"] ||
           [s containsString:@"third"] || [s containsString:@"verify"] ||
           [s containsString:@"risk"] || [s containsString:@"register"];
}

static NSURLSessionDataTask *(*o_dataTask)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)) = NULL;

static NSURLSessionDataTask *ks_dataTask(id self, SEL _cmd, NSURLRequest *request,
    void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    @try {
        if (request && KSInterestingURL(request.URL)) {
            NSMutableString *line = [NSMutableString string];
            [line appendFormat:@"\n[REQ] %@ %@", request.HTTPMethod, request.URL.absoluteString];
            NSDictionary *h = request.allHTTPHeaderFields;
            if (h.count) [line appendFormat:@"\n  headers: %@", h];
            NSData *body = request.HTTPBody;
            if (body.length) {
                NSString *txt = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
                if (txt.length) {
                    [line appendFormat:@"\n  body: %@", [txt substringToIndex:MIN(txt.length, 800)]];
                } else {
                    NSMutableString *hex = [NSMutableString string];
                    const uint8_t *p = body.bytes;
                    for (NSUInteger i = 0; i < MIN(body.length, (NSUInteger)120); i++)
                        [hex appendFormat:@"%02x", p[i]];
                    [line appendFormat:@"\n  body(%luB hex): %@", (unsigned long)body.length, hex];
                }
            }
            KSNetLog(line);
        }
    } @catch (NSException *e) {}
    if (!completion) {
        return o_dataTask ? o_dataTask(self, _cmd, request, completion) : nil;
    }
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        @try {
            if (resp && KSInterestingURL(resp.URL)) {
                NSMutableString *line = [NSMutableString string];
                [line appendFormat:@"[RESP] %@ %ld", resp.URL.absoluteString,
                       (long)((NSHTTPURLResponse *)resp).statusCode];
                if (data.length) {
                    NSString *txt = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                    if (txt.length) {
                        [line appendFormat:@"\n  body: %@", [txt substringToIndex:MIN(txt.length, 800)]];
                    } else {
                        NSMutableString *hex = [NSMutableString string];
                        const uint8_t *p = data.bytes;
                        for (NSUInteger i = 0; i < MIN(data.length, (NSUInteger)120); i++)
                            [hex appendFormat:@"%02x", p[i]];
                        [line appendFormat:@"\n  body(%luB hex): %@", (unsigned long)data.length, hex];
                    }
                }
                if (err) [line appendFormat:@"\n  err: %@", err.localizedDescription];
                KSNetLog(line);
            }
        } @catch (NSException *e) {}
        completion(data, resp, err);
    };
    return o_dataTask ? o_dataTask(self, _cmd, request, wrapped) : nil;
}

static void KSInstallHooks(void) {
    Class ud = NSClassFromString(@"UIDevice");
    if (ud) {
        hookInst(ud, @selector(model), (IMP)ks_model, (IMP *)&o_model);
        hookInst(ud, @selector(name), (IMP)ks_name, (IMP *)&o_name);
        hookInst(ud, @selector(systemVersion), (IMP)ks_sysVer, (IMP *)&o_sysVer);
    }
    Class pi = NSClassFromString(@"NSProcessInfo");
    if (pi) {
        hookInst(pi, @selector(physicalMemory), (IMP)ks_physMem, (IMP *)&o_physMem);
        hookInst(pi, @selector(processorCount), (IMP)ks_procCount, (IMP *)&o_procCount);
    }
    Class fm = NSClassFromString(@"NSFileManager");
    if (fm) {
        hookInst(fm, @selector(attributesOfFileSystemForPath:error:), (IMP)ks_attrsOfFS, (IMP *)&o_attrsOfFS);
    }
    if (ud) {
        hookInst(ud, NSSelectorFromString(@"identifierForVendor"), (IMP)ks_idfv, (IMP *)&o_idfv);
    }
    Class sess = NSClassFromString(@"NSURLSession");
    if (sess) {
        hookInst(sess, @selector(dataTaskWithRequest:completionHandler:),
                 (IMP)ks_dataTask, (IMP *)&o_dataTask);
    }
    Class aim = NSClassFromString(@"ASIdentifierManager");
    if (aim) {
        hookInst(aim, NSSelectorFromString(@"advertisingIdentifier"), (IMP)ks_idfa, (IMP *)&o_idfa);
    }
    struct bds_rebinding rb[] = {
        {"sysctlbyname", (void *)ks_sysctlbyname, (void **)&o_sysctlbyname},
        {"SecItemCopyMatching", (void *)ks_SecItemCopyMatching, (void **)&o_SecItemCopyMatching},
    };
    bds_rebind_symbols(rb, sizeof(rb) / sizeof(rb[0]));
    // 安装时间键（NSUserDefaults）
    Class udc = NSClassFromString(@"NSUserDefaults");
    if (udc) {
        hookInst(udc, @selector(objectForKey:), (IMP)ks_ud_object, (IMP *)&o_ud_object);
        hookInst(udc, @selector(stringForKey:), (IMP)ks_ud_string, (IMP *)&o_ud_string);
        hookInst(udc, @selector(doubleForKey:), (IMP)ks_ud_double, (IMP *)&o_ud_double);
        hookInst(udc, @selector(integerForKey:), (IMP)ks_ud_integer, (IMP *)&o_ud_integer);
    }
    KSSpoofInstallState();
    if (g_installHits && ![g_installHits containsObject:@"installTimeKeys"])
        [g_installHits addObject:@"installTimeKeys"];
}

#pragma mark - 悬浮球 + 面板

static UIWindow *g_ballWin = nil;
static UIWindow *g_panelWin = nil;
static UIView *g_ball = nil;
static UILabel *g_ballLabel = nil;
static UITextView *g_text = nil;
static BOOL g_expanded = NO;
static CGPoint g_ballCenter = {0, 0};

static UIWindowScene *KSScene(void) {
    if (@available(iOS 13.0, *)) {
        UIWindowScene *fb = nil;
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            if (ws.activationState == UISceneActivationStateForegroundActive) return ws;
            if (!fb) fb = ws;
        }
        return fb;
    }
    return nil;
}

static NSString *KSInstallTimeText(void) {
    long long ms = cfgInt(@"installTimeMs", 0);
    if (ms <= 0) ms = KSFakeInstallMs();   // 面板打开时主动生成并落盘
    if (ms <= 0) return @"(待生成)";
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"MM-dd HH:mm:ss";
    return [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)ms / 1000.0]];
}

static NSString *KSDashboard(void) {
    return [NSString stringWithFormat:
        @"快手伪装\n\n"
        @"档案: %@  %@\n"
        @"机型: %@ (%@)\n"
        @"系统: %@ (%@)\n"
        @"内存: %lld MB\n"
        @"磁盘: %lld GB\n"
        @"IDFV: %@\n"
        @"IDFA: %@\n"
        @"开关: %@\n"
        @"安装时间: %@\n"
        @"安装状态: %@\n"
        @"KC 诊断: 总%d 匹配%d 拦截%d\n"
        @"网络抓包: %d 条（看 Documents/ksnet_log.txt）\n\n"
        @"点「一键随机」生成全新身份\n改完重启快手生效",
        cfgStr(@"profileId", @"-"),
        cfgStr(@"profileName", @"-"),
        cfgStr(@"hwMachine", @"-"),
        cfgStr(@"hwModel", @"-"),
        cfgStr(@"systemVersion", @"-"),
        cfgStr(@"systemBuild", @"-"),
        cfgInt(@"memoryMB", 0),
        cfgInt(@"diskGB", 0),
        cfgStr(@"idfv", @"-"),
        cfgStr(@"idfa", @"-"),
        cfgBool(@"enabled", YES) ? @"开" : @"关",
        KSInstallTimeText(),
        (g_installHits && g_installHits.count)
            ? [g_installHits componentsJoinedByString:@", "] : @"(未 hook 到)",
        g_kcTotal, g_kcMatch, g_kcBlocked, g_netCount];
}

static void KSRefreshPanel(void) {
    if (g_text) g_text.text = KSDashboard();
}

@interface KSTarget : NSObject
+ (instancetype)shared;
- (void)tap;
- (void)pan:(UIPanGestureRecognizer *)g;
- (void)randomize;
- (void)close;
- (void)viewLog;
- (void)viewDash;
@end

@implementation KSTarget
+ (instancetype)shared {
    static KSTarget *s;
    static dispatch_once_t o;
    dispatch_once(&o, ^{ s = [KSTarget new]; });
    return s;
}
- (void)tap {
    g_expanded = !g_expanded;
    g_panelWin.hidden = !g_expanded;
    g_ballLabel.text = g_expanded ? @"关闭" : @"伪装";
    g_ball.backgroundColor = g_expanded
        ? [UIColor colorWithRed:0.78 green:0.16 blue:0.16 alpha:0.95]
        : [UIColor colorWithRed:0.10 green:0.55 blue:0.85 alpha:0.92];
    if (g_expanded) KSRefreshPanel();
}
- (void)pan:(UIPanGestureRecognizer *)g {
    if (!g_ballWin) return;
    CGPoint t = [g translationInView:nil];
    CGRect screen = [UIScreen mainScreen].bounds;
    CGPoint c = CGPointMake(g_ballWin.center.x + t.x, g_ballWin.center.y + t.y);
    c.x = MAX(30, MIN(screen.size.width - 30, c.x));
    c.y = MAX(40, MIN(screen.size.height - 30, c.y));
    g_ballWin.center = c;
    [g setTranslation:CGPointZero inView:nil];
    g_ballCenter = c;
}
- (void)randomize {
    KSRandomizeIdentity();
    KSRefreshPanel();
    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:@"已生成新身份"
                         message:@"彻底关闭快手（后台划掉）再打开才生效"
                  preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault handler:nil]];
    UIViewController *vc = g_ballWin.rootViewController;
    if (vc) [vc presentViewController:a animated:YES completion:nil];
}
- (void)viewLog {
    NSString *log = [NSString stringWithContentsOfFile:KSNetLogPath()
                                             encoding:NSUTF8StringEncoding error:NULL];
    if (!log.length) log = @"(还没有抓包记录)\n\n走一遍登录流程再看";
    g_text.text = log;
}

- (void)viewDash {
    g_text.text = KSDashboard();
}

- (void)close {
    g_expanded = NO;
    g_panelWin.hidden = YES;
    g_ballLabel.text = @"伪装";
    g_ball.backgroundColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.85 alpha:0.92];
}
@end

static void KSInstallUI(void) {
    @try {
        if (g_ballWin) return;
        UIWindowScene *scene = KSScene();
        if (@available(iOS 13.0, *)) {
            if (!scene) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ KSInstallUI(); });
                return;
            }
        }
        CGRect screen = [UIScreen mainScreen].bounds;
        CGFloat side = 52.0;
        CGPoint center = g_ballCenter;
        if (center.x <= 0) center = CGPointMake(screen.size.width - side / 2 - 8, screen.size.height * 0.3);

        g_ballWin = [[UIWindow alloc] initWithFrame:CGRectMake(center.x - side / 2, center.y - side / 2, side, side)];
        if (@available(iOS 13.0, *)) { if (scene) g_ballWin.windowScene = scene; }
        g_ballWin.windowLevel = UIWindowLevelAlert + 100;
        g_ballWin.backgroundColor = [UIColor clearColor];
        g_ballWin.rootViewController = [UIViewController new];
        g_ballWin.hidden = NO;

        g_ball = [[UIView alloc] initWithFrame:CGRectMake(0, 0, side, side)];
        g_ball.layer.cornerRadius = side / 2;
        g_ball.clipsToBounds = YES;
        g_ball.backgroundColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.85 alpha:0.92];
        g_ball.userInteractionEnabled = YES;
        [g_ball addGestureRecognizer:[[UITapGestureRecognizer alloc]
            initWithTarget:[KSTarget shared] action:@selector(tap)]];
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
            initWithTarget:[KSTarget shared] action:@selector(pan:)];
        pan.cancelsTouchesInView = NO;
        [g_ball addGestureRecognizer:pan];

        g_ballLabel = [[UILabel alloc] initWithFrame:g_ball.bounds];
        g_ballLabel.text = @"伪装";
        g_ballLabel.textColor = [UIColor whiteColor];
        g_ballLabel.font = [UIFont boldSystemFontOfSize:13];
        g_ballLabel.textAlignment = NSTextAlignmentCenter;
        [g_ball addSubview:g_ballLabel];
        [g_ballWin.rootViewController.view addSubview:g_ball];

        CGFloat w = MIN(340, screen.size.width - 24);
        CGFloat h = MIN(470, screen.size.height * 0.62);
        g_panelWin = [[UIWindow alloc] initWithFrame:CGRectMake((screen.size.width - w) / 2,
                                                                (screen.size.height - h) / 2, w, h)];
        if (@available(iOS 13.0, *)) { if (scene) g_panelWin.windowScene = scene; }
        g_panelWin.windowLevel = UIWindowLevelAlert + 99;
        g_panelWin.backgroundColor = [UIColor clearColor];
        g_panelWin.rootViewController = [UIViewController new];
        g_panelWin.hidden = YES;

        UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, h)];
        panel.backgroundColor = [UIColor colorWithWhite:0.05 alpha:0.94];
        panel.layer.cornerRadius = 12;
        panel.clipsToBounds = YES;
        [g_panelWin.rootViewController.view addSubview:panel];

        g_text = [[UITextView alloc] initWithFrame:CGRectMake(10, 10, w - 20, h - 118)];
        g_text.backgroundColor = [UIColor clearColor];
        g_text.textColor = [UIColor whiteColor];
        g_text.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
        g_text.editable = NO;
        g_text.selectable = YES;
        g_text.text = KSDashboard();
        [panel addSubview:g_text];

        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(10, h - 52, w - 20, 42);
        [btn setTitle:@"一键随机" forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
        btn.backgroundColor = [UIColor colorWithRed:0.10 green:0.55 blue:0.85 alpha:1];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        btn.layer.cornerRadius = 8;
        [btn addTarget:[KSTarget shared] action:@selector(randomize) forControlEvents:UIControlEventTouchUpInside];
        [panel addSubview:btn];

        CGFloat half = (w - 30) / 2;
        UIButton *btnLog = [UIButton buttonWithType:UIButtonTypeSystem];
        btnLog.frame = CGRectMake(10, h - 100, half, 40);
        [btnLog setTitle:@"查看抓包" forState:UIControlStateNormal];
        btnLog.titleLabel.font = [UIFont boldSystemFontOfSize:15];
        btnLog.backgroundColor = [UIColor colorWithRed:0.55 green:0.35 blue:0.10 alpha:1];
        [btnLog setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        btnLog.layer.cornerRadius = 8;
        [btnLog addTarget:[KSTarget shared] action:@selector(viewLog) forControlEvents:UIControlEventTouchUpInside];
        [panel addSubview:btnLog];

        UIButton *btnDash = [UIButton buttonWithType:UIButtonTypeSystem];
        btnDash.frame = CGRectMake(20 + half, h - 100, half, 40);
        [btnDash setTitle:@"返回状态" forState:UIControlStateNormal];
        btnDash.titleLabel.font = [UIFont boldSystemFontOfSize:15];
        btnDash.backgroundColor = [UIColor colorWithWhite:0.25 alpha:1];
        [btnDash setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        btnDash.layer.cornerRadius = 8;
        [btnDash addTarget:[KSTarget shared] action:@selector(viewDash) forControlEvents:UIControlEventTouchUpInside];
        [panel addSubview:btnDash];
    } @catch (NSException *e) {}
}

__attribute__((constructor))
static void KSInit(void) {
    @autoreleasepool {
        @try {
            NSString *bid = [NSBundle mainBundle].bundleIdentifier ?: @"";
            NSString *low = bid.lowercaseString;
            if (!([low containsString:@"kuaishou"] ||
                  [low containsString:@"jiangjia"] ||
                  [low containsString:@"kwai"])) return;
            KSReloadConfig();
            if (!g_cfg) g_cfg = @{};
            if (!g_mut) g_mut = [NSMutableDictionary dictionary];
            if (!cfgBool(@"enabled", YES)) return;
            // hook 必须最早装：快手启动早期就会读设备名/机型并缓存上报
            KSInstallHooks();
            // UI 需要等 window scene 就绪，延迟装
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                KSInstallUI();
            });
        } @catch (NSException *e) {}
    }
}
