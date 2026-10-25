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
    g_cfg = [NSDictionary dictionaryWithContentsOfFile:KSConfigPath()] ?: @{};
    g_mut = [g_cfg mutableCopy];
}

static void KSSaveConfig(void) {
    if (!g_mut) return;
    [g_mut writeToFile:KSConfigPath() atomically:YES];
    g_cfg = [g_mut copy];
}

#pragma mark - 随机身份

static const char *kMachines[] = {
    "iPhone14,5", "iPhone15,2", "iPhone15,3", "iPhone16,1", "iPhone16,2",
    "iPhone13,2", "iPhone13,3", "iPhone14,2", "iPhone12,1",
};
static const char *kModels[] = {
    "D79AP", "D73AP", "D63AP", "D53gAP", "D54pAP",
    "D52gAP", "D53gAP", "D53pAP", "N104AP",
};

static NSString *KSRandomHex(int n) {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < n; i++) {
        [s appendFormat:@"%x", arc4random_uniform(16)];
    }
    return s;
}

static void KSRandomizeIdentity(void) {
    int i = arc4random_uniform(sizeof(kMachines) / sizeof(kMachines[0]));
    g_mut[@"hwMachine"] = [NSString stringWithUTF8String:kMachines[i]];
    g_mut[@"hwModel"] = [NSString stringWithUTF8String:kModels[i]];
    static const char *vers[] = {"17.0.1", "17.0.2", "17.1", "16.6.1", "16.7"};
    static const char *builds[] = {"21A340", "21A351", "21B80", "20G81", "20H18"};
    int vi = arc4random_uniform(5);
    g_mut[@"systemVersion"] = [NSString stringWithUTF8String:vers[vi]];
    g_mut[@"systemBuild"] = [NSString stringWithUTF8String:builds[vi]];
    g_mut[@"deviceName"] = @"iPhone";
    static const int mems[] = {4096, 6144, 8192};   // 单位 MB
    g_mut[@"memoryMB"] = @(mems[arc4random_uniform(3)]);
    static const int disks[] = {128, 256, 512};
    g_mut[@"diskGB"] = @(disks[arc4random_uniform(3)]);
    // 安装时间也重置：下次读取时重新生成「今天随机时刻」
    g_mut[@"installTimeMs"] = @0;
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
    struct bds_rebinding rb[] = {
        {"sysctlbyname", (void *)ks_sysctlbyname, (void **)&o_sysctlbyname},
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
        @"机型: %@ (%@)\n"
        @"系统: %@ (%@)\n"
        @"内存: %lld MB\n"
        @"磁盘: %lld GB\n"
        @"开关: %@\n"
        @"安装时间: %@\n"
        @"安装状态: %@\n\n"
        @"点「一键随机」生成全新身份\n改完重启快手生效",
        cfgStr(@"hwMachine", @"-"),
        cfgStr(@"hwModel", @"-"),
        cfgStr(@"systemVersion", @"-"),
        cfgStr(@"systemBuild", @"-"),
        cfgInt(@"memoryMB", 0),
        cfgInt(@"diskGB", 0),
        cfgBool(@"enabled", YES) ? @"开" : @"关",
        KSInstallTimeText(),
        (g_installHits && g_installHits.count)
            ? [g_installHits componentsJoinedByString:@", "] : @"(未 hook 到)"];
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
        CGFloat h = MIN(400, screen.size.height * 0.5);
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

        g_text = [[UITextView alloc] initWithFrame:CGRectMake(10, 10, w - 20, h - 70)];
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
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                KSInstallHooks();
                KSInstallUI();
            });
        } @catch (NSException *e) {}
    }
}
