//
//  hmcleaner-standalone.m
//  HMCleaner —— 河马剧场 (com.cbn.hmjc) 独立外部清理工具（RootHide / root CLI）1.1.4
//  1.1.4 按 Codex 第五轮只读复审修复：
//   - 新增 hm_pathClass 锚定容器根做整条路径四态分类（干净缺失/真实目录/不安全/I-O错误），
//     Crane 入口不再"safeWithin 失败后二次 lstat 吞错"，I/O 与中间层链接一律计失败；
//     wipeAll/wipeIDs/偏好全部改用同一分类，消除分散判断；
//   - 失败提示如实说明：普通文件删除无逐个备份、不可恢复，仅偏好 plist 与钥匙串有容器外备份。
//

#import <Foundation/Foundation.h>
#import <sqlite3.h>
#import <unistd.h>
#import <signal.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <errno.h>

static NSString * const kTargetBundleID = @"com.cbn.hmjc";
static NSString * const kKeychainGroup = @"WU3L875P4M.com.cbn.hmjc";

#pragma mark - RootHide 路径展开

static NSArray<NSString *> *hm_expand(NSString *logical) {
    NSMutableArray *out = [NSMutableArray array];
    typedef const char *(*fn_t)(const char *);
    fn_t jbroot = (fn_t)dlsym(RTLD_DEFAULT, "jbroot");
    fn_t rootfs = (fn_t)dlsym(RTLD_DEFAULT, "rootfs");
    if (jbroot) { const char *p = jbroot(logical.UTF8String); if (p&&*p) [out addObject:[NSString stringWithUTF8String:p]]; }
    if (rootfs) { const char *p = rootfs(logical.UTF8String); if (p&&*p) [out addObject:[NSString stringWithUTF8String:p]]; }
    const char *env = getenv("JBRootPath");
    if (env && *env) [out addObject:[[NSString stringWithUTF8String:env] stringByAppendingString:logical]];
    [out addObject:logical];
    [out addObject:[@"/var/jb" stringByAppendingString:logical]];
    [out addObject:[@"/rootfs" stringByAppendingString:logical]];
    return out;
}

static NSString *hm_firstExisting(NSString *logical, BOOL dir) {
    for (NSString *p in hm_expand(logical)) {
        BOOL isDir = NO;
        if ([[NSFileManager defaultManager] fileExistsAtPath:p isDirectory:&isDir] && isDir == dir) return p;
    }
    return nil;
}

#pragma mark - 路径安全

// child 必须位于 root 内；root 自身与逐级路径都必须存在且非符号链接。
// 末级不存在视为安全（本来就无需删除）。
// 锚定 root 的整条路径分类（1.1.4，取代"safeWithin+dirClass 分开判断"以避免吞错）：
//  0 = 链上各级都是真实目录、末级不存在（干净缺失）
//  1 = 末级为真实目录（干净存在）
//  2 = 不安全：任一级是符号链接/非目录、越界、中间级缺失
//  3 = I/O 错误（lstat 失败且非 ENOENT）
static BOOL hm_sameOrDescendant(NSString *root, NSString *child) {
    if ([child isEqualToString:root]) return YES;
    NSString *prefix = [root isEqualToString:@"/"] ? @"/" : [root stringByAppendingString:@"/"];
    return [child hasPrefix:prefix];
}

static int hm_pathClass(NSString *root, NSString *child) {
    NSString *r = root.stringByStandardizingPath;
    NSString *c = child.stringByStandardizingPath;
    if (!hm_sameOrDescendant(r, c)) return 2;
    struct stat rst;
    if (lstat(r.UTF8String, &rst) != 0) return (errno == ENOENT) ? 2 : 3;
    if (S_ISLNK(rst.st_mode) || !S_ISDIR(rst.st_mode)) return 2;
    NSString *rel = [c substringFromIndex:r.length];
    NSString *cur = r;
    NSArray *parts = rel.pathComponents;
    for (NSUInteger i = 0; i < parts.count; i++) {
        NSString *part = parts[i];
        if ([part isEqualToString:@"/"] || part.length == 0) continue;
        cur = [cur stringByAppendingPathComponent:part];
        BOOL leaf = (i == parts.count - 1);
        struct stat st;
        if (lstat(cur.UTF8String, &st) != 0) {
            if (errno == ENOENT) return leaf ? 0 : 2; // 中间级缺失属异常=不安全
            return 3;
        }
        if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode)) return 2;
    }
    return 1;
}

static BOOL hm_safeWithin(NSString *root, NSString *child) {
    NSString *r = root.stringByStandardizingPath;
    NSString *c = child.stringByStandardizingPath;
    if (!hm_sameOrDescendant(r, c)) return NO;
    if ([c isEqualToString:r]) return hm_pathClass(r, c) == 1;

    // hm_pathClass 的末级必须是目录；这里只用它校验父链，
    // 待处理末级则允许普通文件或目录，但仍拒绝符号链接。
    NSString *parent = c.stringByDeletingLastPathComponent;
    if (hm_pathClass(r, parent) != 1) return NO;
    struct stat st;
    if (lstat(c.UTF8String, &st) != 0) return errno == ENOENT;
    return !S_ISLNK(st.st_mode);
}

// 存在且是非链接目录
static BOOL hm_realDir(NSString *p) {
    struct stat st;
    if (lstat(p.UTF8String, &st) != 0) return NO;
    return S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode);
}

#pragma mark - 进程（失败即停）

typedef int (*hm_proc_pidpath_fn)(int pid, void *buffer, uint32_t buffersize);

static hm_proc_pidpath_fn hm_procPidPathFunction(void) {
    static hm_proc_pidpath_fn fn;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ fn = (hm_proc_pidpath_fn)dlsym(RTLD_DEFAULT, "proc_pidpath"); });
    return fn;
}

static NSDictionary<NSNumber *, NSString *> *hm_allProcessPaths(BOOL *ok) {
    *ok = YES;
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    hm_proc_pidpath_fn procPidPath = hm_procPidPathFunction();
    if (!procPidPath) { *ok = NO; return out; }
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t need = 0;
    if (sysctl(mib, 4, NULL, &need, NULL, 0) < 0) { *ok = NO; return out; }
    for (int attempt = 0; attempt < 3; attempt++) {
        struct kinfo_proc *procs = malloc(need);
        if (!procs) { *ok = NO; return out; }
        size_t len = need;
        int rc = sysctl(mib, 4, procs, &len, NULL, 0);
        if (rc == 0) {
            size_t cnt = len / sizeof(struct kinfo_proc);
            char pb[4096];
            for (size_t i = 0; i < cnt; i++) {
                pid_t pid = procs[i].kp_proc.p_pid;
                int n = procPidPath(pid, pb, sizeof(pb));
                if (n > 0) out[@(pid)] = [NSString stringWithUTF8String:pb];
            }
            free(procs);
            return out;
        }
        free(procs);
        if (errno != ENOMEM) { *ok = NO; return out; }
        need *= 2;
    }
    *ok = NO;
    return out;
}

static NSString *hm_bundleIDForExe(NSString *exePath) {
    NSString *appDir = [exePath stringByDeletingLastPathComponent];
    if (![appDir.pathExtension isEqualToString:@"app"]) return nil;
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                          [appDir stringByAppendingPathComponent:@"Info.plist"]];
    id v = info[@"CFBundleIdentifier"];
    return [v isKindOfClass:[NSString class]] ? v : nil;
}

static BOOL hm_isTargetBid(NSString *bid) {
    if (!bid) return NO;
    NSString *b = bid.lowercaseString;
    return [b isEqualToString:kTargetBundleID] ||
           [b hasPrefix:[kTargetBundleID stringByAppendingString:@"."]];
}

static NSArray<NSNumber *> *hm_targetPIDs(NSDictionary<NSNumber *,NSString *> *procs) {
    NSMutableArray *pids = [NSMutableArray array];
    [procs enumerateKeysAndObjectsUsingBlock:^(NSNumber *pid, NSString *path, BOOL *stop) {
        if (hm_isTargetBid(hm_bundleIDForExe(path))) [pids addObject:pid];
    }];
    return pids;
}

static void hm_killByName(const char *comm) {
    BOOL ok;
    NSDictionary *procs = hm_allProcessPaths(&ok);
    if (!ok) return;
    [procs enumerateKeysAndObjectsUsingBlock:^(NSNumber *pid, NSString *path, BOOL *stop) {
        if ([path.lastPathComponent isEqualToString:[NSString stringWithUTF8String:comm]]) {
            if (kill(pid.intValue, SIGKILL) == 0)
                printf("  -> 重启 %s pid=%d\n", comm, pid.intValue);
        }
    }];
}

static BOOL hm_killTargetApp(void) {
    BOOL ok;
    NSDictionary *procs = hm_allProcessPaths(&ok);
    if (!ok) { printf("[!] 进程枚举失败，停止操作\n"); return NO; }
    NSArray *pids = hm_targetPIDs(procs);
    for (NSNumber *p in pids) if (kill(p.intValue, SIGTERM) == 0) printf("  -> SIGTERM pid=%d\n", p.intValue);
    if (pids.count) {
        usleep(800 * 1000);
        procs = hm_allProcessPaths(&ok);
        if (!ok) { printf("[!] 进程枚举失败，停止操作\n"); return NO; }
        for (NSNumber *p in hm_targetPIDs(procs))
            if (kill(p.intValue, SIGKILL) == 0) printf("  -> SIGKILL pid=%d\n", p.intValue);
        usleep(400 * 1000);
        procs = hm_allProcessPaths(&ok);
        if (!ok) { printf("[!] 进程枚举失败，停止操作\n"); return NO; }
        NSArray *left = hm_targetPIDs(procs);
        if (left.count) {
            printf("[!] 目标进程仍存在：");
            for (NSNumber *p in left) printf(" %d", p.intValue);
            printf("，停止操作（请手动从后台划掉后重试）\n");
            return NO;
        }
    }
    return YES;
}

#pragma mark - 容器发现（锚定容器根逐级校验）

static NSString *hm_containerBid(NSString *root) {
    NSString *meta = [root stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:meta];
    id v = d[@"MCMMetadataIdentifier"];
    return [v isKindOfClass:[NSString class]] ? v : nil;
}

static void hm_collectCrane(NSString *dir, NSMutableArray<NSString *> *out, NSUInteger *failures) {
    if (!hm_realDir(dir)) { (*failures)++; return; }
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *e = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:dir error:&e];
    if (!items) { printf("  [!] 枚举失败 %s: %s\n", dir.UTF8String, e.localizedDescription.UTF8String); (*failures)++; return; }
    for (NSString *it in items) {
        if (*failures) return;
        NSString *p = [dir stringByAppendingPathComponent:it];
        if (!hm_safeWithin(dir, p)) { printf("  [!] 拒绝越界/符号链接: %s\n", p.UTF8String); (*failures)++; continue; }
        struct stat cst;
        if (lstat(p.UTF8String, &cst) != 0) {
            printf("  [!] lstat 失败: %s\n", p.UTF8String); (*failures)++; continue;
        }
        if (S_ISLNK(cst.st_mode)) { printf("  [!] 符号链接: %s\n", p.UTF8String); (*failures)++; continue; }
        if (!S_ISDIR(cst.st_mode)) continue; // 普通文件（plist/数据库等）正常跳过，不计失败
        BOOL hasDocs = [fm fileExistsAtPath:[p stringByAppendingPathComponent:@"Documents"]],
             hasLib  = [fm fileExistsAtPath:[p stringByAppendingPathComponent:@"Library"]];
        if (hasDocs || hasLib) [out addObject:p];
        hm_collectCrane(p, out, failures);
    }
}

static NSArray<NSString *> *hm_findContainers(NSUInteger *failures) {
    NSString *root = hm_firstExisting(@"/var/mobile/Containers/Data/Application", YES);
    if (!root) { printf("[!] 找不到数据容器根目录\n"); *failures += 1; return nil; }
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *e = nil;
    NSArray *dirs = [fm contentsOfDirectoryAtPath:root error:&e];
    if (!dirs) { printf("[!] 枚举容器根失败: %s\n", e.localizedDescription.UTF8String); *failures += 1; return nil; }
    NSMutableArray<NSString *> *primaries = [NSMutableArray array];
    NSMutableArray<NSString *> *cranes = [NSMutableArray array];
    for (NSString *name in dirs) {
        NSString *c = [root stringByAppendingPathComponent:name];
        if (!hm_safeWithin(root, c) || !hm_realDir(c)) continue;
        if (![[hm_containerBid(c) lowercaseString] isEqualToString:kTargetBundleID]) continue;
        [primaries addObject:c];
        // 锚定容器根，逐级校验 c → Library → ___Crane_Containers（1.1.4：失败不再被吞）
        NSString *craneRoot = [c stringByAppendingPathComponent:@"Library/___Crane_Containers"];
        int pc = hm_pathClass(c, craneRoot);
        if (pc == 2 || pc == 3) {
            printf("  [!] Crane 路径不安全/读取失败(%d): %s\n", pc, craneRoot.UTF8String);
            (*failures)++; continue;
        }
        if (pc == 1) hm_collectCrane(craneRoot, cranes, failures);
    }
    NSMutableArray *ordered = [NSMutableArray array];
    [ordered addObjectsFromArray:cranes];
    [ordered addObjectsFromArray:primaries];
    return ordered;
}

#pragma mark - 删除（失败计数、即时中止）

static BOOL hm_matchResidue(NSString *name) {
    static NSSet *exact;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        exact = [NSSet setWithArray:@[@".PID4SM.txt", @"FP_SEQ.txt", @"come2", @"PdnuLKiM",
            @"zxsdkcache", @"zxdatabase.sqlite", @"mh_data_ura.dat", @"adLocalCacheFile.plist",
            @"TSStubbingSessions", @"na_extend_res", @".UTSystemConfig", @"mmkv"]];
    });
    if ([exact containsObject:name]) return YES;
    if ([name hasPrefix:@"noah_"]) return YES;
    return NO;
}

static BOOL hm_remove(NSString *root, NSString *target, NSFileManager *fm, NSUInteger *failures) {
    if (!hm_safeWithin(root, target)) {
        printf("  [!] 拒绝越界/符号链接路径: %s\n", target.UTF8String); (*failures)++; return NO;
    }
    BOOL exists = NO;
    if (![fm fileExistsAtPath:target isDirectory:&exists]) return YES;
    NSError *e = nil;
    if ([fm removeItemAtPath:target error:&e]) {
        printf("  - 删除 %s\n", target.lastPathComponent.UTF8String); return YES;
    }
    printf("  [!] 删除失败 %s : %s\n", target.UTF8String, e.localizedDescription.UTF8String);
    (*failures)++; return NO;
}

static void hm_wipeAll(NSString *c, NSFileManager *fm, NSUInteger *failures) {
    for (NSString *t in @[@"Documents", @"Library", @"tmp"]) {
        if (*failures) return;
        NSString *dir = [c stringByAppendingPathComponent:t];
        int pc = hm_pathClass(c, dir);
        if (pc == 0) continue;
        if (pc != 1) {
            printf("  [!] %s 不安全/读取失败(%d)，拒绝处理\n", t.UTF8String, pc); (*failures)++; continue;
        }
        NSError *e = nil;
        NSArray *items = [fm contentsOfDirectoryAtPath:dir error:&e];
        if (!items) { printf("  [!] 枚举 %s 失败: %s\n", t.UTF8String, e.localizedDescription.UTF8String); (*failures)++; continue; }
        for (NSString *it in items) {
            if (*failures) return;
            if ([t isEqualToString:@"Library"] && [it isEqualToString:@"___Crane_Containers"]) continue;
            hm_remove(c, [dir stringByAppendingPathComponent:it], fm, failures);
        }
    }
}

#pragma mark - 容器外备份目录（逐级校验，只 chown 新建目录）

static NSString *hm_backupRoot(NSUInteger *failures) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *base = nil;
    for (NSString *cand in hm_expand(@"/var/mobile/Library/Application Support")) {
        struct stat st;
        if (lstat(cand.UTF8String, &st) == 0 && S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) { base = cand; break; }
    }
    if (!base) { printf("  [!] 找不到真实的 Application Support 目录\n"); if (failures) (*failures)++; return nil; }
    NSString *hmDir = [base stringByAppendingPathComponent:@"HMCleaner"];
    NSString *full = [hmDir stringByAppendingPathComponent:@"Backups"];
    NSMutableArray<NSString *> *created = [NSMutableArray array];
    for (NSString *d in @[hmDir, full]) {
        struct stat st;
        if (lstat(d.UTF8String, &st) == 0) {
            if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode)) {
                printf("  [!] 备份路径被占用且不安全: %s\n", d.UTF8String); if (failures) (*failures)++; return nil;
            }
        } else if (errno == ENOENT) {
            NSError *e = nil;
            if (![fm createDirectoryAtPath:d withIntermediateDirectories:NO
                               attributes:@{NSFilePosixPermissions:@(0700)} error:&e]) {
                printf("  [!] 备份目录创建失败 %s: %s\n", d.UTF8String, e.localizedDescription.UTF8String);
                if (failures) (*failures)++; return nil;
            }
            [created addObject:d];
        } else {
            if (failures) (*failures)++; return nil;
        }
    }
    if (chmod(full.UTF8String, 0700) != 0) {
        printf("  [!] 备份目录 chmod 失败: %s\n", strerror(errno)); if (failures) (*failures)++; return nil;
    }
    for (NSString *d in created) {
        if (lchown(d.UTF8String, 501, 501) != 0) {
            printf("  [!] 新建备份目录属主设置失败 %s: %s\n", d.UTF8String, strerror(errno));
            if (failures) (*failures)++; return nil;
        }
    }
    return full;
}

#pragma mark - 偏好键（锚定容器根；备份失败即跳过）

static BOOL hm_matchPrefKey(NSString *key) {
    static NSSet *exact;
    static NSArray *prefix;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        exact = [NSSet setWithArray:@[@"nbs_md", @"nbs_userId", @"nbs_tingyun_did", @"nbs_SDKVersion",
            @"UMATOKEN", @"UMENGIDFV", @"UMIDFA", @"UMINSOURCETOKEN", @"UMRESETTOKEN", @"UTDID",
            @"OpenUDID", @"CSJLocalDeviceID", @"FLink_IDFA", @"FLink_IDFV", @"csj_sd_token",
            @"KS_OUTERID_AD_KEY", @"KS_CLONE_AD_KEY", @"com.kuaishou.ksadsdk.egid",
            @"egidtime", @"devicesig", @"deviceModel", @"com.ksad.device.deviceId",
            @"weapon_env", @"SASessionModel"]];
        prefix = @[@"__turingshield_", @"108078.com.tencent.TuringShield.",
                   @"com.turingshield.", @"nbs_"];
    });
    if ([exact containsObject:key]) return YES;
    for (NSString *p in prefix) if ([key hasPrefix:p]) return YES;
    return NO;
}

static void hm_cleanPreferences(NSString *c, NSString *containerTag,
                               NSString *backupRoot, NSFileManager *fm, NSUInteger *failures) {
    NSString *prefDir = [c stringByAppendingPathComponent:@"Library/Preferences"];
    int ppc = hm_pathClass(c, prefDir); // 锚定容器根逐级校验
    if (ppc == 0) return;                               // 本就没有偏好目录
    if (ppc != 1) { printf("  [!] Preferences 不安全/读取失败(%d)，跳过并计数\n", ppc); (*failures)++; return; }
    NSError *le = nil;
    NSArray *names = [fm contentsOfDirectoryAtPath:prefDir error:&le];
    if (!names) { printf("  [!] 枚举 Preferences 失败: %s\n", le.localizedDescription.UTF8String); (*failures)++; return; }
    for (NSString *name in names) {
        if (*failures) return;
        if (![name hasSuffix:@".plist"]) continue;
        NSString *path = [prefDir stringByAppendingPathComponent:name];
        if (!hm_safeWithin(c, path)) { (*failures)++; continue; }
        NSDictionary *attr = [fm attributesOfItemAtPath:path error:nil];
        if (!attr) { printf("  [!] 读不到属性，跳过 %s\n", name.UTF8String); (*failures)++; continue; }
        NSData *data = [NSData dataWithContentsOfFile:path];
        if (!data) { printf("  [!] 读取失败，跳过 %s\n", name.UTF8String); (*failures)++; continue; }
        NSPropertyListFormat origFmt = NSPropertyListBinaryFormat_v1_0;
        NSError *parseErr = nil;
        id plist = [NSPropertyListSerialization propertyListWithData:data
                                        options:NSPropertyListMutableContainersAndLeaves
                                         format:&origFmt error:&parseErr];
        if (!plist) {
            // 解析失败（损坏 plist）属不确定，计数中止；不静默当正常跳过
            printf("  [!] plist 解析失败，跳过并计数 %s: %s\n",
                   name.UTF8String, parseErr.localizedDescription.UTF8String);
            (*failures)++; continue;
        }
        if (![plist isKindOfClass:[NSMutableDictionary class]]) continue; // 合法非字典 plist 正常跳过
        NSMutableDictionary *d = (NSMutableDictionary *)plist;
        NSMutableArray *kill = [NSMutableArray array];
        for (NSString *k in d.allKeys) if (hm_matchPrefKey(k)) [kill addObject:k];
        if (!kill.count) continue;
        // 只清洗文件名组件，再拼到容器外备份目录（绝不对完整路径替换 /）
        NSString *fname = [NSString stringWithFormat:@"%@.%@.%d.bak",
                           containerTag, name, (int)[[NSDate date] timeIntervalSince1970]];
        fname = [fname stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
        NSString *bak = [backupRoot stringByAppendingPathComponent:fname];
        NSError *bkErr = nil;
        if (![fm copyItemAtPath:path toPath:bak error:&bkErr]) {
            printf("  [!] 备份失败，保持原文件不动 %s: %s\n", name.UTF8String, bkErr.localizedDescription.UTF8String);
            (*failures)++; continue;
        }
        [d removeObjectsForKeys:kill];
        NSError *wErr = nil;
        NSData *out = [NSPropertyListSerialization dataWithPropertyList:d format:origFmt options:0 error:&wErr];
        if (!out || ![out writeToFile:path options:NSDataWritingAtomic error:&wErr]) {
            printf("  [!] 写回失败 %s: %s（可用备份恢复）\n", name.UTF8String, wErr.localizedDescription.UTF8String);
            (*failures)++; continue;
        }
        NSNumber *uidN = attr[NSFileOwnerAccountID], *gidN = attr[NSFileGroupOwnerAccountID];
        uid_t uid = uidN ? uidN.unsignedIntValue : 501;
        gid_t gid = gidN ? gidN.unsignedIntValue : 501;
        if (lchown(path.UTF8String, uid, gid) != 0) {
            printf("  [!] 属主恢复失败 %s: %s\n", name.UTF8String, strerror(errno)); (*failures)++;
        }
        NSNumber *modeN = attr[NSFilePosixPermissions];
        if (modeN && chmod(path.UTF8String, modeN.unsignedShortValue) != 0) {
            printf("  [!] 权限恢复失败 %s: %s\n", name.UTF8String, strerror(errno)); (*failures)++;
        }
        printf("  - %s 清除偏好键 %lu 个（备份于容器外）\n", name.UTF8String, (unsigned long)kill.count);
    }
}

static void hm_wipeIDs(NSString *c, NSString *tag, NSString *backupRoot,
                       NSFileManager *fm, NSUInteger *failures) {
    NSString *docs = [c stringByAppendingPathComponent:@"Documents"];
    int dpc = hm_pathClass(c, docs);
    if (dpc == 2 || dpc == 3) { (*failures)++; return; }
    if (dpc == 1) {
        NSError *e = nil;
        NSArray *its = [fm contentsOfDirectoryAtPath:docs error:&e];
        if (!its) {
            printf("  [!] 枚举 Documents 失败: %s\n", e.localizedDescription.UTF8String);
            (*failures)++; return; // 立即中止，不再执行后续段
        }
        for (NSString *it in its) {
            if (*failures) return;
            if (hm_matchResidue(it)) hm_remove(c, [docs stringByAppendingPathComponent:it], fm, failures);
        }
    }
    if (*failures) return; // 段间拦截
    hm_remove(c, [c stringByAppendingPathComponent:@"Library/Caches/NBSCache"], fm, failures);
    if (*failures) return;

    NSString *asup = [c stringByAppendingPathComponent:@"Library/Application Support"];
    int apc = hm_pathClass(c, asup);
    if (apc == 2 || apc == 3) { (*failures)++; return; }
    if (apc == 1) {
        NSError *e = nil;
        NSArray *its = [fm contentsOfDirectoryAtPath:asup error:&e];
        if (!its) { (*failures)++; return; }
        for (NSString *it in its) {
            if (*failures) return;
            if ([it hasPrefix:@"com.kuaishou.security"] || [it isEqualToString:@".iphonems"])
                hm_remove(c, [asup stringByAppendingPathComponent:it], fm, failures);
        }
    }
    if (*failures) return; // 段间拦截
    NSString *libRoot = [c stringByAppendingPathComponent:@"Library"];
    int lpc = hm_pathClass(c, libRoot);
    if (lpc == 2 || lpc == 3) {
        printf("  [!] Library 不安全/读取失败(%d)，跳过并计数\n", lpc);
        (*failures)++; return;
    }
    if (lpc == 1)
        hm_remove(c, [libRoot stringByAppendingPathComponent:@".iphonems"], fm, failures);
    if (*failures) return;
    hm_cleanPreferences(c, tag, backupRoot, fm, failures);
}

#pragma mark - 钥匙串

static int hm_sqliteBackup(const char *srcPath, const char *dstPath) {
    sqlite3 *src = NULL, *dst = NULL;
    int rc = -1;
    do {
        if (sqlite3_open(srcPath, &src) != SQLITE_OK) break;
        if (sqlite3_open(dstPath, &dst) != SQLITE_OK) break;
        sqlite3_backup *bk = sqlite3_backup_init(dst, "main", src, "main");
        if (!bk) break;
        int step = sqlite3_backup_step(bk, -1);
        int fin = sqlite3_backup_finish(bk);
        if (step == SQLITE_DONE && fin == SQLITE_OK) rc = 0;
    } while (0);
    if (src) sqlite3_close(src);
    if (dst) sqlite3_close(dst);
    return rc;
}

static int hm_exec0(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) { printf("  [!] SQL 失败: %s (%s)\n", sql, err); sqlite3_free(err); }
    return rc;
}

static int hm_cleanKeychain(NSUInteger *failures) {
    NSString *dbPath = nil;
    for (NSString *logical in @[@"/private/var/Keychains/keychain-2.db",
                                @"/var/Keychains/keychain-2.db",
                                @"/var/mobile/Keychains/keychain-2.db"]) {
        dbPath = hm_firstExisting(logical, NO);
        if (dbPath) break;
    }
    if (!dbPath) { printf("[!] 找不到 keychain-2.db，钥匙串未清理\n"); return 1; }
    NSString *bakDir = hm_backupRoot(failures);
    if (!bakDir) { printf("[!] 备份目录不可用，中止钥匙串清理\n"); return 1; }
    NSString *bak = [bakDir stringByAppendingPathComponent:
                     [NSString stringWithFormat:@"keychain-2.%d.bak", (int)[[NSDate date] timeIntervalSince1970]]];
    if (hm_sqliteBackup(dbPath.UTF8String, bak.UTF8String) != 0) {
        printf("[!] 钥匙串一致性备份失败，中止删除（目标: %s）\n", bak.UTF8String);
        return 1;
    }
    printf("  -> 一致性备份: %s\n", bak.UTF8String);

    sqlite3 *db = NULL;
    if (sqlite3_open(dbPath.UTF8String, &db) != SQLITE_OK) {
        printf("[!] keychain-2.db 打开失败: %s\n", sqlite3_errmsg(db));
        if (db) sqlite3_close(db); return 1;
    }
    sqlite3_busy_timeout(db, 5000);
    int abortFlag = 0, total = 0;
    if (hm_exec0(db, "PRAGMA wal_checkpoint(TRUNCATE);") != 0) abortFlag = 1;
    if (!abortFlag && hm_exec0(db, "BEGIN IMMEDIATE;") != 0) abortFlag = 1;

    NSArray *tables = @[@"genp", @"inet", @"keys", @"cert"];
    if (!abortFlag) {
        for (NSString *tbl in tables) {
            sqlite3_stmt *chk = NULL;
            BOOL hasAgrp = NO;
            if (sqlite3_prepare_v2(db, [[NSString stringWithFormat:@"PRAGMA table_info(%@);", tbl] UTF8String],
                                   -1, &chk, NULL) == SQLITE_OK) {
                while (sqlite3_step(chk) == SQLITE_ROW) {
                    const unsigned char *col = sqlite3_column_text(chk, 1);
                    if (col && strcmp((const char *)col, "agrp") == 0) hasAgrp = YES;
                }
            }
            sqlite3_finalize(chk);
            if (!hasAgrp) continue;
            sqlite3_stmt *sy = NULL;
            if (sqlite3_prepare_v2(db, [[NSString stringWithFormat:
                @"SELECT COUNT(*) FROM %@ WHERE (agrp=?1 OR agrp LIKE ?2) AND sync=1;", tbl] UTF8String],
                -1, &sy, NULL) == SQLITE_OK) {
                sqlite3_bind_text(sy, 1, kKeychainGroup.UTF8String, -1, SQLITE_TRANSIENT);
                NSString *like = [NSString stringWithFormat:@"%%%@", kTargetBundleID];
                sqlite3_bind_text(sy, 2, like.UTF8String, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(sy) == SQLITE_ROW && sqlite3_column_int(sy, 0) > 0)
                    printf("  ! 表 %s 含 %d 条 iCloud 可同步项，若开 iCloud 钥匙串可能回补\n",
                           tbl.UTF8String, sqlite3_column_int(sy, 0));
            }
            sqlite3_finalize(sy);

            sqlite3_stmt *st = NULL;
            const char *del = [[NSString stringWithFormat:
                @"DELETE FROM %@ WHERE agrp = ?1 OR agrp LIKE ?2;", tbl] UTF8String];
            if (sqlite3_prepare_v2(db, del, -1, &st, NULL) != SQLITE_OK) {
                printf("  [!] %s 准备失败: %s\n", tbl.UTF8String, sqlite3_errmsg(db)); abortFlag = 1; break;
            }
            sqlite3_bind_text(st, 1, kKeychainGroup.UTF8String, -1, SQLITE_TRANSIENT);
            NSString *like = [NSString stringWithFormat:@"%%%@", kTargetBundleID];
            sqlite3_bind_text(st, 2, like.UTF8String, -1, SQLITE_TRANSIENT);
            int step = sqlite3_step(st);
            if (step != SQLITE_DONE) {
                printf("  [!] %s 删除失败: %s\n", tbl.UTF8String, sqlite3_errmsg(db));
                sqlite3_finalize(st); abortFlag = 1; break;
            }
            int n = sqlite3_changes(db);
            total += n;
            printf("  - 表 %s 删除 %d 行\n", tbl.UTF8String, n);
            sqlite3_finalize(st);
        }
    }

    if (abortFlag) {
        hm_exec0(db, "ROLLBACK;");
        sqlite3_close(db);
        printf("[!] 钥匙串事务失败已回滚，未重启 securityd\n");
        return 1;
    }
    if (hm_exec0(db, "COMMIT;") != 0) {
        printf("[!] COMMIT 失败，中止\n"); sqlite3_close(db); return 1;
    }
    for (NSString *tbl in tables) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, [[NSString stringWithFormat:
            @"SELECT COUNT(*) FROM %@ WHERE agrp=?1 OR agrp LIKE ?2;", tbl] UTF8String],
            -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, kKeychainGroup.UTF8String, -1, SQLITE_TRANSIENT);
            NSString *like = [NSString stringWithFormat:@"%%%@", kTargetBundleID];
            sqlite3_bind_text(st, 2, like.UTF8String, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                int left = sqlite3_column_int(st, 0);
                if (left) printf("  [!] 表 %s 删后仍有 %d 行残留\n", tbl.UTF8String, left);
            }
        }
        sqlite3_finalize(st);
    }
    if (hm_exec0(db, "PRAGMA quick_check;") != SQLITE_OK)
        printf("  [!] quick_check 异常，请用备份检查\n");
    sqlite3_close(db);

    if (total == 0) printf("  -> 没有匹配访问组的条目（可能已清）\n");
    else printf("  -> 共删除 %d 行，重启 securityd 放弃缓存\n", total);
    hm_killByName("securityd");
    hm_killByName("cfprefsd");
    return 0;
}

#pragma mark - main

static void hm_usage(const char *argv0) {
    printf("HMCleaner 1.1.4 —— 河马剧场(com.cbn.hmjc) 外部清理\n");
    printf("用法（root；先杀进程并确认停止，任何不确定或失败立即中止）：\n");
    printf("  %s list       只列出匹配容器，不修改\n", argv0);
    printf("  %s all        清空全部容器数据(保留 Crane 结构) + 清钥匙串访问组\n", argv0);
    printf("  %s ids        只删已取证 ID 残留 + 清钥匙串访问组\n", argv0);
    printf("  %s keychain   只清钥匙串访问组\n", argv0);
    printf("备份统一放在容器外 /var/mobile/Library/Application Support/HMCleaner/Backups。\n");
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSString *mode = argc > 1 ? [NSString stringWithUTF8String:argv[1]] : @"all";
        if ([mode isEqualToString:@"-h"] || [mode isEqualToString:@"--help"]) { hm_usage(argv[0]); return 0; }
        if (geteuid() != 0) { printf("[!] 必须以 root 运行\n"); return 2; }
        BOOL dryRun=[mode isEqualToString:@"list"], doAll=[mode isEqualToString:@"all"],
             doIDs=[mode isEqualToString:@"ids"], doKC=[mode isEqualToString:@"keychain"];
        if (!dryRun && !doAll && !doIDs && !doKC) {
            printf("[!] 未知模式: %s\n", mode.UTF8String); hm_usage(argv[0]); return 2;
        }

        printf("== HMCleaner 模式: %s ==\n", mode.UTF8String);
        NSUInteger failures = 0;
        NSArray<NSString *> *containers = hm_findContainers(&failures);
        if (failures) { printf("[!] 容器发现阶段已出现失败，立即中止\n"); return 3; }
        if (!containers && !doKC) return 2;
        if (!containers) containers = @[];
        if (!containers.count && !doKC) {
            printf("[!] 没有找到 %s 的数据容器，为避免误操作中止\n", kTargetBundleID.UTF8String);
            return 2;
        }
        for (NSString *c in containers) printf("  容器: %s\n", c.UTF8String);
        if (dryRun) { printf("(list 模式不修改)\n"); return 0; }

        printf("[1] 结束目标 App 并确认停止\n");
        if (!hm_killTargetApp()) return 2;

        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *backupRoot = nil;
        if (doAll || doIDs) {
            backupRoot = hm_backupRoot(&failures);
            if (!backupRoot || failures) { printf("[!] 容器外备份目录不可用，中止\n"); return 3; }
            printf("  -> 备份目录: %s\n", backupRoot.UTF8String);
        }
        if (doAll) {
            printf("[2] 清空容器数据（Crane 副本先、主容器最后；保留 ___Crane_Containers）\n");
            for (NSString *c in containers) {
                if (failures) break;
                printf("  ## %s\n", c.UTF8String);
                hm_wipeAll(c, fm, &failures);
            }
        } else if (doIDs) {
            printf("[2] 定点删除 ID 残留\n");
            for (NSString *c in containers) {
                if (failures) break;
                printf("  ## %s\n", c.UTF8String);
                hm_wipeIDs(c, c.lastPathComponent, backupRoot, fm, &failures);
            }
        }
        if (failures) {
            printf("[!] 文件阶段出现 %lu 个失败/拒绝项，已立即中止，不继续清钥匙串。\n",
                   (unsigned long)failures);
            printf("    注意：已执行的普通文件/目录删除没有逐个备份、不可恢复；只有偏好 plist 和钥匙串在容器外有备份，请人工核对。\n");
            return 3;
        }
        if (doIDs) hm_killByName("cfprefsd"); // 全部成功后才重启偏好守护

        printf("[3] 清理钥匙串访问组 %s\n", kKeychainGroup.UTF8String);
        int rc = hm_cleanKeychain(&failures);
        if (rc == 0) printf("== 完成。换 IP 后冷启动河马再注册 ==\n");
        return rc;
    }
}
