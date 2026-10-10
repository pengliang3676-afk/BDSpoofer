// ─────────────────────────────────────────────────────────────────────────────
//  NetworkSpoofer.h —— 网络层伪装模块（自包含，可单独编译或并入宿主）
//
//  为什么需要它：
//    百度极速的网络诊断模块（NetEngine / BBANetwork*）会采集并上报这些网络指纹，
//    而插件原来只覆盖了「代理」一项，其余全是真实值：
//        localDnsServerList / localDnsServerUsed   本机 DNS 服务器
//        /etc/resolv.conf → nameserver             直接读文件
//        getifaddrs → utun0/en0/pdp_ip0            遍历网卡
//        if_nametoindex                            按名字取网卡序号
//        网络类型 netType
//
//  实现思路（刻意避开高风险做法）：
//    · 不 hook res_9_ninit / res_9_getservers —— 那要按结构体偏移写内存，
//      偏移猜错就把进程写坏。改为伪造 /etc/resolv.conf 的内容，
//      系统自己的解析器读到的就是假 DNS，res_9_* 自然跟着变。
//    · 不 hook read/pread —— 那是热路径（百度二进制里 read 出现 6351 次），
//      挂钩会拖慢一切。改为在 open/openat/fopen 处就把路径换掉，
//      返回一个装着假内容的临时文件句柄，read 完全不用管。
//    · getifaddrs 只做「摘链」不改数据，摘下来的节点留着，等 freeifaddrs 一起释放。
//
//  用法（宿主侧）：
//        BDSNetSpoofConfigure(enabled, spoofDNS, hideVPN);
//        然后在自己的 rebinding 表里加上 BDSNetSpoofAddRebindings(...)
// ─────────────────────────────────────────────────────────────────────────────

#import <Foundation/Foundation.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <arpa/inet.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <netinet/in.h>
#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <unistd.h>
#import <errno.h>
#import <fcntl.h>
#import <limits.h>
#import <stdarg.h>
#import <notify.h>

#pragma mark - 配置

// hook 表条目类型（宿主把它翻译成自己的 rebinding 结构）
typedef struct { const char *name; void *replacement; void **replaced; } BDSNetSpoofHook;

typedef struct {
    int enabled;              // 总开关
    int spoofDNS;             // 伪造 DNS
    int hideVPN;              // 隐藏隧道网卡
    char dnsServers[3][64];   // 最多 3 个 DNS 服务器
    int dnsServerCount;
} BDSNetSpoofConfig;

static BDSNetSpoofConfig g_bdsNetCfg = {0, 1, 1, {{0}}, 0};

static void BDSNetSpoofConfigure(int enabled, int spoofDNS, int hideVPN) {
    g_bdsNetCfg.enabled = enabled ? 1 : 0;
    g_bdsNetCfg.spoofDNS = spoofDNS ? 1 : 0;
    g_bdsNetCfg.hideVPN = hideVPN ? 1 : 0;
    if (g_bdsNetCfg.dnsServerCount == 0) {
        strncpy(g_bdsNetCfg.dnsServers[0], "223.5.5.5", 63);       // 阿里公共 DNS
        strncpy(g_bdsNetCfg.dnsServers[1], "119.29.29.29", 63);    // DNSPod
        g_bdsNetCfg.dnsServerCount = 2;
    }
}

/// 自定义要伪装的 DNS 服务器（传 NULL 恢复默认）
static void BDSNetSpoofSetDNS(const char *const *servers, int count) {
    g_bdsNetCfg.dnsServerCount = 0;
    if (servers && count > 0) {
        for (int i = 0; i < count && i < 3; i++) {
            if (!servers[i] || !servers[i][0]) continue;
            strncpy(g_bdsNetCfg.dnsServers[g_bdsNetCfg.dnsServerCount],
                    servers[i], sizeof(g_bdsNetCfg.dnsServers[0]) - 1);
            g_bdsNetCfg.dnsServerCount++;
        }
    }
    if (g_bdsNetCfg.dnsServerCount == 0) {
        strncpy(g_bdsNetCfg.dnsServers[0], "223.5.5.5", 63);
        strncpy(g_bdsNetCfg.dnsServers[1], "119.29.29.29", 63);
        g_bdsNetCfg.dnsServerCount = 2;
    }
}

/// 生成 /etc/resolv.conf 的假内容
static int BDSNetSpoofResolvConf(char *out, size_t cap) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    size_t used = 0;
    int n = g_bdsNetCfg.dnsServerCount > 0 ? g_bdsNetCfg.dnsServerCount : 2;
    int lines = 0;
    for (int i = 0; i < n && i < 3; i++) {
        const char *ip = g_bdsNetCfg.dnsServers[i][0]
                       ? g_bdsNetCfg.dnsServers[i]
                       : (i == 0 ? "223.5.5.5" : "119.29.29.29");
        int w = snprintf(out + used, cap - used, "nameserver %s\n", ip);
        if (w <= 0 || (size_t)w >= cap - used) break;
        used += (size_t)w;
        lines++;
    }
    return lines;
}

#pragma mark - 对外接口（宿主与模块内部共用）

void BDSNetSpoofFilterIfaddrs(struct ifaddrs **ifap);
void BDSNetSpoofReleaseDetached(void);
const char *BDSNetSpoofResolvPath(void);
int  BDSNetSpoofIsResolvConf(const char *path);
int  BDSNetSpoofInterfaceVisible(const char *name);
int  BDSNetSpoofIsTunnelInterface(const char *name);

#pragma mark - 隧道网卡判定

int BDSNetSpoofIsTunnelInterface(const char *name) {
    if (!name || !name[0]) return 0;
    static const char *prefixes[] = {
        "utun", "tun", "tap", "ppp", "ipsec", "gpd", "wg", NULL
    };
    for (int i = 0; prefixes[i]; i++) {
        if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0) return 1;
    }
    return 0;
}

int BDSNetSpoofInterfaceVisible(const char *name) {
    if (!g_bdsNetCfg.enabled) return 1;
    if (BDSNetSpoofIsTunnelInterface(name)) return 0;
    return 1;
}

#pragma mark - 原函数指针

static int   (*BDSNetSpoof_orig_getifaddrs)(struct ifaddrs **) = NULL;
static void  (*BDSNetSpoof_orig_freeifaddrs)(struct ifaddrs *) = NULL;
static unsigned int (*BDSNetSpoof_orig_if_nametoindex)(const char *) = NULL;
static int   (*BDSNetSpoof_orig_open)(const char *, int, ...) = NULL;
static int   (*BDSNetSpoof_orig_openat)(int, const char *, int, ...) = NULL;
static FILE *(*BDSNetSpoof_orig_fopen)(const char *, const char *) = NULL;

#pragma mark - getifaddrs / freeifaddrs

// 摘下来的节点留在这里，等 freeifaddrs 统一释放。
// 不能就地 free —— 调用方还要拿这条链表去 freeifaddrs，链表被破坏就会崩。
static struct ifaddrs *g_bdsNetDetached = NULL;

static int BDSNetSpoof_getifaddrs(struct ifaddrs **ifap) {
    if (!BDSNetSpoof_orig_getifaddrs) { errno = ENOSYS; return -1; }
    int r = BDSNetSpoof_orig_getifaddrs(ifap);
    if (r != 0 || !ifap || !*ifap) return r;
    BDSNetSpoofFilterIfaddrs(ifap);
    return r;
}

static void BDSNetSpoof_freeifaddrs(struct ifaddrs *ifa) {
    // 先把摘下来的节点释放掉，再让系统释放主链
    BDSNetSpoofReleaseDetached();
    if (BDSNetSpoof_orig_freeifaddrs) BDSNetSpoof_orig_freeifaddrs(ifa);
}

static unsigned int BDSNetSpoof_if_nametoindex(const char *name) {
    if (!g_bdsNetCfg.enabled) {
        return BDSNetSpoof_orig_if_nametoindex
             ? BDSNetSpoof_orig_if_nametoindex(name) : 0;
    }
    if (BDSNetSpoofIsTunnelInterface(name)) {
        errno = ENXIO;      // 系统对不存在的网卡就是这个错误码
        return 0;
    }
    return BDSNetSpoof_orig_if_nametoindex
         ? BDSNetSpoof_orig_if_nametoindex(name) : 0;
}

#pragma mark - 隧道网卡过滤（getifaddrs 摘链）

// 摘下来的节点留在 g_bdsNetDetached（变量本体定义在上面的 getifaddrs 段），
// 等 freeifaddrs 统一释放。不能就地 free —— 调用方还要拿这条链表去
// freeifaddrs，链表被破坏就会崩。

/// 把隧道网卡（utun/tun/tap/ppp/...）从链表里摘掉。
/// 宿主在 bds_my_getifaddrs 末尾调用。
void BDSNetSpoofFilterIfaddrs(struct ifaddrs **ifap) {
    if (!ifap || !*ifap) return;
    if (!g_bdsNetCfg.enabled || !g_bdsNetCfg.hideVPN) return;

    struct ifaddrs *prev = NULL;
    struct ifaddrs *cur = *ifap;
    while (cur) {
        if (!BDSNetSpoofInterfaceVisible(cur->ifa_name)) {
            struct ifaddrs *next = cur->ifa_next;
            if (prev) prev->ifa_next = next;
            else *ifap = next;
            cur->ifa_next = g_bdsNetDetached;   // 挂到待释放链
            g_bdsNetDetached = cur;
            cur = next;
            continue;
        }
        prev = cur;
        cur = cur->ifa_next;
    }
}

/// 释放摘下来的那些节点。宿主在 bds_my_freeifaddrs 里先调这个，再交系统释放主链。
void BDSNetSpoofReleaseDetached(void) {
    struct ifaddrs *p = g_bdsNetDetached;
    while (p) {
        struct ifaddrs *n = p->ifa_next;
        free(p);
        p = n;
    }
    g_bdsNetDetached = NULL;
}

#pragma mark - /etc/resolv.conf 接管

/// 懒加载：第一次用到时把假内容写进 App 的 tmp 目录，之后复用同一个文件。
const char *BDSNetSpoofResolvPath(void) {
    static char cachedPath[PATH_MAX] = {0};
    static int tried = 0;
    if (tried) return cachedPath[0] ? cachedPath : NULL;
    tried = 1;

    const char *tmp = getenv("TMPDIR");
    if (!tmp || !tmp[0]) tmp = "/tmp";
    char tmpl[PATH_MAX] = {0};
    snprintf(tmpl, sizeof(tmpl), "%s/bdsnetXXXXXX", tmp);

    int fd = mkstemp(tmpl);
    if (fd < 0) return NULL;

    char content[256] = {0};
    if (BDSNetSpoofResolvConf(content, sizeof(content)) > 0) {
        ssize_t w = write(fd, content, strlen(content));
        (void)w;
    }
    close(fd);
    chmod(tmpl, 0644);

    strncpy(cachedPath, tmpl, sizeof(cachedPath) - 1);
    return cachedPath;
}

int BDSNetSpoofIsResolvConf(const char *path) {
    if (!g_bdsNetCfg.enabled || !g_bdsNetCfg.spoofDNS || !path) return 0;
    return strcmp(path, "/etc/resolv.conf") == 0 ||
           strcmp(path, "/private/etc/resolv.conf") == 0;
}

static int BDSNetSpoof_open(const char *path, int oflag, ...) {
    if (BDSNetSpoofIsResolvConf(path)) {
        const char *fake = BDSNetSpoofResolvPath();
        if (fake && BDSNetSpoof_orig_open) {
            // 只读语义下换成假文件；写语义放行（我们不拦写入）
            if ((oflag & O_ACCMODE) == O_RDONLY) {
                return BDSNetSpoof_orig_open(fake, oflag);
            }
        }
    }
    if (!BDSNetSpoof_orig_open) { errno = ENOSYS; return -1; }
    // 透传第三个参数（只有带 O_CREAT 时才有意义）
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return BDSNetSpoof_orig_open(path, oflag, mode);
}

static int BDSNetSpoof_openat(int fd, const char *path, int oflag, ...) {
    if (BDSNetSpoofIsResolvConf(path)) {
        const char *fake = BDSNetSpoofResolvPath();
        if (fake && BDSNetSpoof_orig_openat) {
            if ((oflag & O_ACCMODE) == O_RDONLY) {
                return BDSNetSpoof_orig_openat(fd, fake, oflag);
            }
        }
    }
    if (!BDSNetSpoof_orig_openat) { errno = ENOSYS; return -1; }
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return BDSNetSpoof_orig_openat(fd, path, oflag, mode);
}

static FILE *BDSNetSpoof_fopen(const char *path, const char *mode) {
    if (BDSNetSpoofIsResolvConf(path) && mode && mode[0] == 'r') {
        const char *fake = BDSNetSpoofResolvPath();
        if (fake && BDSNetSpoof_orig_fopen) {
            return BDSNetSpoof_orig_fopen(fake, mode);
        }
    }
    if (!BDSNetSpoof_orig_fopen) { errno = ENOSYS; return NULL; }
    return BDSNetSpoof_orig_fopen(path, mode);
}

#pragma mark - 给宿主用的安装入口

// 宿主通过 BDSNetSpoofStart() 拿到这张表，填进自己的 rebinding 实现即可。
static const BDSNetSpoofHook BDSNetSpoofHookTable[] = {
    {"getifaddrs",     (void *)BDSNetSpoof_getifaddrs,     (void **)&BDSNetSpoof_orig_getifaddrs},
    {"freeifaddrs",    (void *)BDSNetSpoof_freeifaddrs,    (void **)&BDSNetSpoof_orig_freeifaddrs},
    {"if_nametoindex", (void *)BDSNetSpoof_if_nametoindex, (void **)&BDSNetSpoof_orig_if_nametoindex},
    {"open",           (void *)BDSNetSpoof_open,           (void **)&BDSNetSpoof_orig_open},
    {"openat",         (void *)BDSNetSpoof_openat,         (void **)&BDSNetSpoof_orig_openat},
    {"fopen",          (void *)BDSNetSpoof_fopen,          (void **)&BDSNetSpoof_orig_fopen},
};
static const size_t BDSNetSpoofHookCount =
    sizeof(BDSNetSpoofHookTable) / sizeof(BDSNetSpoofHookTable[0]);

#pragma mark - 自检报告

// 读真实文件用的原函数（绕开插件自己的 hook）。
// 用 dlsym(RTLD_NEXT, "open") 拿 libc 真身：
//   · 不走 GOT，所以 fishhook 换不掉它
//   · 比 syscall(SYS_open, ...) 安全 —— iOS 上直接发系统调用可能触发 SIGSYS
//     （那是直接崩，不是返回错误），自检不该冒这个险
static int BDSNetSpoofRawRead(const char *path, char *out, size_t cap) {
    if (!path || !out || cap == 0) return -1;
    out[0] = '\0';

    static int (*realOpen)(const char *, int, ...) = NULL;
    static int tried = 0;
    if (!tried) {
        tried = 1;
        realOpen = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
        if (!realOpen) realOpen = (int (*)(const char *, int, ...))dlsym(RTLD_DEFAULT, "open");
    }
    if (!realOpen) return -1;

    int fd = realOpen(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, cap - 1);
    close(fd);
    if (n < 0) { out[0] = '\0'; return -1; }
    out[n] = '\0';
    return (int)n;
}

// 从 resolv.conf 文本里收集 nameserver（按出现顺序，去重）
static int BDSNetSpoofParseNameservers(const char *text, char out[][64], int maxn) {
    if (!text || !out || maxn <= 0) return 0;
    int n = 0;
    const char *p = text;
    while (p && *p && n < maxn) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 11 && strncmp(p, "nameserver", 10) == 0) {
            const char *q = p + 10;
            while (*q == ' ' || *q == '\t') q++;
            size_t ipLen = len - (size_t)(q - p);
            while (ipLen > 0 && (q[ipLen-1] == ' ' || q[ipLen-1] == '\t' ||
                                 q[ipLen-1] == '\r')) ipLen--;
            if (ipLen > 0 && ipLen < 64) {
                char buf[64] = {0};
                memcpy(buf, q, ipLen);
                int dup = 0;
                for (int i = 0; i < n; i++) if (strcmp(out[i], buf) == 0) { dup = 1; break; }
                if (!dup) { strncpy(out[n], buf, 63); n++; }
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
    return n;
}

/// 网络层伪装自检报告。返回一段可以直接显示的多行文本。
/// 整个函数包在 @try 里：自检是用来查问题的，自己绝不能把 App 搞崩。
static NSString *BDSNetSpoofDiagnosticsBody(void);

static NSString *BDSNetSpoofDiagnostics(void) {
    @try {
        return BDSNetSpoofDiagnosticsBody();
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"自检自身出错（不影响插件功能）：\n  %@\n  %@",
                e.name ?: @"?", e.reason ?: @"?"];
    }
}

static NSString *BDSNetSpoofDiagnosticsBody(void) {
    NSMutableString *r = [NSMutableString string];

    [r appendString:@"【当前状态】\n"];
    [r appendFormat:@"  总开关 %@｜伪造 DNS %@｜隐藏隧道网卡 %@\n",
        g_bdsNetCfg.enabled   ? @"开" : @"关",
        g_bdsNetCfg.spoofDNS  ? @"开" : @"关",
        g_bdsNetCfg.hideVPN   ? @"开" : @"关"];
    [r appendString:@"  要伪装的 DNS："];
    for (int i = 0; i < g_bdsNetCfg.dnsServerCount; i++) {
        [r appendFormat:@"%@%@", i ? @" / " : @"",
            [NSString stringWithUTF8String:g_bdsNetCfg.dnsServers[i]]];
    }
    [r appendString:@"\n"];

    // ── ① DNS ──
    [r appendString:@"\n【DNS】\n"];

    // 真值：dlsym(RTLD_NEXT) 拿的 libc open 直接读，绕开插件 hook
    char real[512] = {0};
    int realLen = BDSNetSpoofRawRead("/etc/resolv.conf", real, sizeof(real));
    char realNS[6][64] = {{0}};
    int realCount = realLen >= 0 ? BDSNetSpoofParseNameservers(real, realNS, 6) : 0;
    if (realLen < 0) {
        [r appendString:@"  真机 /etc/resolv.conf：读不到\n"];
    } else if (realCount == 0) {
        [r appendString:@"  真机 /etc/resolv.conf：里面没有 nameserver 行\n"];
    } else {
        [r appendString:@"  真机 DNS："];
        for (int i = 0; i < realCount; i++) {
            [r appendFormat:@"%@%s", i ? @" / " : @"", realNS[i]];
        }
        [r appendString:@"\n"];
    }

    // 走插件 hook 再读一次 —— App 实际看到的就是这个
    // （open 已被 bds_my_open 接管，这里读的是假文件）
    BOOL resolvHooked = BDSNetSpoofIsResolvConf("/etc/resolv.conf");
    FILE *fp = BDSNetSpoof_orig_fopen ? BDSNetSpoof_orig_fopen("/etc/resolv.conf", "r") : NULL;
    if (fp) {
        char seen[512] = {0};
        size_t got = fread(seen, 1, sizeof(seen) - 1, fp);
        seen[got] = '\0';
        fclose(fp);
        char fakeNS[6][64] = {{0}};
        int fakeCount = BDSNetSpoofParseNameservers(seen, fakeNS, 6);
        [r appendString:@"  App 看到："];
        if (fakeCount == 0) [r appendString:@"（读不到 nameserver）"];
        for (int i = 0; i < fakeCount; i++) {
            [r appendFormat:@"%@%s", i ? @" / " : @"", fakeNS[i]];
        }
        [r appendString:@"\n"];
    } else {
        [r appendString:@"  App 看到：读取失败\n"];
    }

    // 判定
    if (!g_bdsNetCfg.enabled || !g_bdsNetCfg.spoofDNS) {
        [r appendString:@"  → 未生效（DNS 伪造开关是关的）\n"];
    } else if (!resolvHooked) {
        [r appendString:@"  → ★未生效（路径判定没通过）\n"];
    } else if (realCount > 0 && realCount == 0) {
        [r appendString:@"  → ?\n"];
    } else {
        const char *fakePath = BDSNetSpoofResolvPath();
        [r appendFormat:@"  → 已生效；假文件：%@\n",
            fakePath ? [NSString stringWithUTF8String:fakePath] : @"（创建失败！）"];
    }

    // ── ② 网卡 ──
    [r appendString:@"\n【网卡】\n"];
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) == 0 && list) {
        NSMutableArray *visible = [NSMutableArray array];
        NSMutableArray *hidden  = [NSMutableArray array];
        for (struct ifaddrs *ifa = list; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_name) continue;
            NSString *nm = [NSString stringWithUTF8String:ifa->ifa_name];
            if (!nm || [visible containsObject:nm] || [hidden containsObject:nm]) continue;
            if (BDSNetSpoofInterfaceVisible(ifa->ifa_name)) [visible addObject:nm];
            else [hidden addObject:nm];
        }
        [r appendFormat:@"  可见（%lu）：%@\n", (unsigned long)visible.count,
            visible.count ? [visible componentsJoinedByString:@" "] : @"（无）"];
        if (hidden.count) {
            [r appendFormat:@"  已隐藏（%lu）：%@\n", (unsigned long)hidden.count,
                [hidden componentsJoinedByString:@" "]];
        } else {
            [r appendString:@"  已隐藏：无（这台机器上没有 utun/tun/tap/ppp 这类网卡）\n"];
        }
        freeifaddrs(list);
    } else {
        [r appendString:@"  枚举失败\n"];
    }
    if (!g_bdsNetCfg.enabled || !g_bdsNetCfg.hideVPN) {
        [r appendString:@"  → 未生效（隐藏隧道网卡开关是关的）\n"];
    } else {
        [r appendString:@"  → 百度遍历时拿不到上面「已隐藏」那几块\n"];
    }

    [r appendString:@"\n说明：真机 DNS 用 dlsym(RTLD_NEXT) 直读，App 看到的是走插件 hook 的结果；\n"];
    [r appendString:@"两边不一样就说明生效了。"];
    return r;
}

#pragma mark - 配置加载（不依赖宿主）

// 配置读取：优先读 App 容器里的 bdspoofer_config.plist（卍解写的那份），
// 读不到就用沙盒内的 NSUserDefaults。
// 这样本模块可以独立跑，宿主只管调 BDSNetSpoofStart()。
static NSDictionary *BDSNetSpoofLoadConfig(void) {
    @try {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        // 插件实际读的是 Documents 下的同名文件或 NSUserDefaults，两条路都试
        if (docs) {
            NSString *p = [docs stringByAppendingPathComponent:@"bdspoofer_config.plist"];
            NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:p];
            if ([d isKindOfClass:NSDictionary.class] && d.count) return d;
        }
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
        NSDictionary *d = [ud dictionaryRepresentation];
        if ([d isKindOfClass:NSDictionary.class]) return d;
    } @catch (NSException *e) {}
    return nil;
}

static int BDSNetSpoofConfigBool(NSDictionary *cfg, NSString *key, int def) {
    if (!cfg) return def;
    id v = cfg[key];
    if ([v isKindOfClass:NSNumber.class]) return [v boolValue] ? 1 : 0;
    if ([v isKindOfClass:NSString.class]) {
        NSString *s = [(NSString *)v lowercaseString];
        if ([s isEqualToString:@"yes"] || [s isEqualToString:@"true"] ||
            [s isEqualToString:@"1"]) return 1;
        if ([s isEqualToString:@"no"] || [s isEqualToString:@"false"] ||
            [s isEqualToString:@"0"]) return 0;
    }
    return def;
}

/// 从配置里读开关和 DNS 列表。全部缺省时：总开关跟随「功能总开关」，DNS 用默认值。
static void BDSNetSpoofLoadFromConfig(void) {
    NSDictionary *cfg = BDSNetSpoofLoadConfig();
    int enabled = BDSNetSpoofConfigBool(cfg, @"netSpoofEnabled", 1);
    int spDNS   = BDSNetSpoofConfigBool(cfg, @"netSpoofDNS", 1);
    int hideVPN = BDSNetSpoofConfigBool(cfg, @"netSpoofHideVPN", 1);
    BDSNetSpoofConfigure(enabled, spDNS, hideVPN);

    @try {
        id list = cfg[@"netSpoofDNSServers"];
        if ([list isKindOfClass:NSArray.class] && [(NSArray *)list count]) {
            NSArray *a = (NSArray *)list;
            const char *buf[3] = {NULL, NULL, NULL};
            char store[3][64] = {{0}};
            int n = 0;
            for (id item in a) {
                if (n >= 3) break;
                if (![item isKindOfClass:NSString.class]) continue;
                const char *s = [(NSString *)item UTF8String];
                if (!s || !s[0]) continue;
                strncpy(store[n], s, 63);
                buf[n] = store[n];
                n++;
            }
            if (n > 0) BDSNetSpoofSetDNS(buf, n);
        }
    } @catch (NSException *e) {}
}

#pragma mark - 独立运行入口

/// 宿主调用：载入配置（开关 + DNS 列表）。
/// hook 表由宿主自己在 rebinding 表里登记（见 BDSNetSpoofHookTable），
/// 这里不做回调，避免 block / 函数指针签名不一致的麻烦。
static void BDSNetSpoofStart(void) {
    BDSNetSpoofLoadFromConfig();
}

/// hook 表的只读访问（宿主想遍历登记时用）
static const BDSNetSpoofHook *BDSNetSpoofHooks(size_t *countOut) {
    if (countOut) *countOut = BDSNetSpoofHookCount;
    return BDSNetSpoofHookTable;
}

/// 配置变了（卍解改了 plist）时调一下，重新读取开关。
/// hook 本身不用重装，判定入口每次都看 g_bdsNetCfg。
static void BDSNetSpoofReload(void) {
    BDSNetSpoofLoadFromConfig();
}

