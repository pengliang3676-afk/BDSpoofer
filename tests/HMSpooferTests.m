#define HM_HOST_TEST 1
#import "../HMSpoofer.m"

static unsigned checks;
#define CHECK(condition) do { ++checks; if (!(condition)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); exit(1); } } while (0)

static int forcedError, calls;
static const char *realBoard = "D331pAP";
static const char *mountName = "/private/var";
static const char *fsName = "apfs";
static uint32_t blockSize = 4096;

static int stubValue(HMQuery query, void *oldp, size_t *length) {
    ++calls;
    if (forcedError) return hm_error(forcedError);
    uint64_t memory = 1234;
    struct timeval boot = {123, 0};
    const void *value = query == HMBoard ? (const void *)realBoard : (const void *)"iPhone11,6";
    size_t need = strlen(value) + 1;
    if (query == HMMemory) { value = &memory; need = sizeof(memory); }
    if (query == HMBoot) { value = &boot; need = sizeof(boot); }
    if (!length) return 0;
    size_t cap = oldp ? *length : 0;
    *length = need;
    if (!oldp) return 0;
    if (cap < need) return hm_error(ENOMEM);
    memcpy(oldp, value, need);
    return 0;
}
static int stubByName(const char *name, void *oldp, size_t *length, void *newp, size_t newlen) {
    if (newp || newlen) { ++calls; return hm_error(EPERM); }
    return stubValue(hm_nameQuery(name), oldp, length);
}
static int stubMib(int *name, u_int count, void *oldp, size_t *length, void *newp, size_t newlen) {
    if (newp || newlen) { ++calls; return hm_error(EPERM); }
    return stubValue(hm_mibQuery(name, count), oldp, length);
}
static int stubUname(struct utsname *u) {
    ++calls;
    if (forcedError) return hm_error(forcedError);
    memset(u, 0, sizeof(*u));
    strlcpy(u->machine, "iPhone11,6", sizeof(u->machine));
    return 0;
}
static int stubStatfs(const char *path, struct statfs *out) {
    ++calls;
    if (forcedError) return hm_error(forcedError);
    memset(out, 0, sizeof(*out));
    strlcpy(out->f_fstypename, fsName, sizeof(out->f_fstypename));
    strlcpy(out->f_mntonname, mountName, sizeof(out->f_mntonname));
    out->f_bsize = blockSize;
    out->f_blocks = 100000000;
    out->f_bfree = 40000000;
    out->f_bavail = 39000000;
    return 0;
}
static void stubFunctions(void) {
    atomic_store(&real_sysctl, stubMib);
    atomic_store(&real_sysctlbyname, stubByName);
    atomic_store(&real_uname, stubUname);
    atomic_store(&real_statfs, stubStatfs);
}
static NSDictionary *profileAt(NSUInteger index) {
    HMPoolEntry *e = hm_pool()[index];
    NSMutableDictionary *p = [hm_makeProfile() mutableCopy];
    [p addEntriesFromDictionary:@{@"machine":e.machine, @"board":e.board, @"market":e.market,
        @"mem":@(e.mem), @"w":@(e.w), @"h":@(e.h), @"scale":@(e.scale),
        @"nw":@(e.nw), @"nh":@(e.nh), @"status":@(e.status), @"safeTop":@(e.safeTop),
        @"safeBottom":@(e.safeBottom), @"disk":e.disks[0], @"sysVer":e.sysVers[0], @"poolIndex":@(index)}];
    return [p copy];
}
static void setProfile(NSDictionary *p) {
    os_unfair_lock_lock(&g_lock);
    g_profile = [p copy];
    g_pending = g_profile;
    os_unfair_lock_unlock(&g_lock);
    atomic_store(&g_active, 1);
}
static void testSysctl(void) {
    setProfile(profileAt(7)); // fake D79AP is shorter than the real D331pAP.
    for (int useMib = 0; useMib < 2; ++useMib) {
        int mib[2] = {CTL_HW, HW_MODEL};
#define QUERY(buf, len) (useMib ? hm_my_sysctl(mib, 2, buf, len, NULL, 0) : hm_my_sysctlbyname("hw.model", buf, len, NULL, 0))
        size_t length; // Deliberately uninitialized for size-only query.
        calls = 0; errno = EDOM;
        CHECK(QUERY(NULL, &length) == 0 && length == 6 && errno == EDOM && calls == 1);
        unsigned char buffer[32]; memset(buffer, 0xA5, sizeof(buffer));
        CHECK(QUERY(buffer, &length) == 0 && length == 6 && !strcmp((char *)buffer, "D79AP"));
        CHECK(buffer[6] == 0xA5 && calls == 2);
        length = 5;
        memset(buffer, 0xA5, sizeof(buffer));
        CHECK(QUERY(buffer, &length) == -1 && errno == ENOMEM && length == 6);
        CHECK(buffer[0] == 0xA5 && buffer[31] == 0xA5);
        length = sizeof(buffer);
        forcedError = EACCES;
        CHECK(QUERY(buffer, &length) == -1 && errno == EACCES);
        CHECK(length == sizeof(buffer) && buffer[0] == 0xA5);
        forcedError = 0;
        length = sizeof(buffer);
        CHECK(QUERY((void *)(uintptr_t)1, &length) == -1 && errno == EFAULT);
        CHECK(QUERY(buffer, (size_t *)(uintptr_t)1) == -1 && errno == EFAULT);
        atomic_store(&g_active, 0);
        length = sizeof(buffer);
        CHECK(QUERY(buffer, &length) == 0 && !strcmp((char *)buffer, realBoard));
        atomic_store(&g_active, 1);
        ++g_cDepth;
        length = sizeof(buffer);
        CHECK(QUERY(buffer, &length) == 0 && !strcmp((char *)buffer, realBoard));
        --g_cDepth;
#undef QUERY
    }
    setProfile(profileAt(2)); realBoard = "D79AP"; // fake is longer than real.
    size_t length = 6; char text[16]; memset(text, 'x', sizeof(text));
    CHECK(hm_my_sysctlbyname("hw.model", text, &length, NULL, 0) == -1 && errno == ENOMEM && length == 8);
    CHECK(text[0] == 'x');
    CHECK(hm_my_sysctlbyname("hw.model", text, &length, NULL, 0) == 0 && !strcmp(text, "D331pAP"));
    realBoard = "D331pAP";
    for (int kind = 0; kind < 2; ++kind) {
        const char *name = kind ? "kern.boottime" : "hw.memsize";
        unsigned char bytes[32] = {0}; length = sizeof(bytes);
        CHECK(hm_my_sysctlbyname(name, bytes, &length, NULL, 0) == 0);
        CHECK(length == (kind ? sizeof(struct timeval) : sizeof(uint64_t)));
        if (!kind) { uint64_t mem; memcpy(&mem, bytes, sizeof(mem)); CHECK(mem == 4ull * 1024 * 1024 * 1024); }
        else { struct timeval tv; memcpy(&tv, bytes, sizeof(tv)); CHECK(tv.tv_usec == 0 && tv.tv_sec == [g_profile[@"bootEpoch"] longLongValue]); }
        length = 1;
        CHECK(hm_my_sysctlbyname(name, bytes, &length, NULL, 0) == -1 && errno == ENOMEM);
    }
    length = sizeof(text);
    CHECK(hm_my_sysctlbyname("hw.model", text, &length, text, 1) == -1 && errno == EPERM);
    CHECK(hm_error(ENOSYS) == -1 && errno == ENOSYS);
    puts("PASS sysctl contracts: lengths, both entrances, short buffers, errno, failures, gates, EFAULT");
}
static void testUnameStatfs(void) {
    setProfile(profileAt(7));
    struct utsname u; memset(&u, 0x5A, sizeof(u));
    forcedError = EFAULT;
    CHECK(hm_my_uname(&u) == -1 && errno == EFAULT && ((unsigned char *)&u)[0] == 0x5A);
    forcedError = 0; errno = EDOM;
    CHECK(hm_my_uname(&u) == 0 && !strcmp(u.machine, "iPhone12,8") && errno == EDOM);
    struct statfs fs;
    forcedError = ENOENT; memset(&fs, 0x5A, sizeof(fs));
    CHECK(hm_my_statfs("missing", &fs) == -1 && errno == ENOENT && ((unsigned char *)&fs)[0] == 0x5A);
    forcedError = 0;
    const char *mounts[] = {"/var", "/private/var", "/var/mobile", "/private/var/mobile", "/var2", "/"};
    for (size_t i = 0; i < 6; ++i) {
        mountName = mounts[i];
        CHECK(hm_my_statfs("path", &fs) == 0);
        if (i < 2) {
            CHECK(fs.f_blocks == [g_profile[@"disk"] unsignedLongLongValue] / 4096);
            CHECK(fs.f_bavail <= fs.f_bfree && fs.f_bfree <= fs.f_blocks);
        } else CHECK(fs.f_blocks == 100000000);
    }
    mountName = "/var"; fsName = "apfs-extra";
    CHECK(hm_my_statfs("path", &fs) == 0 && fs.f_blocks == 100000000);
    fsName = "apfs"; blockSize = 0;
    CHECK(hm_my_statfs("path", &fs) == 0 && fs.f_blocks == 100000000);
    blockSize = 4096;
    puts("PASS uname/statfs: failure buffers unchanged, exact mounts, free-space ordering, zero block size");
}

@interface HMTestBase : NSObject
- (NSString *)label;
- (NSOperatingSystemVersion)version;
- (CGRect)rect;
@end
@implementation HMTestBase
- (NSString *)label { return @"base"; }
- (NSOperatingSystemVersion)version { return (NSOperatingSystemVersion){1,2,3}; }
- (CGRect)rect { return CGRectZero; }
@end
@interface HMTestChild : HMTestBase @end
@implementation HMTestChild @end
static _Atomic(IMP) originalLabel, originalVersion;
static NSString *labelHook(id self, SEL cmd) {
    IMP old = atomic_load(&originalLabel);
    CHECK(old != NULL);
    return [((NSString *(*)(id, SEL))old)(self, cmd) stringByAppendingString:@"-child"];
}
static NSOperatingSystemVersion versionHook(id self, SEL cmd) {
    NSOperatingSystemVersion v = ((NSOperatingSystemVersion(*)(id, SEL))atomic_load(&originalVersion))(self, cmd);
    v.majorVersion += 10; return v;
}
static void testHooks(void) {
    CHECK(!hm_encodingOK(class_getInstanceMethod(HMTestBase.class, @selector(rect)), @encode(NSOperatingSystemVersion)));
    CHECK(hm_encodingOK(class_getInstanceMethod(HMTestBase.class, @selector(version)), @encode(NSOperatingSystemVersion)));
    CHECK(!hm_install(HMTestChild.class, @selector(absent), (IMP)labelHook, &originalLabel, @encode(id)));
    CHECK(hm_install(HMTestChild.class, @selector(label), (IMP)labelHook, &originalLabel, @encode(id)));
    CHECK([[HMTestBase.new label] isEqualToString:@"base"]);
    CHECK([[HMTestChild.new label] isEqualToString:@"base-child"]);
    CHECK(hm_install(HMTestChild.class, @selector(version), (IMP)versionHook, &originalVersion, @encode(NSOperatingSystemVersion)));
    CHECK([HMTestChild.new version].majorVersion == 11);
    CHECK([HMTestBase.new version].majorVersion == 1);
    CHECK(hm_install(HMTestBase.class, @selector(version), (IMP)versionHook, &originalVersion, @encode(NSOperatingSystemVersion)));
    CHECK([HMTestBase.new version].majorVersion == 11);
    puts("PASS Objective-C: complete return encoding, inherited method isolation, original IMP, struct return");
}
static void testProfiles(void) {
    CHECK(hm_pool().count == 8);
    for (NSUInteger i = 0; i < 8; ++i) {
        NSDictionary *p = profileAt(i);
        CHECK(hm_profileComplete(p));
        CHECK([p[@"w"] doubleValue] * [p[@"scale"] doubleValue] == [p[@"nw"] doubleValue]);
        CHECK([p[@"h"] doubleValue] * [p[@"scale"] doubleValue] == [p[@"nh"] doubleValue]);
        NSMutableDictionary *bad = [p mutableCopy]; bad[@"board"] = @"WRONG";
        CHECK(!hm_profileComplete(bad));
        bad = [p mutableCopy]; bad[@"mem"] = @[]; CHECK(!hm_profileComplete(bad));
        bad = [p mutableCopy]; bad[@"freeFrac"] = @(NAN); CHECK(!hm_profileComplete(bad));
        bad = [p mutableCopy]; bad[@"idfv"] = @"bad"; CHECK(!hm_profileComplete(bad));
        bad = [p mutableCopy]; bad[@"poolIndex"] = @100; CHECK(!hm_profileComplete(bad));
        bad = [p mutableCopy]; bad[@"schema"] = @999; CHECK(!hm_profileComplete(bad));
        CGRect portrait = hm_profileBounds(p, CGRectMake(0,0,375,812), NO);
        CGRect landscape = hm_profileBounds(p, CGRectMake(0,0,812,375), NO);
        CHECK(portrait.size.width == landscape.size.height && portrait.size.height == landscape.size.width);
    }
    NSMutableDictionary *badSKU = [profileAt(0) mutableCopy]; badSKU[@"disk"] = @(128000000000ull);
    CHECK(!hm_profileComplete(badSKU));
    badSKU = [profileAt(0) mutableCopy]; badSKU[@"sysVer"] = @"17.4.1"; CHECK(!hm_profileComplete(badSKU));
    NSString *folder = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    NSError *error = nil;
    CHECK([NSFileManager.defaultManager createDirectoryAtPath:folder withIntermediateDirectories:YES attributes:nil error:&error]);
    g_testCfgPath = [folder stringByAppendingPathComponent:@"config.plist"];
    setProfile(profileAt(0));
    CHECK(hm_saveProfile(g_profile, &error));
    NSDictionary *old = hm_snap();
    CHECK(hm_changePending(YES, &error));
    NSDictionary *random = hm_pending();
    CHECK(![random[@"idfv"] isEqual:old[@"idfv"]]);
    CHECK(hm_changePending(NO, &error));
    CHECK([hm_pending()[@"idfv"] isEqual:random[@"idfv"]]);
    CHECK(![hm_pending()[@"enabled"] boolValue]);
    CHECK([hm_snap() isEqual:old] && [g_profile isEqual:old]);
    CHECK([[NSDictionary dictionaryWithContentsOfFile:g_testCfgPath] isEqual:hm_pending()]);
    NSString *validPath = g_testCfgPath;
    g_testCfgPath = [folder stringByAppendingPathComponent:@"missing/config.plist"];
    NSDictionary *saved = hm_pending();
    CHECK(!hm_changePending(YES, &error) && error != nil);
    CHECK([hm_pending() isEqual:saved] && [hm_snap() isEqual:old]);
    g_testCfgPath = validPath;
    CHECK(hm_loadOrInit());
    CHECK([g_profile isEqual:saved]);
    CHECK([NSFileManager.defaultManager removeItemAtPath:folder error:&error]);
    UIEdgeInsets x = hm_hardwareInsets(profileAt(0), NO, NO);
    UIEdgeInsets se = hm_hardwareInsets(profileAt(7), NO, NO);
    CHECK(x.top == 44 && x.bottom == 34 && se.top == 0 && se.bottom == 0);
    x = hm_hardwareInsets(profileAt(0), YES, NO);
    CHECK(x.top == 0 && x.left == 44 && x.right == 44 && x.bottom == 21);
    UIEdgeInsets adjusted = hm_replaceHardwareInsets((UIEdgeInsets){64,0,0,0}, (UIEdgeInsets){20,0,0,0}, (UIEdgeInsets){44,0,34,0});
    CHECK(adjusted.top == 88 && adjusted.bottom == 34);
    puts("PASS profiles: all 8 models, invalid data rejection, pending identity survives toggle, write failure, reload, geometry");
}
static void testResolvers(void) {
    atomic_store(&real_sysctl, NULL); atomic_store(&real_sysctlbyname, NULL);
    atomic_store(&real_uname, NULL); atomic_store(&real_statfs, NULL);
    dispatch_apply(64, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(size_t i) {
        (void)hm_get_real_sysctl(); (void)hm_get_real_sysctlbyname();
        (void)hm_get_real_uname(); (void)hm_get_real_statfs();
    });
    CHECK(atomic_load(&real_sysctl) && atomic_load(&real_sysctlbyname) &&
          atomic_load(&real_uname) && atomic_load(&real_statfs));
    puts("PASS independent symbol resolution under concurrent first use");
}
int main(void) {
    @autoreleasepool {
        stubFunctions();
        testSysctl(); testUnameStatfs(); testHooks(); testProfiles(); testResolvers();
        printf("PASS %u checks (macOS host tests; UIKit and arm64e runtime require iPhone validation)\n", checks);
    }
    return 0;
}
