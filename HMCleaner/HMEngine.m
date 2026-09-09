#import "HMEngine.h"
#import <fcntl.h>
#import <unistd.h>

@implementation HMScanItem
- (NSString *)name { return self.index < HM_FILE_COUNT ? @(hm_names[self.index]) : @"无效项"; }
- (NSString *)summary {
    if (self.readError) return HMErrnoText(self.readError);
    HMFileState st = self.state;
    return [NSString stringWithFormat:@"存在 · %lld 字节 · SHA-256 %@…", st.st.st_size, [HMHex(st.sha, 32) substringToIndex:12]];
}
@end

static BOOL HMValidRecordID(NSString *identifier) {
    return [identifier isKindOfClass:NSString.class] && [[NSUUID alloc] initWithUUIDString:identifier] != nil;
}
static int HMChildDirectory(int parent, const char *name, BOOL create) {
    if (create && mkdirat(parent, name, 0700) && errno != EEXIST) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || st.st_uid != geteuid()) { close(fd); errno = EPERM; return -1; }
    if (create && fchmod(fd, 0700)) { int e = errno; close(fd); errno = e; return -1; }
    return fd;
}
static NSDictionary *HMReadPlist(int dir, NSString *name, NSError **error) {
    HMFileState state; void *bytes = NULL;
    if (hm_read(dir, name.fileSystemRepresentation, &state, &bytes)) {
        if (error) *error = HMError(HMErrnoText(errno)); return nil;
    }
    NSData *data = [NSData dataWithBytesNoCopy:bytes length:(NSUInteger)state.st.st_size freeWhenDone:YES];
    id object = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:error];
    if (![object isKindOfClass:NSDictionary.class]) {
        if (error && !*error) *error = HMError(@"记录格式错误。"); return nil;
    }
    return object;
}
static BOOL HMWritePlist(int dir, NSString *name, NSDictionary *object, NSError **error) {
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:object format:NSPropertyListXMLFormat_v1_0 options:0 error:error];
    if (!data) return NO;
    if (hm_write_new(dir, name.fileSystemRepresentation, data.bytes, data.length, 0600) || fsync(dir)) {
        if (error) *error = HMError([@"保存记录失败：" stringByAppendingString:HMErrnoText(errno)]); return NO;
    }
    return YES;
}

@implementation HMEngine
- (instancetype)initWithEnvironment:(HMEnvironment *)environment storePath:(NSString *)path {
    if ((self = [super init])) { _environment = environment; _storePath = [path copy]; }
    return self;
}
- (int)openStore:(BOOL)create error:(NSError **)error {
    // The fixed parent must already exist. Only our two private directories may be created.
    NSString *parent = [[self.storePath stringByDeletingLastPathComponent] stringByDeletingLastPathComponent];
    int p = hm_open_dir(parent.fileSystemRepresentation);
    if (p < 0) { if (error) *error = HMError([@"备份父目录无法访问：" stringByAppendingString:HMErrnoText(errno)]); return -1; }
    int app = HMChildDirectory(p, [[self.storePath stringByDeletingLastPathComponent].lastPathComponent UTF8String], create);
    int e = errno; close(p);
    if (app < 0) { if (error) *error = HMError(HMErrnoText(e)); return -1; }
    int dir = HMChildDirectory(app, self.storePath.lastPathComponent.UTF8String, create);
    e = errno; if (create && dir >= 0 && fsync(app)) { e = errno; close(dir); dir = -1; }
    close(app);
    if (dir < 0 && error) *error = HMError(HMErrnoText(e));
    return dir;
}
- (NSArray<HMScanItem *> *)scan:(NSDictionary *)container error:(NSError **)error {
    int fd = [self.environment openVerifiedContainer:container error:error];
    if (fd < 0) return nil;
    NSMutableArray *items = [NSMutableArray array];
    for (NSUInteger i = 0; i < HM_FILE_COUNT; i++) {
        HMScanItem *item = [HMScanItem new]; item.index = i;
        HMFileState state = {0};
        item.readError = hm_read_candidate(fd, i, &state, NULL) ? errno : 0;
        item.state = state;
        [items addObject:item];
    }
    close(fd); return items;
}
- (NSDictionary *)clean:(NSDictionary *)container items:(NSArray<HMScanItem *> *)items error:(NSError **)error {
    NSMutableArray<HMScanItem *> *selected = [NSMutableArray array];
    NSMutableIndexSet *seen = [NSMutableIndexSet indexSet];
    for (HMScanItem *item in items) if (item.selected) {
        if (item.readError || item.index >= HM_FILE_COUNT || [seen containsIndex:item.index]) {
            if (error) *error = HMError(@"勾选项无效，请重新扫描。"); return nil;
        }
        [seen addIndex:item.index]; [selected addObject:item];
    }
    if (!selected.count) { if (error) *error = HMError(@"请先勾选要清理的文件。"); return nil; }
    if (![self.environment targetStopped:error]) return nil;
    int root = [self.environment openVerifiedContainer:container error:error];
    if (root < 0) return nil;
    int store = [self openStore:YES error:error];
    if (store < 0) { close(root); return nil; }
    NSString *recordID = NSUUID.UUID.UUIDString;
    if (mkdirat(store, recordID.UTF8String, 0700)) {
        if (error) *error = HMError(HMErrnoText(errno)); close(store); close(root); return nil;
    }
    int backup = HMChildDirectory(store, recordID.UTF8String, NO);
    if (backup < 0 || fsync(store)) {
        if (error) *error = HMError(@"备份目录持久化失败，未清理任何文件。");
        if (backup >= 0) close(backup); close(store); close(root); return nil;
    }
    close(store);
    NSMutableArray *entries = [NSMutableArray array];
    BOOL prepared = YES;
    for (HMScanItem *item in selected) {
        if (self.cancelRequested) { prepared = NO; if (error) *error = HMError(@"系统执行时间到期，已停止，未清理。"); break; }
        HMFileState state; void *bytes = NULL;
        HMFileState expected = item.state;
        int r = hm_read_candidate(root, item.index, &state, &bytes);
        int e = errno;
        if (r || !hm_same(&state, &expected)) {
            free(bytes); prepared = NO; if (error) *error = HMError(r ? HMErrnoText(e) : @"扫描后文件发生变化，未清理。"); break;
        }
        NSString *filename = [NSString stringWithFormat:@"file-%lu.bin", (unsigned long)item.index];
        if (hm_write_new(backup, filename.UTF8String, bytes, (size_t)state.st.st_size, 0600)) {
            e = errno; free(bytes); prepared = NO; if (error) *error = HMError(HMErrnoText(e)); break;
        }
        free(bytes);
        HMFileState check;
        if (hm_read(backup, filename.UTF8String, &check, NULL) || check.st.st_size != state.st.st_size || memcmp(check.sha, state.sha, 32)) {
            prepared = NO; if (error) *error = HMError(@"备份读回校验失败，未清理任何文件。"); break;
        }
        [entries addObject:@{@"index":@(item.index), @"name":item.name, @"backup":filename,
                             @"size":@(state.st.st_size), @"sha256":HMHex(state.sha, 32),
                             @"uid":@(state.st.st_uid), @"gid":@(state.st.st_gid), @"mode":@(state.st.st_mode & 0777)}];
    }
    NSMutableDictionary *record = [@{@"schema":@1, @"id":recordID, @"target":HMTargetID,
                                    @"created":[[NSDate date] description], @"container":container,
                                    @"entries":entries, @"prepared":@(prepared),
                                    @"keychain":@"未启用：未核实容器访问组，未读取或删除钥匙串",
                                    @"restoreScope":@"文件内容、所有者和权限；不承诺恢复时间戳或扩展属性"} mutableCopy];
    NSError *saveError = nil;
    if (!HMWritePlist(backup, @"manifest.plist", record, &saveError) || !prepared) {
        if (error && saveError) *error = saveError;
        close(backup); close(root); return nil;
    }
    close(root);
    NSMutableArray *results = [NSMutableArray array];
    for (HMScanItem *item in selected) {
        if (self.cancelRequested) { [results addObject:@{@"result":@"系统执行时间到期，后续清理停止"}]; break; }
        NSError *guardError = nil;
        BOOL stopped = [self.environment targetStopped:&guardError];
        int current = stopped ? [self.environment openVerifiedContainer:container error:&guardError] : -1;
        NSString *result;
        if (current < 0) result = [@"已停止：" stringByAppendingString:guardError.localizedDescription ?: @"容器校验失败"];
        else {
            HMFileState expected = item.state;
            result = hm_remove_candidate(current, item.index, &expected) ? HMErrnoText(errno) : @"已清理，复查不存在";
            close(current);
        }
        NSDictionary *event = @{@"index":@(item.index), @"name":item.name, @"result":result};
        [results addObject:event];
        if (!HMWritePlist(backup, [NSString stringWithFormat:@"clean-%lu.plist", (unsigned long)item.index], event, &saveError)) {
            [results addObject:@{@"result":@"记录写入失败，后续操作停止；备份已保存，请重新验证"}]; break;
        }
        if (guardError) break;
    }
    close(backup);
    record[@"results"] = results;
    return record;
}
- (int)openRecord:(NSDictionary *)input record:(NSDictionary **)record error:(NSError **)error {
    NSString *rid = input[@"id"];
    if (!HMValidRecordID(rid)) { if (error) *error = HMError(@"备份编号无效。"); return -1; }
    int store = [self openStore:NO error:error]; if (store < 0) return -1;
    int dir = HMChildDirectory(store, rid.UTF8String, NO); int e = errno; close(store);
    if (dir < 0) { if (error) *error = HMError(HMErrnoText(e)); return -1; }
    NSDictionary *m = HMReadPlist(dir, @"manifest.plist", error);
    BOOL valid = [m[@"schema"] isEqual:@1] && [m[@"id"] isEqual:rid] && [m[@"target"] isEqual:HMTargetID] &&
        [m[@"container"] isKindOfClass:NSDictionary.class] && [m[@"entries"] isKindOfClass:NSArray.class] && [m[@"entries"] count] <= HM_FILE_COUNT;
    NSMutableIndexSet *seen = [NSMutableIndexSet indexSet];
    for (id entry in valid ? m[@"entries"] : @[]) {
        if (![entry isKindOfClass:NSDictionary.class] || ![entry[@"index"] isKindOfClass:NSNumber.class]) { valid = NO; break; }
        NSUInteger index = [entry[@"index"] unsignedIntegerValue];
        if (index >= HM_FILE_COUNT || [seen containsIndex:index] || ![entry[@"name"] isEqual:@(hm_names[index])] ||
            ![entry[@"backup"] isEqual:[NSString stringWithFormat:@"file-%lu.bin", (unsigned long)index]] ||
            ![entry[@"sha256"] isKindOfClass:NSString.class] || [entry[@"sha256"] length] != 64 ||
            ![entry[@"uid"] isKindOfClass:NSNumber.class] || ![entry[@"gid"] isKindOfClass:NSNumber.class] ||
            ![entry[@"mode"] isKindOfClass:NSNumber.class] || ![entry[@"size"] isKindOfClass:NSNumber.class]) { valid = NO; break; }
        [seen addIndex:index];
    }
    if (!valid) { if (error) *error = HMError(@"备份清单不符合固定范围，已拒绝。"); close(dir); return -1; }
    *record = m; return dir;
}
- (NSArray<NSDictionary *> *)history:(NSError **)error {
    int store = [self openStore:NO error:error];
    if (store < 0) return nil;
    close(store);
    NSArray *names = [NSFileManager.defaultManager contentsOfDirectoryAtPath:self.storePath error:error];
    NSMutableArray *records = [NSMutableArray array];
    for (NSString *name in names) if (HMValidRecordID(name)) {
        NSDictionary *record = nil; NSError *readError = nil;
        int fd = [self openRecord:@{@"id":name} record:&record error:&readError];
        if (fd >= 0) {
            NSMutableDictionary *expanded = [record mutableCopy]; NSMutableArray *events = [NSMutableArray array];
            for (NSDictionary *entry in record[@"entries"]) {
                NSString *eventName = [NSString stringWithFormat:@"clean-%@.plist", entry[@"index"]];
                NSDictionary *event = HMReadPlist(fd, eventName, NULL);
                [events addObject:event ?: @{@"name":entry[@"name"], @"result":@"无完成记录：可能未执行或中途退出，请验证"}];
            }
            expanded[@"results"] = events; [records addObject:expanded]; close(fd);
        } else {
            [records addObject:@{@"id":name, @"created":@"", @"invalid":readError.localizedDescription ?: @"不完整备份"}];
        }
    }
    return [records sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) { return [b[@"created"] compare:a[@"created"]]; }];
}
- (NSDictionary *)verify:(NSDictionary *)input error:(NSError **)error {
    NSDictionary *record = nil;
    int backup = [self openRecord:input record:&record error:error]; if (backup < 0) return nil;
    close(backup);
    int root = [self.environment openVerifiedContainer:record[@"container"] error:error]; if (root < 0) return nil;
    NSMutableArray *results = [NSMutableArray array];
    for (NSDictionary *entry in record[@"entries"]) {
        HMFileState now;
        int rc = hm_read_candidate(root, [entry[@"index"] unsignedIntegerValue], &now, NULL), e = errno;
        NSString *status = rc ? (e == ENOENT ? @"当前不存在" : [@"无法验证：" stringByAppendingString:HMErrnoText(e)]) :
            ([HMHex(now.sha, 32) isEqual:entry[@"sha256"]] ? @"当前存在，内容与备份相同" : @"当前存在，内容与备份不同");
        [results addObject:@{@"name":entry[@"name"], @"result":status}];
    }
    close(root);
    return @{@"id":record[@"id"], @"container":record[@"container"], @"results":results,
             @"note":@"仅比较文件内容；存在不等于证明由哪个 SDK 重建。钥匙串未操作。"};
}
- (NSDictionary *)restore:(NSDictionary *)input error:(NSError **)error {
    if (![self.environment targetStopped:error]) return nil;
    NSDictionary *record = nil;
    int backup = [self openRecord:input record:&record error:error]; if (backup < 0) return nil;
    if (![record[@"prepared"] boolValue]) { close(backup); if (error) *error = HMError(@"此备份准备未完成，清理未开始，不允许自动恢复。"); return nil; }
    NSMutableArray *results = [NSMutableArray array];
    for (NSDictionary *entry in record[@"entries"]) {
        NSError *guardError = nil;
        if (self.cancelRequested) { [results addObject:@{@"result":@"系统执行时间到期，后续恢复停止"}]; break; }
        BOOL stopped = [self.environment targetStopped:&guardError];
        int root = stopped ? [self.environment openVerifiedContainer:record[@"container"] error:&guardError] : -1;
        if (root < 0) { if (error) *error = guardError; break; }
        HMFileState check; void *bytes = NULL;
        NSString *result;
        if (hm_read(backup, [entry[@"backup"] UTF8String], &check, &bytes)) result = [@"备份读取失败：" stringByAppendingString:HMErrnoText(errno)];
        else if (![HMHex(check.sha, 32) isEqual:entry[@"sha256"]] || check.st.st_size != [entry[@"size"] longLongValue]) result = @"备份校验失败，未恢复";
        else {
            int rc = hm_restore_candidate(root, [entry[@"index"] unsignedIntegerValue], bytes, (size_t)check.st.st_size,
                                          check.sha, [entry[@"uid"] unsignedIntValue], [entry[@"gid"] unsignedIntValue], [entry[@"mode"] unsignedShortValue]);
            result = rc ? HMErrnoText(errno) : @"已恢复文件内容";
        }
        free(bytes); close(root);
        NSDictionary *event = @{@"name":entry[@"name"], @"result":result};
        [results addObject:event];
        if (!HMWritePlist(backup, [NSString stringWithFormat:@"restore-%@-%@.plist", entry[@"index"], NSUUID.UUID.UUIDString], event, error)) break;
    }
    close(backup);
    return @{@"id":record[@"id"], @"container":record[@"container"], @"results":results,
             @"note":@"已有文件不会覆盖；恢复文件内容、所有者和权限，不恢复时间戳、ACL 或扩展属性。钥匙串未操作。"};
}
@end
