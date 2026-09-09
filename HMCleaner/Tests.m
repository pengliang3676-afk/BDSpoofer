#import <Foundation/Foundation.h>
#import "HMEngine.h"
#import <fcntl.h>
#import <unistd.h>

static int checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", __LINE__, #x, errno); exit(1); } } while (0)

@interface HMTestEnvironment : HMEnvironment
@property(nonatomic, copy) NSString *root;
@property(nonatomic) BOOL stopped;
@property(nonatomic) BOOL changed;
@end
@implementation HMTestEnvironment
- (int)openVerifiedContainer:(NSDictionary *)container error:(NSError **)error {
    if (self.changed || ![container[@"id"] isEqual:@"test-container"]) {
        if (error) *error = HMError(@"容器变化"); return -1;
    }
    return hm_open_dir(self.root.fileSystemRepresentation);
}
- (BOOL)targetStopped:(NSError **)error {
    if (!self.stopped && error) *error = HMError(@"仍在运行"); return self.stopped;
}
@end

static void Put(int docs, size_t index, const char *data) {
    CHECK(hm_write_new(docs, hm_names[index], data, strlen(data), 0640) == 0);
}
static NSDictionary *Fixture(NSString *base, NSString *label) {
    NSString *root = [base stringByAppendingPathComponent:label];
    CHECK([NSFileManager.defaultManager createDirectoryAtPath:[root stringByAppendingPathComponent:@"Documents"] withIntermediateDirectories:YES attributes:nil error:NULL]);
    return @{@"id":@"test-container", @"name":label, @"root":root, @"paths":@[]};
}

int main(void) {
    @autoreleasepool {
        char temporary[] = "/private/tmp/HMCleaner-tests-XXXXXX";
        CHECK(mkdtemp(temporary)); NSString *base = @(temporary);
        NSDictionary *container = Fixture(base, @"core");
        int root = hm_open_dir([container[@"root"] fileSystemRepresentation]); CHECK(root >= 0);
        int docs = hm_documents(root); CHECK(docs >= 0);
        Put(docs, 0, "first");
        HMFileState original; void *bytes = NULL;
        CHECK(hm_read_candidate(root, 0, &original, &bytes) == 0);
        CHECK(original.st.st_size == 5 && !memcmp(bytes, "first", 5));
        CHECK(hm_restore_candidate(root, 0, bytes, 5, original.sha, getuid(), getgid(), 0640) < 0 && errno == EEXIST);
        CHECK(hm_remove_candidate(root, 0, &original) == 0);
        HMFileState now;
        CHECK(hm_read_candidate(root, 0, &now, NULL) < 0 && errno == ENOENT);
        CHECK(hm_restore_candidate(root, 0, bytes, 5, original.sha, getuid(), getgid(), 0640) == 0);
        CHECK(hm_read_candidate(root, 0, &now, NULL) == 0 && !memcmp(now.sha, original.sha, 32));
        CHECK((now.st.st_mode & 0777) == 0640);
        free(bytes);
        // Same-length content mutation must not be accepted as the scanned file.
        CHECK(hm_read_candidate(root, 0, &original, NULL) == 0);
        int raw = openat(docs, hm_names[0], O_WRONLY); CHECK(raw >= 0);
        CHECK(write(raw, "other", 5) == 5); CHECK(close(raw) == 0);
        CHECK(hm_remove_candidate(root, 0, &original) < 0 && errno == ESTALE);
        CHECK(hm_read_candidate(root, 0, &now, NULL) == 0);
        // Reject traversal, absolute basename, invalid indexes and hardlinks.
        CHECK(hm_read(docs, "../anything", &now, NULL) < 0 && errno == EINVAL);
        CHECK(hm_write_new(docs, "/tmp/outside", "x", 1, 0600) < 0 && errno == EINVAL);
        CHECK(hm_remove_candidate(root, HM_FILE_COUNT, &now) < 0 && errno == EINVAL);
        CHECK(hm_open_dir([[container[@"root"] stringByAppendingString:@"/Documents/.."] UTF8String]) < 0 && errno == EINVAL);
        CHECK(linkat(docs, hm_names[0], docs, "hardlink", 0) == 0);
        CHECK(hm_read_candidate(root, 0, &now, NULL) < 0 && errno == EINVAL);
        CHECK(unlinkat(docs, "hardlink", 0) == 0);
        CHECK(symlinkat(hm_names[0], docs, hm_names[1]) == 0);
        CHECK(hm_read_candidate(root, 1, &now, NULL) < 0);
        CHECK(hm_restore_candidate(root, 1, "x", 1, original.sha, getuid(), getgid(), 0600) < 0);
        CHECK(unlinkat(docs, hm_names[1], 0) == 0);
        // FIFOs cannot block the reader; oversized files cannot be backed up/deleted.
        CHECK(mkfifoat(docs, hm_names[1], 0600) == 0);
        CHECK(hm_read_candidate(root, 1, &now, NULL) < 0 && errno == EINVAL);
        CHECK(unlinkat(docs, hm_names[1], 0) == 0);
        raw = openat(docs, hm_names[1], O_WRONLY | O_CREAT | O_EXCL, 0600); CHECK(raw >= 0);
        CHECK(ftruncate(raw, HM_MAX_BYTES + 1) == 0); close(raw);
        CHECK(hm_read_candidate(root, 1, &now, NULL) < 0 && errno == EINVAL);
        CHECK(unlinkat(docs, hm_names[1], 0) == 0);
        close(docs); close(root);

        NSDictionary *linkContainer = Fixture(base, @"link-parent");
        NSString *docsPath = [linkContainer[@"root"] stringByAppendingPathComponent:@"Documents"];
        CHECK(rmdir(docsPath.fileSystemRepresentation) == 0);
        CHECK(symlink([container[@"root"] fileSystemRepresentation], docsPath.fileSystemRepresentation) == 0);
        root = hm_open_dir([linkContainer[@"root"] fileSystemRepresentation]); CHECK(root >= 0);
        CHECK(hm_read_candidate(root, 0, &now, NULL) < 0); close(root);

        HMTestEnvironment *env = [HMTestEnvironment new]; env.stopped = YES;
        container = Fixture(base, @"engine"); env.root = container[@"root"];
        HMEngine *engine = [[HMEngine alloc] initWithEnvironment:env storePath:[base stringByAppendingPathComponent:@"Store/Backups"]];
        NSError *error = nil;
        NSArray *items = [engine scan:container error:&error];
        CHECK(items.count == HM_FILE_COUNT && !error);
        CHECK(![NSFileManager.defaultManager fileExistsAtPath:engine.storePath]);
        root = hm_open_dir(env.root.fileSystemRepresentation); docs = hm_documents(root);
        Put(docs, 0, "backup-me"); Put(docs, 1, "1"); close(docs); close(root);
        items = [engine scan:container error:&error]; ((HMScanItem *)items[0]).selected = YES;
        env.stopped = NO;
        CHECK(![engine clean:container items:items error:&error]);
        CHECK(![NSFileManager.defaultManager fileExistsAtPath:engine.storePath]);
        env.stopped = YES; error = nil;
        NSDictionary *record = [engine clean:container items:items error:&error];
        CHECK(record && !error && [record[@"entries"] count] == 1);
        CHECK([record[@"results"][0][@"result"] isEqual:@"已清理，复查不存在"]);
        root = hm_open_dir(env.root.fileSystemRepresentation);
        CHECK(hm_read_candidate(root, 0, &now, NULL) < 0 && errno == ENOENT);
        CHECK(hm_read_candidate(root, 1, &now, NULL) == 0); close(root);
        CHECK([[engine history:&error] count] == 1);
        NSDictionary *verification = [engine verify:record error:&error];
        CHECK([verification[@"results"][0][@"result"] isEqual:@"当前不存在"]);
        NSDictionary *restored = [engine restore:record error:&error];
        CHECK([restored[@"results"][0][@"result"] isEqual:@"已恢复文件内容"]);
        restored = [engine restore:record error:&error];
        CHECK([restored[@"results"][0][@"result"] isEqual:@"已有文件，未覆盖"]);
        env.changed = YES; error = nil;
        CHECK(![engine verify:record error:&error] && error); env.changed = NO;
        // Corrupt backup bytes: refusal even when the current file is absent.
        NSString *backupFile = [[engine.storePath stringByAppendingPathComponent:record[@"id"]] stringByAppendingPathComponent:@"file-0.bin"];
        raw = open(backupFile.fileSystemRepresentation, O_WRONLY | O_TRUNC); CHECK(raw >= 0);
        CHECK(write(raw, "corrupted", 9) == 9); close(raw);
        root = hm_open_dir(env.root.fileSystemRepresentation); docs = hm_documents(root);
        CHECK(unlinkat(docs, hm_names[0], 0) == 0); close(docs); close(root);
        error = nil; restored = [engine restore:record error:&error];
        CHECK([restored[@"results"][0][@"result"] isEqual:@"备份校验失败，未恢复"]);
        CHECK(![engine verify:@{@"id":@"../bad"} error:&error]);
        // Expiration before backup must never delete a selected file.
        error = nil; items = [engine scan:container error:&error]; ((HMScanItem *)items[1]).selected = YES;
        engine.cancelRequested = YES;
        CHECK(![engine clean:container items:items error:&error]);
        root = hm_open_dir(env.root.fileSystemRepresentation);
        CHECK(hm_read_candidate(root, 1, &now, NULL) == 0); close(root);
        // Preflight is batch-wide: changing the second selected file must leave the first intact.
        container = Fixture(base, @"batch"); env.root = container[@"root"];
        engine.cancelRequested = NO;
        root = hm_open_dir(env.root.fileSystemRepresentation); docs = hm_documents(root);
        Put(docs, 0, "keep-first"); Put(docs, 1, "old-second");
        error = nil; items = [engine scan:container error:&error];
        ((HMScanItem *)items[0]).selected = YES; ((HMScanItem *)items[1]).selected = YES;
        raw = openat(docs, hm_names[1], O_WRONLY | O_TRUNC); CHECK(raw >= 0);
        CHECK(write(raw, "new-second", 10) == 10); close(raw);
        CHECK(![engine clean:container items:items error:&error]);
        CHECK(hm_read_candidate(root, 0, &now, NULL) == 0 && now.st.st_size == 10);
        CHECK(hm_read_candidate(root, 1, &now, NULL) == 0 && now.st.st_size == 10);
        close(docs); close(root);
        printf("PASS %d checks; fixture directory: %s\n", checks, temporary);
    }
    return 0;
}
