#include "HMFileStore.h"
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *const hm_names[HM_FILE_COUNT] = {
    ".PID4SM.txt", "FP_SEQ.txt", "come2", "PdnuLKiM",
    ".thumbcache_ED91762CA5ED7B556B28BA051E9F978D"
};

static bool hm_basename(const char *s) {
    return s && *s && strcmp(s, ".") && strcmp(s, "..") && !strchr(s, '/') &&
           strlen(s) <= NAME_MAX;
}
static int hm_close_error(int fd, int error) { if (fd >= 0) close(fd); errno = error; return -1; }

int hm_open_dir(const char *absolute) {
    if (!absolute || absolute[0] != '/' || !absolute[1] || strlen(absolute) >= PATH_MAX) {
        errno = EINVAL; return -1;
    }
    char path[PATH_MAX]; strlcpy(path, absolute + 1, sizeof(path));
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    char *cursor = path, *part;
    while ((part = strsep(&cursor, "/"))) {
        if (!hm_basename(part)) return hm_close_error(fd, EINVAL);
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int e = errno; close(fd);
        if (next < 0) { errno = e; return -1; }
        fd = next;
    }
    return fd;
}

int hm_documents(int root) {
    return openat(root, "Documents", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static bool hm_metadata_equal(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_nlink == b->st_nlink && a->st_flags == b->st_flags &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
        a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}

int hm_read(int directory, const char *basename, HMFileState *state, void **bytes) {
    if (bytes) *bytes = NULL;
    if (!hm_basename(basename) || !state) { errno = EINVAL; return -1; }
    int fd = openat(directory, basename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    struct stat first, last;
    if (fstat(fd, &first)) return hm_close_error(fd, errno);
    if (!S_ISREG(first.st_mode) || first.st_nlink != 1 || first.st_size < 0 ||
        first.st_size > HM_MAX_BYTES) return hm_close_error(fd, EINVAL);
    size_t size = (size_t)first.st_size;
    unsigned char *data = malloc(size ? size : 1);
    if (!data) return hm_close_error(fd, ENOMEM);
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = read(fd, data + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { int e = count < 0 ? errno : ESTALE; free(data); return hm_close_error(fd, e); }
        offset += (size_t)count;
    }
    if (fstat(fd, &last)) { int e = errno; free(data); return hm_close_error(fd, e); }
    if (!hm_metadata_equal(&first, &last)) { free(data); return hm_close_error(fd, ESTALE); }
    close(fd);
    state->st = last;
    CC_SHA256(data, (CC_LONG)size, state->sha);
    if (bytes) *bytes = data; else free(data);
    return 0;
}

bool hm_same(const HMFileState *a, const HMFileState *b) {
    return hm_metadata_equal(&a->st, &b->st) && !memcmp(a->sha, b->sha, 32);
}

int hm_read_candidate(int root, size_t index, HMFileState *state, void **bytes) {
    if (index >= HM_FILE_COUNT) { errno = EINVAL; return -1; }
    int docs = hm_documents(root);
    if (docs < 0) return -1;
    int r = hm_read(docs, hm_names[index], state, bytes), e = errno;
    close(docs); errno = e; return r;
}

int hm_write_new(int directory, const char *basename, const void *bytes, size_t length, mode_t mode) {
    if (!hm_basename(basename) || length > HM_MAX_BYTES || (!bytes && length)) { errno = EINVAL; return -1; }
    int fd = openat(directory, basename, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = write(fd, (const char *)bytes + offset, length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            int e = n < 0 ? errno : EIO; close(fd); unlinkat(directory, basename, 0); errno = e; return -1;
        }
        offset += (size_t)n;
    }
    if (fchmod(fd, mode & 0777) || fsync(fd)) {
        int e = errno; close(fd); unlinkat(directory, basename, 0); errno = e; return -1;
    }
    if (close(fd)) { int e = errno; unlinkat(directory, basename, 0); errno = e; return -1; }
    return 0;
}

int hm_remove_candidate(int root, size_t index, const HMFileState *expected) {
    if (index >= HM_FILE_COUNT || !expected) { errno = EINVAL; return -1; }
    int docs = hm_documents(root);
    if (docs < 0) return -1;
    HMFileState current;
    if (hm_read(docs, hm_names[index], &current, NULL)) return hm_close_error(docs, errno);
    if (!hm_same(expected, &current)) return hm_close_error(docs, ESTALE);
    char temporary[100];
    snprintf(temporary, sizeof(temporary), ".hmcleaner-%08x-%08x.pending", arc4random(), arc4random());
    if (renameatx_np(docs, hm_names[index], docs, temporary, RENAME_EXCL)) return hm_close_error(docs, errno);
    HMFileState moved;
    // Renaming changes ctime on some filesystems; verify identity, bytes and original mode instead.
    if (hm_read(docs, temporary, &moved, NULL) || moved.st.st_dev != expected->st.st_dev ||
        moved.st.st_ino != expected->st.st_ino || moved.st.st_size != expected->st.st_size ||
        moved.st.st_mode != expected->st.st_mode || moved.st.st_uid != expected->st.st_uid ||
        moved.st.st_gid != expected->st.st_gid || memcmp(moved.sha, expected->sha, 32)) {
        int restored = renameatx_np(docs, temporary, docs, hm_names[index], RENAME_EXCL);
        return hm_close_error(docs, restored == 0 ? ESTALE : EBUSY);
    }
    if (unlinkat(docs, temporary, 0)) {
        int e = errno;
        if (renameatx_np(docs, temporary, docs, hm_names[index], RENAME_EXCL)) e = EBUSY;
        return hm_close_error(docs, e);
    }
    // The manifest keeps a pending entry if the process is interrupted here; backup survives.
    if (fsync(docs)) return hm_close_error(docs, errno);
    struct stat st;
    if (!fstatat(docs, hm_names[index], &st, AT_SYMLINK_NOFOLLOW)) return hm_close_error(docs, EBUSY);
    if (errno != ENOENT) return hm_close_error(docs, errno);
    close(docs); return 0;
}

int hm_restore_candidate(int root, size_t index, const void *bytes, size_t length,
                         const unsigned char sha[32], uid_t uid, gid_t gid, mode_t mode) {
    if (index >= HM_FILE_COUNT || !sha) { errno = EINVAL; return -1; }
    int docs = hm_documents(root);
    if (docs < 0) return -1; // Never constructs missing Documents/container directories.
    char temporary[100];
    snprintf(temporary, sizeof(temporary), ".hmcleaner-%08x-%08x.restore", arc4random(), arc4random());
    if (hm_write_new(docs, temporary, bytes, length, mode)) return hm_close_error(docs, errno);
    HMFileState check;
    int r = hm_read(docs, temporary, &check, NULL);
    if (r || memcmp(check.sha, sha, 32)) {
        int e = r ? errno : EBADMSG; unlinkat(docs, temporary, 0); return hm_close_error(docs, e);
    }
    int fd = openat(docs, temporary, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { int e = errno; unlinkat(docs, temporary, 0); return hm_close_error(docs, e); }
    if ((check.st.st_uid != uid || check.st.st_gid != gid) && fchown(fd, uid, gid)) {
        int e = errno; close(fd); unlinkat(docs, temporary, 0); return hm_close_error(docs, e);
    }
    if (fchmod(fd, mode & 0777) || fsync(fd)) {
        int e = errno; close(fd); unlinkat(docs, temporary, 0); return hm_close_error(docs, e);
    }
    close(fd);
    if (renameatx_np(docs, temporary, docs, hm_names[index], RENAME_EXCL)) {
        int e = errno; unlinkat(docs, temporary, 0); return hm_close_error(docs, e);
    }
    if (fsync(docs)) return hm_close_error(docs, errno);
    close(docs); return 0;
}
