#pragma once
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The core accepts an index into this closed list, never an imported path.
#define HM_FILE_COUNT 5
#define HM_MAX_BYTES (1024 * 1024)
extern const char *const hm_names[HM_FILE_COUNT];
typedef struct {
    struct stat st;
    unsigned char sha[32];
} HMFileState;

// Open each directory component without following symlinks. Reject dot/parent paths.
int hm_open_dir(const char *absolute);
int hm_documents(int root);
int hm_read(int directory, const char *basename, HMFileState *state, void **bytes);
bool hm_same(const HMFileState *a, const HMFileState *b);
int hm_read_candidate(int root, size_t index, HMFileState *state, void **bytes);
int hm_write_new(int directory, const char *basename, const void *bytes, size_t length,
                 mode_t mode);
// Backup must already be durable; expected is compared again after atomic detachment.
int hm_remove_candidate(int root, size_t index, const HMFileState *expected);
// Never replaces an existing file. Content is read back and hashed before publication.
int hm_restore_candidate(int root, size_t index, const void *bytes, size_t length,
                         const unsigned char sha[32], uid_t uid, gid_t gid, mode_t mode);
