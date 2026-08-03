/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <kallsyms.h>
#include <hook.h>
#include <asm/current.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <kputils.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <folkpatch_pathhide.h>

#define FOLKPATCH_PATHHIDE_MAX_PATHS 256
#define FOLKPATCH_PATHHIDE_MAX_UIDS 256
#define FOLKPATCH_PATHHIDE_MAX_PATH_LEN 512
#define FOLKPATCH_PATHHIDE_DIRENT_LEN 4096
#define AT_FDCWD (-100)
#define DENT64_RECLEN_OFF 16
#define DENT64_NAME_OFF 19

struct folkpatch_pathhide_state {
    char paths[FOLKPATCH_PATHHIDE_MAX_PATHS][FOLKPATCH_PATHHIDE_MAX_PATH_LEN];
    uid_t uids[FOLKPATCH_PATHHIDE_MAX_UIDS];
    int path_count;
    int uid_count;
    int enabled;
    int uid_mode;
    int filter_system;
    int hooks_ready;
    uid_t manager_uid;
    spinlock_t lock;
};

static struct folkpatch_pathhide_state pathhide;
static void *(*pathhide_fget)(unsigned int);
static void (*pathhide_fput)(void *);
static char *(*pathhide_file_path)(void *, char *, int);
static unsigned long (*pathhide_copy_from_user)(void *, const void __user *, unsigned long);

static int folkpatch_pathhide_copy_path(const char __user *path, char *out)
{
    long len;

    if (!path || !out) return -EINVAL;
    len = compat_strncpy_from_user(out, path, FOLKPATCH_PATHHIDE_MAX_PATH_LEN);
    if (len <= 0) return -EINVAL;
    if (len >= FOLKPATCH_PATHHIDE_MAX_PATH_LEN) return -ENAMETOOLONG;
    if (out[0] != '/') return -EINVAL;
    return (int)len;
}

static int folkpatch_pathhide_match(const char *path, const char *blocked)
{
    int len = strlen(blocked);
    return !strncmp(path, blocked, len) && (path[len] == '\0' || path[len] == '/');
}

static int folkpatch_pathhide_should_filter(void)
{
    uid_t uid = current_uid();
    int i;
    int result = 1;
    unsigned long flags = spin_lock_irqsave(&pathhide.lock);

    if (!pathhide.enabled || uid == pathhide.manager_uid) result = 0;
    else if (!pathhide.uid_mode)
        result = uid >= 10000 || pathhide.filter_system;
    else if (uid == 0)
        result = pathhide.filter_system;
    else {
        result = 0;
        for (i = 0; i < pathhide.uid_count; i++) {
            if (pathhide.uids[i] == uid) {
                result = 1;
                break;
            }
        }
    }
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return result;
}

static int folkpatch_pathhide_is_blocked(const char *path)
{
    int i;
    int blocked = 0;
    unsigned long flags = spin_lock_irqsave(&pathhide.lock);
    for (i = 0; i < pathhide.path_count; i++) {
        if (folkpatch_pathhide_match(path, pathhide.paths[i])) {
            blocked = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return blocked;
}

static int folkpatch_pathhide_fd_path(int fd, char *out, int out_len)
{
    void *file;
    char *path;

    if (!pathhide_fget || !pathhide_fput || !pathhide_file_path) return -ENOSYS;
    file = pathhide_fget((unsigned int)fd);
    if (!file) return -EBADF;
    path = pathhide_file_path(file, out, out_len);
    pathhide_fput(file);
    if (IS_ERR_OR_NULL(path)) return -ENOENT;
    if (path != out) memmove(out, path, strlen(path) + 1);
    return 0;
}

static int folkpatch_pathhide_resolve(int dfd, const char *name, char *out, int out_len)
{
    int len;
    char parent[FOLKPATCH_PATHHIDE_MAX_PATH_LEN];

    if (name[0] == '/') {
        len = strlen(name);
        if (len >= out_len) return -ENAMETOOLONG;
        memcpy(out, name, len + 1);
        return 0;
    }
    if (dfd == AT_FDCWD) return -EOPNOTSUPP;
    if (folkpatch_pathhide_fd_path(dfd, parent, sizeof(parent))) return -ENOENT;
    len = snprintf(out, out_len, "%s/%s", parent, name);
    return len > 0 && len < out_len ? 0 : -ENAMETOOLONG;
}

static void folkpatch_pathhide_before_path(hook_fargs4_t *args, void *udata)
{
    char raw[FOLKPATCH_PATHHIDE_MAX_PATH_LEN];
    char resolved[FOLKPATCH_PATHHIDE_MAX_PATH_LEN];
    const char __user *name;
    int dfd;

    (void)udata;
    if (!folkpatch_pathhide_should_filter()) return;
    dfd = (int)syscall_argn(args, 0);
    name = (const char __user *)syscall_argn(args, 1);
    if (compat_strncpy_from_user(raw, name, sizeof(raw)) <= 0) return;
    if (folkpatch_pathhide_resolve(dfd, raw, resolved, sizeof(resolved))) return;
    if (folkpatch_pathhide_is_blocked(resolved)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

static int folkpatch_pathhide_filter_dirents(char *data, int len, const char *dir)
{
    int pos = 0;
    int out = 0;
    char full[FOLKPATCH_PATHHIDE_MAX_PATH_LEN];

    while (pos < len) {
        uint16_t record_len;
        char *name;
        int full_len;
        if (pos + DENT64_NAME_OFF >= len) return -EIO;
        record_len = *(uint16_t *)(data + pos + DENT64_RECLEN_OFF);
        if (record_len < DENT64_NAME_OFF + 1 || pos + record_len > len) return -EIO;
        name = data + pos + DENT64_NAME_OFF;
        if (!memchr(name, '\0', record_len - DENT64_NAME_OFF)) return -EIO;
        full_len = snprintf(full, sizeof(full), "%s/%s", dir, name);
        if (full_len <= 0 || full_len >= sizeof(full) ||
            !folkpatch_pathhide_is_blocked(full)) {
            if (out != pos) memmove(data + out, data + pos, record_len);
            out += record_len;
        }
        pos += record_len;
    }
    return out;
}

static void folkpatch_pathhide_after_getdents64(hook_fargs4_t *args, void *udata)
{
    char dir[FOLKPATCH_PATHHIDE_MAX_PATH_LEN];
    char *snapshot;
    void __user *user_data;
    int len = (int)(long)args->ret;
    int filtered;

    (void)udata;
    if (len <= 0 || len > FOLKPATCH_PATHHIDE_DIRENT_LEN ||
        !folkpatch_pathhide_should_filter()) return;
    if (folkpatch_pathhide_fd_path((int)syscall_argn(args, 0), dir, sizeof(dir))) return;
    snapshot = vmalloc(len);
    if (!snapshot) return;
    user_data = (void __user *)syscall_argn(args, 1);
    if (!pathhide_copy_from_user || pathhide_copy_from_user(snapshot, user_data, len)) {
        vfree(snapshot);
        return;
    }
    filtered = folkpatch_pathhide_filter_dirents(snapshot, len, dir);
    if (filtered >= 0 && filtered < len &&
        compat_copy_to_user(user_data, snapshot, filtered) == filtered)
        args->ret = filtered;
    vfree(snapshot);
}

int folkpatch_pathhide_init(void)
{
    hook_err_t openat;
    hook_err_t faccessat;
    hook_err_t newfstatat;
    hook_err_t getdents64;

    memset(&pathhide, 0, sizeof(pathhide));
    spin_lock_init(&pathhide.lock);
    pathhide_fget = (void *)kallsyms_lookup_name("fget");
    pathhide_fput = (void *)kallsyms_lookup_name("fput");
    pathhide_file_path = (void *)kallsyms_lookup_name("file_path");
    pathhide_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (!pathhide_copy_from_user)
        pathhide_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");
    openat = fp_hook_syscalln(__NR_openat, 4, folkpatch_pathhide_before_path, 0, 0);
    faccessat = fp_hook_syscalln(__NR_faccessat, 3, folkpatch_pathhide_before_path, 0, 0);
    newfstatat = fp_hook_syscalln(__NR3264_fstatat, 4, folkpatch_pathhide_before_path, 0, 0);
    getdents64 = fp_hook_syscalln(__NR_getdents64, 3, 0,
                                  folkpatch_pathhide_after_getdents64, 0);
    pathhide.hooks_ready = !openat && !faccessat && !newfstatat && !getdents64 &&
                           pathhide_fget && pathhide_fput && pathhide_file_path &&
                           pathhide_copy_from_user;
    return pathhide.hooks_ready ? 0 : -ENOSYS;
}

long folkpatch_pathhide_add(const char __user *path)
{
    char value[FOLKPATCH_PATHHIDE_MAX_PATH_LEN];
    unsigned long flags;
    int i;
    int len = folkpatch_pathhide_copy_path(path, value);

    if (len < 0) return len;
    flags = spin_lock_irqsave(&pathhide.lock);
    for (i = 0; i < pathhide.path_count; i++) {
        if (!strcmp(pathhide.paths[i], value)) {
            spin_unlock_irqrestore(&pathhide.lock, flags);
            return 0;
        }
    }
    if (pathhide.path_count >= FOLKPATCH_PATHHIDE_MAX_PATHS) {
        spin_unlock_irqrestore(&pathhide.lock, flags);
        return -ENOSPC;
    }
    memcpy(pathhide.paths[pathhide.path_count++], value, len + 1);
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return 0;
}

long folkpatch_pathhide_remove(const char __user *path)
{
    char value[FOLKPATCH_PATHHIDE_MAX_PATH_LEN];
    unsigned long flags;
    int i;
    int len = folkpatch_pathhide_copy_path(path, value);

    if (len < 0) return len;
    flags = spin_lock_irqsave(&pathhide.lock);
    for (i = 0; i < pathhide.path_count; i++) {
        if (!strcmp(pathhide.paths[i], value)) {
            pathhide.path_count--;
            if (i != pathhide.path_count)
                memcpy(pathhide.paths[i], pathhide.paths[pathhide.path_count],
                       FOLKPATCH_PATHHIDE_MAX_PATH_LEN);
            spin_unlock_irqrestore(&pathhide.lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return -ENOENT;
}

long folkpatch_pathhide_list(char __user *out, int out_len)
{
    char *snapshot;
    int pos = 0;
    int i;
    int rc;
    unsigned long flags;

    if (!out || out_len <= 0) return -EINVAL;
    snapshot = vmalloc(FOLKPATCH_PATHHIDE_MAX_PATHS * FOLKPATCH_PATHHIDE_MAX_PATH_LEN);
    if (!snapshot) return -ENOMEM;
    flags = spin_lock_irqsave(&pathhide.lock);
    for (i = 0; i < pathhide.path_count; i++) {
        int remaining = FOLKPATCH_PATHHIDE_MAX_PATHS * FOLKPATCH_PATHHIDE_MAX_PATH_LEN - pos;
        int written = snprintf(snapshot + pos, remaining, "%s\n", pathhide.paths[i]);
        if (written < 0 || written >= remaining) break;
        pos += written;
    }
    spin_unlock_irqrestore(&pathhide.lock, flags);
    if (pos > out_len) {
        vfree(snapshot);
        return -ENOBUFS;
    }
    rc = compat_copy_to_user(out, snapshot, pos);
    vfree(snapshot);
    return rc == pos ? pos : -EFAULT;
}

long folkpatch_pathhide_clear(void)
{
    unsigned long flags = spin_lock_irqsave(&pathhide.lock);
    pathhide.path_count = 0;
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return 0;
}

long folkpatch_pathhide_enable(int enable)
{
    unsigned long flags = spin_lock_irqsave(&pathhide.lock);
    if (enable && !pathhide.hooks_ready) {
        spin_unlock_irqrestore(&pathhide.lock, flags);
        return -ENOSYS;
    }
    if (enable) pathhide.manager_uid = current_uid();
    pathhide.enabled = !!enable;
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return 0;
}

long folkpatch_pathhide_status(void)
{
    int enabled;
    int count;
    unsigned long flags = spin_lock_irqsave(&pathhide.lock);
    enabled = pathhide.enabled;
    count = pathhide.path_count;
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return ((long)enabled << 32) | (unsigned int)count;
}

long folkpatch_pathhide_uid_add(uid_t uid)
{
    unsigned long flags;
    int i;

    if (!uid) return -EINVAL;
    flags = spin_lock_irqsave(&pathhide.lock);
    for (i = 0; i < pathhide.uid_count; i++) {
        if (pathhide.uids[i] == uid) {
            spin_unlock_irqrestore(&pathhide.lock, flags);
            return 0;
        }
    }
    if (pathhide.uid_count >= FOLKPATCH_PATHHIDE_MAX_UIDS) {
        spin_unlock_irqrestore(&pathhide.lock, flags);
        return -ENOSPC;
    }
    pathhide.uids[pathhide.uid_count++] = uid;
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return 0;
}

long folkpatch_pathhide_uid_remove(uid_t uid)
{
    unsigned long flags;
    int i;

    if (!uid) return -EINVAL;
    flags = spin_lock_irqsave(&pathhide.lock);
    for (i = 0; i < pathhide.uid_count; i++) {
        if (pathhide.uids[i] == uid) {
            pathhide.uid_count--;
            pathhide.uids[i] = pathhide.uids[pathhide.uid_count];
            spin_unlock_irqrestore(&pathhide.lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return -ENOENT;
}

long folkpatch_pathhide_uid_list(char __user *out, int out_len)
{
    char *snapshot;
    int pos = 0;
    int i;
    int rc;
    unsigned long flags;

    if (!out || out_len <= 0) return -EINVAL;
    snapshot = vmalloc(FOLKPATCH_PATHHIDE_MAX_UIDS * 12);
    if (!snapshot) return -ENOMEM;
    flags = spin_lock_irqsave(&pathhide.lock);
    for (i = 0; i < pathhide.uid_count; i++) {
        int remaining = FOLKPATCH_PATHHIDE_MAX_UIDS * 12 - pos;
        int written = snprintf(snapshot + pos, remaining, "%u\n", pathhide.uids[i]);
        if (written < 0 || written >= remaining) break;
        pos += written;
    }
    spin_unlock_irqrestore(&pathhide.lock, flags);
    if (pos > out_len) {
        vfree(snapshot);
        return -ENOBUFS;
    }
    rc = compat_copy_to_user(out, snapshot, pos);
    vfree(snapshot);
    return rc == pos ? pos : -EFAULT;
}

long folkpatch_pathhide_uid_clear(void)
{
    unsigned long flags = spin_lock_irqsave(&pathhide.lock);
    pathhide.uid_count = 0;
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return 0;
}

long folkpatch_pathhide_uid_mode(int enable)
{
    unsigned long flags = spin_lock_irqsave(&pathhide.lock);
    pathhide.uid_mode = !!enable;
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return 0;
}

long folkpatch_pathhide_filter_system(int enable)
{
    unsigned long flags = spin_lock_irqsave(&pathhide.lock);
    pathhide.filter_system = !!enable;
    spin_unlock_irqrestore(&pathhide.lock, flags);
    return 0;
}
