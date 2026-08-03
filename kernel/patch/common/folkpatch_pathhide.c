/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <uapi/asm-generic/errno.h>
#include <folkpatch_pathhide.h>

#define FOLKPATCH_PATHHIDE_MAX_PATHS 256
#define FOLKPATCH_PATHHIDE_MAX_UIDS 256
#define FOLKPATCH_PATHHIDE_MAX_PATH_LEN 512

struct folkpatch_pathhide_state {
    char paths[FOLKPATCH_PATHHIDE_MAX_PATHS][FOLKPATCH_PATHHIDE_MAX_PATH_LEN];
    uid_t uids[FOLKPATCH_PATHHIDE_MAX_UIDS];
    int path_count;
    int uid_count;
    int enabled;
    int uid_mode;
    int filter_system;
    spinlock_t lock;
};

static struct folkpatch_pathhide_state pathhide;

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

int folkpatch_pathhide_init(void)
{
    memset(&pathhide, 0, sizeof(pathhide));
    spin_lock_init(&pathhide.lock);
    return 0;
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
    return rc == 0 ? pos : -EFAULT;
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
    return rc == 0 ? pos : -EFAULT;
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
