/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <linux/errno.h>
#include <asm/atomic.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <uapi/asm-generic/errno.h>
#include <kstorage.h>
#include <kputils.h>
#include <log.h>
#include <folkpatch_suaudit.h>

#define FOLKPATCH_SUAUDIT_MAX_ENTRIES 256

static int audit_gid = -1;
static atomic64_t audit_sequence = { .counter = 0 };

static int folkpatch_suaudit_trim(void)
{
    int count = kstorage_group_size(audit_gid);
    long *ids;
    int num;
    int remove_count;
    int i;
    int rc = 0;

    if (count <= FOLKPATCH_SUAUDIT_MAX_ENTRIES) return 0;
    ids = vmalloc((size_t)count * sizeof(*ids));
    if (!ids) return -ENOMEM;
    num = list_kstorage_ids(audit_gid, ids, count, false);
    if (num < 0) {
        vfree(ids);
        return num;
    }

    remove_count = num - FOLKPATCH_SUAUDIT_MAX_ENTRIES;
    for (i = 0; i < remove_count; i++) {
        int j;
        int oldest = i;
        for (j = i + 1; j < num; j++) {
            if (ids[j] < ids[oldest]) oldest = j;
        }
        if (oldest != i) {
            long tmp = ids[i];
            ids[i] = ids[oldest];
            ids[oldest] = tmp;
        }
        if (remove_kstorage(audit_gid, ids[i]) < 0 && !rc) rc = -EIO;
    }
    vfree(ids);
    return rc;
}

int folkpatch_suaudit_init(void)
{
    int rc;

    atomic64_set(&audit_sequence, 0);
    audit_gid = try_alloc_kstroage_group();
    if (audit_gid != KSTORAGE_SU_AUDIT_GROUP) {
        logkfe("group alloc mismatch: got %d want %d\n",
               audit_gid, KSTORAGE_SU_AUDIT_GROUP);
        audit_gid = -1;
        return -ENOMEM;
    }
    rc = folkpatch_suaudit_trim();
    logkfi("audit_gid=%d trim=%d\n", audit_gid, rc);
    return rc < 0 ? rc : 0;
}

void folkpatch_suaudit_record(uid_t uid, pid_t pid, pid_t tgid,
                              uid_t to_uid, const char *scontext,
                              const char *comm)
{
    struct su_audit_entry entry = { 0 };
    long sequence;

    if (audit_gid < 0 || uid == 0) return;
    sequence = atomic64_inc_return(&audit_sequence);
    if (sequence < 0) return;
    entry.timestamp = (u64)sequence;
    entry.uid = uid;
    entry.pid = pid;
    entry.tgid = tgid;
    entry.to_uid = to_uid;
    if (scontext) strncpy(entry.scontext, scontext, sizeof(entry.scontext) - 1);
    if (comm) strncpy(entry.comm, comm, sizeof(entry.comm) - 1);

    if (write_kstorage(audit_gid, sequence, &entry, 0, sizeof(entry), false)) {
        logkfe("write failed gid=%d seq=%ld uid=%d\n", audit_gid, sequence, uid);
    } else {
        logkfi("recorded seq=%ld uid=%d to_uid=%d comm='%s'\n",
               sequence, uid, to_uid, entry.comm);
        folkpatch_suaudit_trim();
    }
}

long folkpatch_suaudit_list(struct su_audit_entry __user *entries, int num)
{
    struct su_audit_entry *snapshot;
    long *ids;
    int count;
    int i;
    int copied;

    if (num < 0 || num > FOLKPATCH_SUAUDIT_MAX_ENTRIES) return -EINVAL;
    count = kstorage_group_size(audit_gid);
    if (count < 0) return count;
    if (num == 0) {
        logkfi("count=%d gid=%d\n", count, audit_gid);
        return count;
    }
    if (!entries) return -EFAULT;
    if (count > num) count = num;
    if (!count) return 0;

    ids = vmalloc((size_t)count * sizeof(*ids));
    snapshot = vmalloc((size_t)count * sizeof(*snapshot));
    if (!ids || !snapshot) {
        vfree(ids);
        vfree(snapshot);
        return -ENOMEM;
    }
    count = list_kstorage_ids(audit_gid, ids, count, false);
    if (count < 0) {
        vfree(ids);
        vfree(snapshot);
        return count;
    }
    for (i = 0; i < count; i++) {
        if (read_kstorage(audit_gid, ids[i], &snapshot[i], 0,
                          sizeof(snapshot[i]), false)) {
            vfree(ids);
            vfree(snapshot);
            return -EIO;
        }
    }
    for (i = 0; i < count; i++) {
        int j;
        int newest = i;
        for (j = i + 1; j < count; j++) {
            if (snapshot[j].timestamp > snapshot[newest].timestamp) newest = j;
        }
        if (newest != i) {
            struct su_audit_entry tmp = snapshot[i];
            snapshot[i] = snapshot[newest];
            snapshot[newest] = tmp;
        }
    }
    vfree(ids);
    copied = compat_copy_to_user(entries, snapshot,
                                 (size_t)count * sizeof(*snapshot));
    vfree(snapshot);
    /* compat_copy_to_user returns the number of bytes copied (== len on
     * success), not the kernel's 0-on-success convention. */
    return copied == (size_t)count * sizeof(*snapshot) ? count : -EFAULT;
}

long folkpatch_suaudit_clear(void)
{
    long *ids;
    int count;
    int i;

    if (audit_gid < 0) return 0;
    count = kstorage_group_size(audit_gid);
    if (count <= 0) return count;
    ids = vmalloc((size_t)count * sizeof(*ids));
    if (!ids) return -ENOMEM;
    count = list_kstorage_ids(audit_gid, ids, count, false);
    if (count >= 0) {
        for (i = 0; i < count; i++) remove_kstorage(audit_gid, ids[i]);
        atomic64_set(&audit_sequence, 0);
    }
    vfree(ids);
    return count;
}
