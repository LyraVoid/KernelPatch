/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <kallsyms.h>
#include <pgtable.h>
#include <cache.h>
#include <log.h>
#include <common.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>
#include <kputils.h>
#include <linux/uaccess.h>

#define FOLKPATCH_UTS_SCAN_LEN 512
#define FOLKPATCH_UTS_VALUE_LEN 256

static char *uts_release;
static char *uts_version;
static int uts_release_limit;
static int uts_version_limit;
static char original_release[FOLKPATCH_UTS_VALUE_LEN];
static char original_version[FOLKPATCH_UTS_VALUE_LEN];
static int originals_saved;

static int folkpatch_uts_value_len(const char *value, int limit)
{
    int len = strnlen(value, limit + 1);
    return len <= limit ? len : -E2BIG;
}

static int folkpatch_uts_write(char *dst, const char *src, int len)
{
    uintptr_t start;
    uintptr_t end;

    if (!dst || !src || len <= 0) return -EINVAL;
    start = (uintptr_t)dst;
    end = start + (uintptr_t)len;
    if (end < start) return -EFAULT;

    while (start < end) {
        uintptr_t page_end = (start + page_size) & ~((uintptr_t)page_size - 1);
        uintptr_t chunk_end = end < page_end ? end : page_end;
        uintptr_t *entry = pgtable_entry_kernel(start);
        uintptr_t original_pte;
        uintptr_t writable_pte;
        int chunk_len;

        if (!entry || chunk_end <= start) return -EFAULT;
        chunk_len = (int)(chunk_end - start);
        original_pte = *entry;
        if (pte_valid_cont(original_pte)) return -EOPNOTSUPP;
        writable_pte = original_pte | PTE_DBM;
        writable_pte &= ~((uintptr_t)PTE_RDONLY);
        *entry = writable_pte;
        flush_tlb_kernel_page(start);
        memcpy((void *)start, src + (start - (uintptr_t)dst), chunk_len);
        dsb(ish);
        *entry = original_pte;
        flush_tlb_kernel_page(start);
        start = chunk_end;
    }

    __flush_dcache_area(dst, len);
    return 0;
}

static int folkpatch_uts_resolve(void)
{
    const char *base = (const char *)kallsyms_lookup_name("init_uts_ns");
    const char *name = NULL;
    const char *release = NULL;
    const char *version = NULL;
    const char *version_end = NULL;
    int offset;

    if (!base) return -ENOENT;

    for (offset = 0; offset <= 32; offset += 4) {
        if (!memcmp(base + offset, "Linux", 6)) {
            name = base + offset;
            break;
        }
    }
    if (!name) return -ENOENT;

    const char *scan = name;
    const char *end = name + FOLKPATCH_UTS_SCAN_LEN;
    while (scan < end) {
        int len;
        while (scan < end && *scan == '\0') scan++;
        if (scan >= end) break;
        len = strnlen(scan, end - scan);
        if (len <= 0 || scan + len >= end) break;

        if (scan != name && release && !version && scan[0] == '#') {
            version = scan;
        } else if (scan != name && !release && scan[0] >= '0' && scan[0] <= '9' &&
            memchr(scan, '.', len)) {
            release = scan;
        }
        if (version && scan != version && !version_end)
            version_end = scan;
        scan += len;
        if (release && version && version_end) break;
    }

    if (!release || !version || !version_end || version <= release || version_end <= version)
        return -ENOENT;
    uts_release_limit = (int)(version - release) - 1;
    if (uts_release_limit <= 0 || uts_release_limit >= FOLKPATCH_UTS_VALUE_LEN)
        return -E2BIG;

    uts_version_limit = (int)(version_end - version) - 1;
    if (uts_version_limit <= 0 || uts_version_limit >= FOLKPATCH_UTS_VALUE_LEN)
        return -E2BIG;
    uts_release = (char *)release;
    uts_version = (char *)version;
    return 0;
}

static int folkpatch_uts_save_originals(void)
{
    int release_len;
    int version_len;

    if (originals_saved) return 0;
    if (!uts_release || !uts_version) return -EINVAL;

    release_len = folkpatch_uts_value_len(uts_release, uts_release_limit);
    if (release_len < 0) return release_len;
    version_len = folkpatch_uts_value_len(uts_version, uts_version_limit);
    if (version_len < 0) return version_len;
    memcpy(original_release, uts_release, release_len + 1);
    memcpy(original_version, uts_version, version_len + 1);
    originals_saved = 1;
    return 0;
}

static int folkpatch_uts_copy(const char __user *src, char *dst, int limit)
{
    long len;

    if (!src) return 0;
    len = compat_strncpy_from_user(dst, src, FOLKPATCH_UTS_VALUE_LEN);
    if (len < 0) return -EFAULT;
    if (len >= FOLKPATCH_UTS_VALUE_LEN || len > limit) return -E2BIG;
    return (int)len;
}

long folkpatch_uts_set(const char __user *u_release,
                       const char __user *u_version)
{
    char release[FOLKPATCH_UTS_VALUE_LEN];
    char version[FOLKPATCH_UTS_VALUE_LEN];
    int release_len;
    int version_len;
    int rc;

    if (!uts_release) {
        rc = folkpatch_uts_resolve();
        if (rc) return rc;
    }
    rc = folkpatch_uts_save_originals();
    if (rc) return rc;

    release_len = folkpatch_uts_copy(u_release, release, uts_release_limit);
    if (release_len < 0) return release_len;
    version_len = folkpatch_uts_copy(u_version, version, uts_version_limit);
    if (version_len < 0) return version_len;

    if (u_release) {
        rc = folkpatch_uts_write(uts_release, release, release_len + 1);
        if (rc) return rc;
    }
    if (u_version) {
        rc = folkpatch_uts_write(uts_version, version, version_len + 1);
        if (rc && u_release)
            folkpatch_uts_write(uts_release, original_release,
                                strnlen(original_release, sizeof(original_release) - 1) + 1);
        return rc;
    }
    return 0;
}

long folkpatch_uts_reset(void)
{
    int rc;

    if (!originals_saved) return 0;
    rc = folkpatch_uts_write(uts_release, original_release,
                             strnlen(original_release, sizeof(original_release) - 1) + 1);
    if (rc) return rc;
    return folkpatch_uts_write(uts_version, original_version,
                               strnlen(original_version, sizeof(original_version) - 1) + 1);
}
