/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <pgtable.h>
#include <cache.h>
#include <log.h>
#include <common.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <kputils.h>
#include <linux/uaccess.h>

/* Resolved field addresses (all dynamically discovered at runtime) */
static const char *uts_release_addr;
static const char *uts_version_addr;

/* Write limits: distance to adjacent field, measured dynamically */
static int max_release_len;
static int max_version_len;

/* Original value backups (saved once on first spoof call) */
static char ori_release[256];
static char ori_version[256];
static int ori_release_len;
static int ori_version_len;
static int backup_saved;

static int safe_write_memory(void *dst, const void *src, int len)
{
    if (!dst || !src || len <= 0) return -EINVAL;

    uintptr_t va = (uintptr_t)dst;
    uintptr_t end_va = va + len;
    uintptr_t tp_mask = (((1ul << (48 - page_shift)) - 1) << page_shift);

    while (va < end_va) {
        uintptr_t page_end = (va + page_size) & ~((uintptr_t)page_size - 1);
        uintptr_t chunk_end = (end_va < page_end) ? end_va : page_end;
        int chunk_off = (int)(va - (uintptr_t)dst);
        int chunk_len = (int)(chunk_end - va);

        uintptr_t *entry = pgtable_entry_kernel(va);
        if (!entry) return -EFAULT;

        uintptr_t ori_prot = *entry;
        uintptr_t new_prot = (ori_prot | PTE_DBM) & ~((uintptr_t)PTE_RDONLY);

        if (pte_valid_cont(ori_prot) || pte_valid_cont(new_prot)) {
            uintptr_t prot_bits = new_prot & ~tp_mask;
            uintptr_t *p = (uintptr_t *)((uintptr_t)entry & ~((uintptr_t)sizeof(entry) * CONT_PTES - 1));
            for (int i = 0; i < CONT_PTES; ++i, ++p)
                *p = (*p & tp_mask) | prot_bits;
            *entry = new_prot;
            uintptr_t flush_va = va & CONT_PTE_MASK;
            flush_tlb_kernel_range(flush_va, flush_va + CONT_PTES * page_size);
        } else {
            *entry = new_prot;
            flush_tlb_kernel_page(va);
        }

        memcpy((void *)va, (const char *)src + chunk_off, chunk_len);
        dsb(ish);

        if (pte_valid_cont(ori_prot)) {
            uintptr_t prot_bits = ori_prot & ~tp_mask;
            uintptr_t *p = (uintptr_t *)((uintptr_t)entry & ~((uintptr_t)sizeof(entry) * CONT_PTES - 1));
            for (int i = 0; i < CONT_PTES; ++i, ++p)
                *p = (*p & tp_mask) | prot_bits;
            *entry = ori_prot;
            uintptr_t flush_va = va & CONT_PTE_MASK;
            flush_tlb_kernel_range(flush_va, flush_va + CONT_PTES * page_size);
        } else {
            *entry = ori_prot;
            flush_tlb_kernel_page(va);
        }

        va = chunk_end;
    }

    __flush_dcache_area(dst, len);
    return 0;
}

static int versionspoof_resolve(void)
{
    void *uts_ns = (void *)kallsyms_lookup_name("init_uts_ns");
    if (!uts_ns) {
        logke("versionspoof: failed to resolve init_uts_ns\n");
        return -ENOENT;
    }

    /* Probe for "Linux" to find the name field start within struct uts_namespace */
    const char *name_start = NULL;
    for (int off = 0; off <= 32; off += 4) {
        const char *p = (const char *)uts_ns + off;
        if (p[0] == 'L' && p[1] == 'i' && p[2] == 'n' &&
            p[3] == 'u' && p[4] == 'x' && p[5] == '\0') {
            name_start = p;
            break;
        }
    }
    if (!name_start) {
        logke("versionspoof: failed to probe name offset in init_uts_ns\n");
        return -ENOENT;
    }

    /* Scan for fields by content pattern — no hardcoded offsets or field sizes.
     *   release: first string starting with a digit and containing '.'
     *   version: first string starting with '#'
     *   machine: "aarch64" (used to bound the version field write limit) */
    const char *release_ptr = NULL;
    const char *version_ptr = NULL;
    const char *machine_ptr = NULL;

    const char *scan = name_start;
    const char *scan_end = name_start + 512;

    while (scan < scan_end) {
        while (scan < scan_end && *scan == '\0') scan++;
        if (scan >= scan_end) break;

        int slen = strnlen(scan, scan_end - scan);
        if (slen <= 0) break;

        /* Skip sysname ("Linux") */
        if (scan == name_start) {
            scan += slen;
            continue;
        }

        if (!release_ptr && slen > 1 &&
            scan[0] >= '0' && scan[0] <= '9' && memchr(scan, '.', slen)) {
            release_ptr = scan;
        } else if (!version_ptr && scan[0] == '#' && slen > 2) {
            version_ptr = scan;
        } else if (!machine_ptr && slen == 7 && !memcmp(scan, "aarch64", 7)) {
            machine_ptr = scan;
        }

        if (release_ptr && version_ptr && machine_ptr) break;
        scan += slen;
    }

    if (!release_ptr || !version_ptr) {
        logke("versionspoof: failed to locate fields (release=%p version=%p)\n",
              release_ptr, version_ptr);
        return -ENOENT;
    }

    uts_release_addr = release_ptr;
    uts_version_addr = version_ptr;

    /* Write limits = distance to adjacent field, minus 1 for NUL */
    max_release_len = (int)(version_ptr - release_ptr) - 1;
    max_version_len = machine_ptr ? (int)(machine_ptr - version_ptr) - 1 : 128;

    logkfi("versionspoof: release=%llx(%d) version=%llx(%d)\n",
           (uint64_t)uts_release_addr, max_release_len,
           (uint64_t)uts_version_addr, max_version_len);
    return 0;
}

static void versionspoof_backup_originals(void)
{
    if (backup_saved) return;

    if (uts_release_addr) {
        strncpy(ori_release, uts_release_addr, sizeof(ori_release) - 1);
        ori_release[sizeof(ori_release) - 1] = '\0';
        ori_release_len = strnlen(ori_release, sizeof(ori_release) - 1);
    }
    if (uts_version_addr) {
        strncpy(ori_version, uts_version_addr, sizeof(ori_version) - 1);
        ori_version[sizeof(ori_version) - 1] = '\0';
        ori_version_len = strnlen(ori_version, sizeof(ori_version) - 1);
    }
    backup_saved = 1;
}

long call_uts_set(const char __user *u_release,
                   const char __user *u_version)
{
    if (!uts_release_addr) {
        int rc = versionspoof_resolve();
        if (rc) return rc;
    }

    versionspoof_backup_originals();

    if (u_release) {
        char buf[256];
        long len = compat_strncpy_from_user(buf, u_release, sizeof(buf));
        if (len < 0) return -EINVAL;
        if ((int)len > max_release_len) return -E2BIG;
        int rc = safe_write_memory((void *)uts_release_addr, buf, (int)(len + 1));
        if (rc) return rc;
    }

    if (u_version) {
        char buf[256];
        long len = compat_strncpy_from_user(buf, u_version, sizeof(buf));
        if (len < 0) return -EINVAL;
        if ((int)len > max_version_len) return -E2BIG;
        int rc = safe_write_memory((void *)uts_version_addr, buf, (int)(len + 1));
        if (rc) return rc;
    }

    return 0;
}

long call_uts_reset(void)
{
    if (!backup_saved) return 0;

    int rc = 0;
    if (uts_release_addr && ori_release_len > 0)
        rc |= safe_write_memory((void *)uts_release_addr, ori_release, ori_release_len + 1);
    if (uts_version_addr && ori_version_len > 0)
        rc |= safe_write_memory((void *)uts_version_addr, ori_version, ori_version_len + 1);
    return rc;
}
