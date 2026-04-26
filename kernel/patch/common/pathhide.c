/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <log.h>
#include <common.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <kputils.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <pathhide.h>

#define AT_FDCWD       (-100)
#define __NR_newfstatat 79
#ifdef __NR_getdents64
#undef __NR_getdents64
#endif
#define __NR_getdents64 217

#define MAX_BLOCKED    256
#define MAX_PATH_LEN   512
#define MAX_CPUS       16
#define MAX_UIDS       256
#define DIRENT_BUF_SIZE 4096

/* ─── spinlock: ARM64 inline asm ─── */

typedef volatile int bl_lock_t;

static inline void bl_lock(bl_lock_t *lock)
{
    while (1) {
        int val;
        __asm__ volatile("ldaxr %w0, [%1]" : "=r"(val) : "r"(lock) : "memory");
        if (val) continue;
        int ok;
        __asm__ volatile("stxr %w0, %w2, [%1]" : "=r"(ok) : "r"(lock), "r"(1) : "memory");
        if (!ok) break;
    }
}

static inline void bl_unlock(bl_lock_t *lock)
{
    __asm__ volatile("stlr wzr, [%0]" :: "r"(lock) : "memory");
}

/* ─── blocklist ─── */

static struct {
    char paths[MAX_BLOCKED][MAX_PATH_LEN];
    int count;
    bl_lock_t lock;
} blocklist;

static volatile int pathhide_enabled;

/* ─── UID whitelist ─── */

static struct {
    int uids[MAX_UIDS];
    int count;
    bl_lock_t lock;
} uid_whitelist;

static volatile int pathhide_uid_mode;
static volatile int pathhide_filter_system; /* 0: system UID exempt (default), 1: filter system UID too */

/* ─── exempt logic ─── */

static volatile int pathhide_app_uid = -1;

static void record_caller_uid(void)
{
    int uid = (int)current_uid();
    if (uid > 0)
        pathhide_app_uid = uid;
}

static int is_exempt(void)
{
    int uid = (int)current_uid();
    if (uid == pathhide_app_uid) return 1; /* FolkPatch always exempt */
    if (uid < 10000 && !pathhide_filter_system) return 1; /* system exempt unless toggle ON */
    return 0;
}

/* ─── kernel functions (resolved at runtime via kallsyms) ─── */

static int (*kf_kern_path)(const char *, unsigned, void *);
static char *(*kf_d_path)(const void *, char *, int);
static void (*kf_path_put)(const void *);
static unsigned int (*kf_smp_processor_id)(void);
static unsigned long (*kf_copy_from_user)(void *, const void __user *, unsigned long);
static void *(*kf_fget)(unsigned int);
static void (*kf_fput)(void *);
static char *(*kf_file_path)(void *, char *, int);

/* ─── re-entrancy guard: per-CPU flag ─── */

static volatile int cpu_nesting[MAX_CPUS];

static int is_nested(void)
{
    if (!kf_smp_processor_id) return 0;
    unsigned int cpu = kf_smp_processor_id();
    if (cpu >= MAX_CPUS) return 0;
    return cpu_nesting[cpu];
}

static void set_nested(int val)
{
    if (!kf_smp_processor_id) return;
    unsigned int cpu = kf_smp_processor_id();
    if (cpu >= MAX_CPUS) return;
    cpu_nesting[cpu] = val;
}

/* ─── path normalize ─── */

static void path_normalize(char *path)
{
    char *out = path;
    char *in = path;

    if (*in != '/') *out++ = '/';

    while (*in) {
        while (*in == '/') in++;
        if (!*in) break;

        char *cs = in;
        while (*in && *in != '/') in++;
        int clen = (int)(in - cs);

        if (clen == 1 && cs[0] == '.')
            continue;

        if (clen == 2 && cs[0] == '.' && cs[1] == '.') {
            if (out > path + 1) {
                out--;
                while (out > path && *(out - 1) != '/') out--;
            }
            continue;
        }

        *out++ = '/';
        memcpy(out, cs, clen);
        out += clen;
    }

    if (out == path) *out++ = '/';
    *out = '\0';
}

/* ─── resolve helpers ─── */

static int resolve_absolute(const char *raw, char *out, int outlen)
{
    long len = (long)strlen(raw);
    if (len >= outlen) return -1;
    memcpy(out, raw, len + 1);
    path_normalize(out);
    return 0;
}

static int do_kern_resolve(const char *path_str, char *out, int outlen)
{
    if (!kf_kern_path || !kf_d_path || !kf_path_put)
        return -1;

    uint64_t path[2];
    if (kf_kern_path(path_str, 0, path))
        return -1;

    char *p = kf_d_path(path, out, outlen);
    kf_path_put(path);

    if (IS_ERR_OR_NULL(p))
        return -1;

    if (p != out)
        memmove(out, p, strlen(p) + 1);
    return 0;
}

static int resolve_path(int dfd, const char *raw, char *out, int outlen)
{
    if (raw[0] == '/')
        return resolve_absolute(raw, out, outlen);

    char target[MAX_PATH_LEN];
    if (dfd == AT_FDCWD) {
        long len = (long)strlen(raw);
        if (len >= (long)sizeof(target)) return -1;
        memcpy(target, raw, len + 1);
    } else {
        int plen = snprintf(target, sizeof(target), "/proc/self/fd/%d/%s", dfd, raw);
        if (plen <= 0 || plen >= (int)sizeof(target))
            return -1;
    }

    return do_kern_resolve(target, out, outlen);
}

/* ─── blocklist ops ─── */

/* Check if caller should be filtered (returns 1 = should filter) */
static int should_filter_uid(void)
{
    if (!pathhide_uid_mode) return 1;
    uid_t uid = current_uid();

    /* UID mode + filter_system: also filter root/system UIDs */
    if (pathhide_filter_system && (int)uid < 10000)
        return 1;

    /* UID mode: filter whitelisted app UIDs */
    bl_lock(&uid_whitelist.lock);
    int found = 0;
    for (int i = 0; i < uid_whitelist.count && !found; i++) {
        if (uid_whitelist.uids[i] == (int)uid)
            found = 1;
    }
    bl_unlock(&uid_whitelist.lock);
    return found;
}

static int uid_add(int uid)
{
    bl_lock(&uid_whitelist.lock);
    if (uid_whitelist.count >= MAX_UIDS) {
        bl_unlock(&uid_whitelist.lock);
        return -ENOMEM;
    }
    for (int i = 0; i < uid_whitelist.count; i++) {
        if (uid_whitelist.uids[i] == uid) {
            bl_unlock(&uid_whitelist.lock);
            return 0;
        }
    }
    uid_whitelist.uids[uid_whitelist.count++] = uid;
    bl_unlock(&uid_whitelist.lock);
    logkfi("pathhide: +uid %d\n", uid);
    return 0;
}

static int uid_remove(int uid)
{
    bl_lock(&uid_whitelist.lock);
    for (int i = 0; i < uid_whitelist.count; i++) {
        if (uid_whitelist.uids[i] == uid) {
            for (int j = i; j < uid_whitelist.count - 1; j++)
                uid_whitelist.uids[j] = uid_whitelist.uids[j + 1];
            uid_whitelist.count--;
            bl_unlock(&uid_whitelist.lock);
            logkfi("pathhide: -uid %d\n", uid);
            return 0;
        }
    }
    bl_unlock(&uid_whitelist.lock);
    return -ENOENT;
}

static int bl_add(const char *path)
{
    bl_lock(&blocklist.lock);
    if (blocklist.count >= MAX_BLOCKED) {
        bl_unlock(&blocklist.lock);
        return -ENOMEM;
    }
    for (int i = 0; i < blocklist.count; i++) {
        if (strcmp(blocklist.paths[i], path) == 0) {
            bl_unlock(&blocklist.lock);
            return 0;
        }
    }
    int len = (int)strlen(path);
    if (len >= MAX_PATH_LEN) {
        bl_unlock(&blocklist.lock);
        return -EINVAL;
    }
    memcpy(blocklist.paths[blocklist.count], path, len + 1);
    blocklist.count++;
    bl_unlock(&blocklist.lock);
    logkfi("pathhide: + %s\n", path);
    return 0;
}

static int bl_remove(const char *path)
{
    bl_lock(&blocklist.lock);
    for (int i = 0; i < blocklist.count; i++) {
        if (strcmp(blocklist.paths[i], path) == 0) {
            for (int j = i; j < blocklist.count - 1; j++)
                memcpy(blocklist.paths[j], blocklist.paths[j + 1], MAX_PATH_LEN);
            blocklist.count--;
            bl_unlock(&blocklist.lock);
            logkfi("pathhide: - %s\n", path);
            return 0;
        }
    }
    bl_unlock(&blocklist.lock);
    return -ENOENT;
}

static int bl_match(const char *resolved)
{
    bl_lock(&blocklist.lock);
    int found = 0;
    for (int i = 0; i < blocklist.count && !found; i++) {
        int blen = (int)strlen(blocklist.paths[i]);
        if (strncmp(blocklist.paths[i], resolved, blen) != 0)
            continue;
        char next = resolved[blen];
        if (next == '/' || next == '\0')
            found = 1;
    }
    bl_unlock(&blocklist.lock);
    return found;
}

/* Check if a directory path could contain any hidden entries.
 * Returns 1 if dirpath is a parent of (or equal to) any blocklist entry. */
static int dir_may_contain_hidden(const char *dirpath)
{
    int dlen = (int)strlen(dirpath);
    bl_lock(&blocklist.lock);
    int may = 0;
    for (int i = 0; i < blocklist.count && !may; i++) {
        int blen = (int)strlen(blocklist.paths[i]);
        /* dirpath is a prefix of a blocklist entry, e.g. "/data" vs "/data/foo" */
        if (dlen < blen &&
            strncmp(dirpath, blocklist.paths[i], dlen) == 0 &&
            blocklist.paths[i][dlen] == '/')
            may = 1;
        /* dirpath exactly matches a blocklist entry */
        else if (blen == dlen &&
                 strncmp(dirpath, blocklist.paths[i], dlen) == 0)
            may = 1;
    }
    bl_unlock(&blocklist.lock);
    return may;
}

/* ─── before hooks: openat / faccessat / newfstatat ─── */

static void check_and_block(hook_fargs4_t *args, const char *name)
{
    if (!pathhide_enabled) return;
    if (blocklist.count == 0) return;
    if (is_nested()) return;
    if (is_exempt()) return;
    if (!should_filter_uid()) return;

    set_nested(1);

    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (const char __user *)syscall_argn(args, 1);

    char raw[MAX_PATH_LEN];
    if (compat_strncpy_from_user(raw, filename, sizeof(raw)) > 0) {
        char resolved[MAX_PATH_LEN];
        if (resolve_path(dfd, raw, resolved, sizeof(resolved)) == 0) {
            if (bl_match(resolved)) {
                logkfi("pathhide: [%s] block '%s' -> '%s'\n", name, raw, resolved);
                args->ret = -ENOENT;
                args->skip_origin = 1;
            }
        }
    }

    set_nested(0);
}

static void before_openat(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    check_and_block(args, "openat");
}

static void before_faccessat(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    check_and_block(args, "faccessat");
}

static void before_newfstatat(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    check_and_block(args, "newfstatat");
}

/* ─── getdents64: inline hook on __arm64_sys_getdents64 ─── */

/*
 * struct linux_dirent64 layout (UAPI, stable ABI):
 *   offset 0:  uint64_t d_ino
 *   offset 8:  int64_t  d_off
 *   offset 16: uint16_t d_reclen
 *   offset 18: uint8_t  d_type
 *   offset 19: char     d_name[]
 */
#define DENT64_RECLEN_OFF 16
#define DENT64_NAME_OFF   19

typedef long (*orig_getdents64_t)(const void *);

/* resolve fd -> directory path via fget + file_path */
static int resolve_fd_dirpath(int fd, char *out, int outlen)
{
    if (!kf_fget || !kf_fput || !kf_file_path)
        return -1;

    void *file = kf_fget((unsigned int)fd);
    if (!file)
        return -1;

    char *p = kf_file_path(file, out, outlen);
    kf_fput(file);

    if (IS_ERR_OR_NULL(p))
        return -1;

    if (p != out)
        memmove(out, p, strlen(p) + 1);
    return 0;
}

/* filter hidden entries from dirent buffer, return new length */
static int filter_dirents(char *kbuf, long buflen, const char *dirpath)
{
    int pos = 0, new_pos = 0;
    char full[MAX_PATH_LEN];

    while (pos < buflen) {
        if (pos + DENT64_NAME_OFF >= buflen) break;
        uint16_t reclen = *(uint16_t *)(kbuf + pos + DENT64_RECLEN_OFF);
        if (reclen == 0 || pos + reclen > buflen) break;

        char *name = kbuf + pos + DENT64_NAME_OFF;
        int flen = snprintf(full, sizeof(full), "%s/%s", dirpath, name);

        if (flen <= 0 || flen >= (int)sizeof(full) || !bl_match(full)) {
            if (new_pos != pos)
                memmove(kbuf + new_pos, kbuf + pos, reclen);
            new_pos += reclen;
        } else {
            logkfi("pathhide: [getdents64] hide '%s'\n", name);
        }
        pos += reclen;
    }

    return new_pos;
}

static void before_getdents64(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    if (!pathhide_enabled) return;
    if (blocklist.count == 0) return;
    if (is_exempt()) return;

    if (!should_filter_uid()) return;

    /* call original */
    orig_getdents64_t orig = (orig_getdents64_t)wrap_get_origin_func(args);
    long ret = orig((const void *)args->arg0);
    args->ret = (uint64_t)ret;
    args->skip_origin = 1;

    if (ret <= 0) return;
    if (!kf_copy_from_user) return;
    if (ret > DIRENT_BUF_SIZE) return;

    /* resolve fd -> directory path */
    int fd = (int)syscall_argn(args, 0);
    if (fd < 0) return;

    char dirpath[MAX_PATH_LEN];
    if (resolve_fd_dirpath(fd, dirpath, sizeof(dirpath)) != 0)
        return;

    /* early exit: skip if directory cannot contain hidden entries */
    if (!dir_may_contain_hidden(dirpath)) return;

    /* heap-allocate dirent buffer to avoid ~5KB stack overflow */
    char *kbuf = vmalloc(DIRENT_BUF_SIZE);
    if (!kbuf) return;

    void __user *dirent = (void __user *)syscall_argn(args, 1);
    if (kf_copy_from_user(kbuf, dirent, (unsigned long)ret)) {
        vfree(kbuf);
        return;
    }

    int new_len = filter_dirents(kbuf, ret, dirpath);
    if (new_len < ret) {
        compat_copy_to_user(dirent, kbuf, new_len);
        args->ret = (uint64_t)new_len;
    }
    vfree(kbuf);
}

/* ─── hook handles for uninstall ─── */

static hook_err_t openat_err, faccessat_err, newfstatat_err, getdents64_err;
static void *gd64_addr;

/* ─── public API ─── */

int pathhide_init(void)
{
    logkfi("pathhide: init\n");

    kf_kern_path = (void *)kallsyms_lookup_name("kern_path");
    kf_d_path = (void *)kallsyms_lookup_name("d_path");
    kf_path_put = (void *)kallsyms_lookup_name("path_put");
    kf_smp_processor_id = (void *)kallsyms_lookup_name("smp_processor_id");
    if (!kf_smp_processor_id)
        kf_smp_processor_id = (void *)kallsyms_lookup_name("raw_smp_processor_id");
    kf_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (!kf_copy_from_user)
        kf_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");
    kf_fget = (void *)kallsyms_lookup_name("fget");
    kf_fput = (void *)kallsyms_lookup_name("fput");
    kf_file_path = (void *)kallsyms_lookup_name("file_path");

    logkfi("pathhide: kern_path=%llx d_path=%llx path_put=%llx smp=%llx cfu=%llx\n",
           (uint64_t)kf_kern_path, (uint64_t)kf_d_path,
           (uint64_t)kf_path_put, (uint64_t)kf_smp_processor_id,
           (uint64_t)kf_copy_from_user);

    if (!kf_smp_processor_id)
        logkfi("pathhide: smp_processor_id not found, re-entrancy guard disabled\n");

    blocklist.lock = 0;
    blocklist.count = 0;
    uid_whitelist.lock = 0;
    uid_whitelist.count = 0;
    pathhide_enabled = 0;
    pathhide_uid_mode = 0;

    /* Install hooks (always installed, gated by pathhide_enabled flag) */
    openat_err = fp_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    logkfi("pathhide: hook openat %s\n", openat_err ? "FAIL" : "OK");

    faccessat_err = fp_hook_syscalln(__NR_faccessat, 3, before_faccessat, 0, 0);
    logkfi("pathhide: hook faccessat %s\n", faccessat_err ? "FAIL" : "OK");

    newfstatat_err = fp_hook_syscalln(__NR_newfstatat, 4, before_newfstatat, 0, 0);
    logkfi("pathhide: hook newfstatat %s\n", newfstatat_err ? "FAIL" : "OK");

    /* getdents64: inline hook on real function (bypass CFI trampoline) */
    gd64_addr = (void *)kallsyms_lookup_name("__arm64_sys_getdents64");
    if (gd64_addr) {
        getdents64_err = hook_wrap(gd64_addr, 1, before_getdents64, 0, 0);
        logkfi("pathhide: hook getdents64 %s\n", getdents64_err ? "FAIL" : "OK");
    } else {
        logkfi("pathhide: __arm64_sys_getdents64 not found\n");
    }

    return 0;
}

long call_pathhide_add(const char __user *u_path)
{
    if (!u_path) return -EINVAL;
    char buf[MAX_PATH_LEN];
    long len = compat_strncpy_from_user(buf, u_path, sizeof(buf));
    if (len <= 0) return -EINVAL;
    /* normalize the path */
    path_normalize(buf);
    return bl_add(buf);
}

long call_pathhide_remove(const char __user *u_path)
{
    if (!u_path) return -EINVAL;
    char buf[MAX_PATH_LEN];
    long len = compat_strncpy_from_user(buf, u_path, sizeof(buf));
    if (len <= 0) return -EINVAL;
    path_normalize(buf);
    return bl_remove(buf);
}

long call_pathhide_list(char __user *out_buf, int outlen)
{
    if (!out_buf || outlen <= 0) return -EINVAL;
    char buf[4096];
    int pos = 0;
    bl_lock(&blocklist.lock);
    for (int i = 0; i < blocklist.count && pos < (int)sizeof(buf) - MAX_PATH_LEN; i++)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%s\n", blocklist.paths[i]);
    bl_unlock(&blocklist.lock);
    int copy_len = pos < outlen ? pos : outlen;
    compat_copy_to_user(out_buf, buf, copy_len);
    return pos;
}

long call_pathhide_clear(void)
{
    bl_lock(&blocklist.lock);
    blocklist.count = 0;
    bl_unlock(&blocklist.lock);
    logkfi("pathhide: cleared all paths\n");
    return 0;
}

long call_pathhide_enable(int enable)
{
    record_caller_uid();
    pathhide_enabled = enable ? 1 : 0;
    logkfi("pathhide: %s\n", enable ? "enabled" : "disabled");
    return 0;
}

long call_pathhide_status(void)
{
    record_caller_uid();
    /* return enabled status in high word, count in low word */
    bl_lock(&blocklist.lock);
    int count = blocklist.count;
    bl_unlock(&blocklist.lock);
    return ((long)pathhide_enabled << 32) | count;
}

/* ─── UID whitelist public API ─── */

long call_pathhide_uid_add(int uid)
{
    if (uid <= 0) return -EINVAL;
    return uid_add(uid);
}

long call_pathhide_uid_remove(int uid)
{
    if (uid <= 0) return -EINVAL;
    return uid_remove(uid);
}

long call_pathhide_uid_list(char __user *out_buf, int outlen)
{
    if (!out_buf || outlen <= 0) return -EINVAL;
    char buf[4096];
    int pos = 0;
    bl_lock(&uid_whitelist.lock);
    for (int i = 0; i < uid_whitelist.count && pos < (int)sizeof(buf) - 16; i++)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%d\n", uid_whitelist.uids[i]);
    bl_unlock(&uid_whitelist.lock);
    int copy_len = pos < outlen ? pos : outlen;
    compat_copy_to_user(out_buf, buf, copy_len);
    return pos;
}

long call_pathhide_uid_clear(void)
{
    bl_lock(&uid_whitelist.lock);
    uid_whitelist.count = 0;
    bl_unlock(&uid_whitelist.lock);
    logkfi("pathhide: cleared uid whitelist\n");
    return 0;
}

long call_pathhide_uid_mode(int enable)
{
    pathhide_uid_mode = enable ? 1 : 0;
    logkfi("pathhide: uid mode %s\n", enable ? "ON" : "OFF");
    return 0;
}

long call_pathhide_filter_system(int enable)
{
    pathhide_filter_system = enable ? 1 : 0;
    logkfi("pathhide: filter system %s\n", enable ? "ON" : "OFF");
    return 0;
}
