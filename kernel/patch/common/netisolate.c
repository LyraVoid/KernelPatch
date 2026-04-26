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
#include <netisolate.h>

/* AF_INET = 2, AF_INET6 = 10 */
#define AF_INET  2
#define AF_INET6 10

typedef unsigned int socklen_t;

#define MAX_UIDS       256
#define MAX_CPUS       16

/* connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) */
#ifdef __NR_connect
#undef __NR_connect
#endif
#define __NR_connect 203

/* sendto(int sockfd, const void *buf, size_t len, int flags,
 *        const struct sockaddr *dest_addr, socklen_t addrlen) */
#ifdef __NR_sendto
#undef __NR_sendto
#endif
#define __NR_sendto 206

/* ─── spinlock: ARM64 inline asm (same as pathhide) ─── */

typedef volatile int ni_lock_t;

static inline void ni_lock(ni_lock_t *lock)
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

static inline void ni_unlock(ni_lock_t *lock)
{
    __asm__ volatile("stlr wzr, [%0]" :: "r"(lock) : "memory");
}

/* ─── UID blocklist ─── */

static struct {
    int uids[MAX_UIDS];
    int count;
    ni_lock_t lock;
} uid_blocklist;

static volatile int netisolate_enabled;

/* ─── exempt: FolkPatch manager UID always exempt ─── */

static volatile int netisolate_app_uid = -1;

static int ni_is_exempt(void)
{
    int uid = (int)current_uid();
    if (uid == netisolate_app_uid) return 1;
    if (uid < 10000) return 1; /* system/root exempt */
    return 0;
}

/* ─── re-entrancy guard: per-CPU flag ─── */

static volatile int cpu_nesting[MAX_CPUS];

static unsigned int (*kf_smp_processor_id)(void);

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

/* ─── kernel functions (resolved at runtime) ─── */

static unsigned long (*kf_copy_from_user)(void *, const void __user *, unsigned long);

/* ─── UID blocklist check ─── */

static int should_block_uid(void)
{
    uid_t uid = current_uid();

    ni_lock(&uid_blocklist.lock);
    int found = 0;
    for (int i = 0; i < uid_blocklist.count && !found; i++) {
        if (uid_blocklist.uids[i] == (int)uid)
            found = 1;
    }
    ni_unlock(&uid_blocklist.lock);
    return found;
}

/* ─── sockaddr structures (minimal, no external headers) ─── */

struct ni_sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    char     sin_zero[8];
};

struct ni_sockaddr_in6 {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t  sin6_addr[16];
    uint32_t sin6_scope_id;
};

/* ─── check sockaddr: block if AF_INET or AF_INET6 ─── */

static int check_sockaddr(const void __user *uaddr, socklen_t addrlen)
{
    if (!uaddr || addrlen < 2) return 0;
    if (!kf_copy_from_user) return 0;

    uint16_t family;
    if (kf_copy_from_user(&family, uaddr, sizeof(family)))
        return 0;

    if (family != AF_INET && family != AF_INET6)
        return 0; /* AF_UNIX, AF_NETLINK, etc. pass through */

    return 1; /* should block */
}

/* ─── hook: connect ─── */

static void before_connect(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    if (!netisolate_enabled) return;
    if (uid_blocklist.count == 0) return;
    if (is_nested()) return;
    if (ni_is_exempt()) return;

    set_nested(1);

    if (should_block_uid()) {
        const void __user *uaddr = (const void __user *)syscall_argn(args, 1);
        socklen_t addrlen = (socklen_t)syscall_argn(args, 2);

        if (check_sockaddr(uaddr, addrlen)) {
            logkfi("netisolate: block connect uid=%d\n", (int)current_uid());
            args->ret = -ECONNREFUSED;
            args->skip_origin = 1;
        }
    }

    set_nested(0);
}

/* ─── hook: sendto ─── */

static void before_sendto(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    if (!netisolate_enabled) return;
    if (uid_blocklist.count == 0) return;
    if (is_nested()) return;
    if (ni_is_exempt()) return;

    set_nested(1);

    if (should_block_uid()) {
        /* sendto(fd, buf, len, flags, addr, addrlen) — addr is arg4, addrlen is arg5 */
        const void __user *uaddr = (const void __user *)syscall_argn(args, 4);
        socklen_t addrlen = (socklen_t)syscall_argn(args, 5);

        if (uaddr && addrlen > 0 && check_sockaddr(uaddr, addrlen)) {
            logkfi("netisolate: block sendto uid=%d\n", (int)current_uid());
            args->ret = -ECONNREFUSED;
            args->skip_origin = 1;
        }
    }

    set_nested(0);
}

/* ─── public API ─── */

int netisolate_init(void)
{
    logkfi("netisolate: init\n");

    kf_smp_processor_id = (void *)kallsyms_lookup_name("smp_processor_id");
    if (!kf_smp_processor_id)
        kf_smp_processor_id = (void *)kallsyms_lookup_name("raw_smp_processor_id");

    kf_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (!kf_copy_from_user)
        kf_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");

    logkfi("netisolate: smp=%llx cfu=%llx\n",
           (uint64_t)kf_smp_processor_id, (uint64_t)kf_copy_from_user);

    uid_blocklist.lock = 0;
    uid_blocklist.count = 0;
    netisolate_enabled = 0;

    /* Hook connect (3 args) */
    hook_err_t err = fp_hook_syscalln(__NR_connect, 3, before_connect, 0, 0);
    logkfi("netisolate: hook connect %s\n", err ? "FAIL" : "OK");

    /* Hook sendto (6 args) */
    err = fp_hook_syscalln(__NR_sendto, 6, before_sendto, 0, 0);
    logkfi("netisolate: hook sendto %s\n", err ? "FAIL" : "OK");

    return 0;
}

long call_netisolate_enable(int enable)
{
    int uid = (int)current_uid();
    if (uid > 0)
        netisolate_app_uid = uid;
    netisolate_enabled = enable ? 1 : 0;
    logkfi("netisolate: %s\n", enable ? "enabled" : "disabled");
    return 0;
}

long call_netisolate_status(void)
{
    int uid = (int)current_uid();
    if (uid > 0)
        netisolate_app_uid = uid;
    ni_lock(&uid_blocklist.lock);
    int count = uid_blocklist.count;
    ni_unlock(&uid_blocklist.lock);
    return ((long)netisolate_enabled << 32) | count;
}

long call_netisolate_uid_add(int uid)
{
    if (uid <= 0) return -EINVAL;
    ni_lock(&uid_blocklist.lock);
    if (uid_blocklist.count >= MAX_UIDS) {
        ni_unlock(&uid_blocklist.lock);
        return -ENOMEM;
    }
    for (int i = 0; i < uid_blocklist.count; i++) {
        if (uid_blocklist.uids[i] == uid) {
            ni_unlock(&uid_blocklist.lock);
            return 0;
        }
    }
    uid_blocklist.uids[uid_blocklist.count++] = uid;
    ni_unlock(&uid_blocklist.lock);
    logkfi("netisolate: +uid %d\n", uid);
    return 0;
}

long call_netisolate_uid_remove(int uid)
{
    if (uid <= 0) return -EINVAL;
    ni_lock(&uid_blocklist.lock);
    for (int i = 0; i < uid_blocklist.count; i++) {
        if (uid_blocklist.uids[i] == uid) {
            for (int j = i; j < uid_blocklist.count - 1; j++)
                uid_blocklist.uids[j] = uid_blocklist.uids[j + 1];
            uid_blocklist.count--;
            ni_unlock(&uid_blocklist.lock);
            logkfi("netisolate: -uid %d\n", uid);
            return 0;
        }
    }
    ni_unlock(&uid_blocklist.lock);
    return -ENOENT;
}

long call_netisolate_uid_list(char __user *out_buf, int outlen)
{
    if (!out_buf || outlen <= 0) return -EINVAL;
    char buf[4096];
    int pos = 0;
    ni_lock(&uid_blocklist.lock);
    for (int i = 0; i < uid_blocklist.count && pos < (int)sizeof(buf) - 16; i++)
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%d\n", uid_blocklist.uids[i]);
    ni_unlock(&uid_blocklist.lock);
    int copy_len = pos < outlen ? pos : outlen;
    compat_copy_to_user(out_buf, buf, copy_len);
    return pos;
}

long call_netisolate_uid_clear(void)
{
    ni_lock(&uid_blocklist.lock);
    uid_blocklist.count = 0;
    ni_unlock(&uid_blocklist.lock);
    logkfi("netisolate: cleared uid blocklist\n");
    return 0;
}
