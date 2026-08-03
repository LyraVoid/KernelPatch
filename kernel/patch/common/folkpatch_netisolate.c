/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <asm/current.h>
#include <hook.h>
#include <kallsyms.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <kputils.h>
#include <syscall.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>
#include <folkpatch_netisolate.h>

#define FOLKPATCH_NETISOLATE_MAX_UIDS 256
#define AF_INET 2
#define AF_INET6 10

struct folkpatch_netisolate_state {
    uid_t uids[FOLKPATCH_NETISOLATE_MAX_UIDS];
    int uid_count;
    int enabled;
    int hooks_ready;
    uid_t manager_uid;
    spinlock_t lock;
};

static struct folkpatch_netisolate_state netisolate;
static unsigned long (*netisolate_copy_from_user)(void *, const void __user *, unsigned long);

static int folkpatch_netisolate_uid_selected(uid_t uid)
{
    int i;
    int selected = 0;
    unsigned long flags = spin_lock_irqsave(&netisolate.lock);
    if (netisolate.enabled && uid != netisolate.manager_uid) {
        for (i = 0; i < netisolate.uid_count; i++) {
            if (netisolate.uids[i] == uid) {
                selected = 1;
                break;
            }
        }
    }
    spin_unlock_irqrestore(&netisolate.lock, flags);
    return selected;
}

static int folkpatch_netisolate_inet_address(const void __user *addr, int addr_len)
{
    uint16_t family;

    if (!addr || addr_len < (int)sizeof(family) || !netisolate_copy_from_user)
        return 0;
    if (netisolate_copy_from_user(&family, addr, sizeof(family))) return 0;
    return family == AF_INET || family == AF_INET6;
}

static void folkpatch_netisolate_before_connect(hook_fargs4_t *args, void *udata)
{
    const void __user *addr;
    int addr_len;

    (void)udata;
    if (!folkpatch_netisolate_uid_selected(current_uid())) return;
    addr = (const void __user *)syscall_argn(args, 1);
    addr_len = (int)syscall_argn(args, 2);
    if (folkpatch_netisolate_inet_address(addr, addr_len)) {
        args->ret = -ECONNREFUSED;
        args->skip_origin = 1;
    }
}

static void folkpatch_netisolate_before_sendto(hook_fargs8_t *args, void *udata)
{
    const void __user *addr;
    int addr_len;

    (void)udata;
    if (!folkpatch_netisolate_uid_selected(current_uid())) return;
    addr = (const void __user *)syscall_argn(args, 4);
    addr_len = (int)syscall_argn(args, 5);
    if (folkpatch_netisolate_inet_address(addr, addr_len)) {
        args->ret = -ECONNREFUSED;
        args->skip_origin = 1;
    }
}

int folkpatch_netisolate_init(void)
{
    hook_err_t connect_rc;
    hook_err_t sendto_rc;

    memset(&netisolate, 0, sizeof(netisolate));
    spin_lock_init(&netisolate.lock);
    netisolate_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (!netisolate_copy_from_user)
        netisolate_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");
    if (!netisolate_copy_from_user) return -ENOSYS;

    connect_rc = fp_hook_syscalln(__NR_connect, 3,
                                  folkpatch_netisolate_before_connect, 0, 0);
    sendto_rc = fp_hook_syscalln(__NR_sendto, 6,
                                 folkpatch_netisolate_before_sendto, 0, 0);
    netisolate.hooks_ready = !connect_rc && !sendto_rc;
    return netisolate.hooks_ready ? 0 : -ENOSYS;
}

long folkpatch_netisolate_enable(int enable)
{
    unsigned long flags = spin_lock_irqsave(&netisolate.lock);
    if (enable && !netisolate.hooks_ready) {
        spin_unlock_irqrestore(&netisolate.lock, flags);
        return -ENOSYS;
    }
    if (enable) netisolate.manager_uid = current_uid();
    netisolate.enabled = !!enable;
    spin_unlock_irqrestore(&netisolate.lock, flags);
    return 0;
}

long folkpatch_netisolate_status(void)
{
    int enabled;
    int count;
    unsigned long flags = spin_lock_irqsave(&netisolate.lock);
    enabled = netisolate.enabled;
    count = netisolate.uid_count;
    spin_unlock_irqrestore(&netisolate.lock, flags);
    return ((long)enabled << 32) | (unsigned int)count;
}

long folkpatch_netisolate_uid_add(uid_t uid)
{
    int i;
    unsigned long flags;

    if (!uid) return -EINVAL;
    flags = spin_lock_irqsave(&netisolate.lock);
    for (i = 0; i < netisolate.uid_count; i++) {
        if (netisolate.uids[i] == uid) {
            spin_unlock_irqrestore(&netisolate.lock, flags);
            return 0;
        }
    }
    if (netisolate.uid_count >= FOLKPATCH_NETISOLATE_MAX_UIDS) {
        spin_unlock_irqrestore(&netisolate.lock, flags);
        return -ENOSPC;
    }
    netisolate.uids[netisolate.uid_count++] = uid;
    spin_unlock_irqrestore(&netisolate.lock, flags);
    return 0;
}

long folkpatch_netisolate_uid_remove(uid_t uid)
{
    int i;
    unsigned long flags;

    if (!uid) return -EINVAL;
    flags = spin_lock_irqsave(&netisolate.lock);
    for (i = 0; i < netisolate.uid_count; i++) {
        if (netisolate.uids[i] == uid) {
            netisolate.uid_count--;
            netisolate.uids[i] = netisolate.uids[netisolate.uid_count];
            spin_unlock_irqrestore(&netisolate.lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&netisolate.lock, flags);
    return -ENOENT;
}

long folkpatch_netisolate_uid_list(char __user *out, int out_len)
{
    char *buffer;
    int pos = 0;
    int i;
    int copied;
    unsigned long flags;

    if (!out || out_len <= 0) return -EINVAL;
    buffer = vmalloc(FOLKPATCH_NETISOLATE_MAX_UIDS * 12);
    if (!buffer) return -ENOMEM;
    flags = spin_lock_irqsave(&netisolate.lock);
    for (i = 0; i < netisolate.uid_count; i++) {
        int remaining = FOLKPATCH_NETISOLATE_MAX_UIDS * 12 - pos;
        int written = snprintf(buffer + pos, remaining,
                               "%u\n", netisolate.uids[i]);
        if (written < 0 || written >= remaining) {
            spin_unlock_irqrestore(&netisolate.lock, flags);
            vfree(buffer);
            return -ENOBUFS;
        }
        pos += written;
    }
    spin_unlock_irqrestore(&netisolate.lock, flags);
    if (pos > out_len) {
        vfree(buffer);
        return -ENOBUFS;
    }
    copied = compat_copy_to_user(out, buffer, pos);
    vfree(buffer);
    return copied == pos ? pos : -EFAULT;
}

long folkpatch_netisolate_uid_clear(void)
{
    unsigned long flags = spin_lock_irqsave(&netisolate.lock);
    netisolate.uid_count = 0;
    spin_unlock_irqrestore(&netisolate.lock, flags);
    return 0;
}
