/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_FOLKPATCH_SUPERCALL_H_
#define _KP_FOLKPATCH_SUPERCALL_H_

#include <ktypes.h>
#include <linux/uaccess.h>
#include <uapi/scdefs.h>
#include <folkpatch_suaudit.h>

/* FolkPatch owns this range; upstream commands must remain unchanged. */
static inline bool folkpatch_supercall_cmd(long cmd)
{
    return (cmd >= SUPERCALL_FOLKPATCH_MIN && cmd <= SUPERCALL_FOLKPATCH_MAX) ||
           (cmd >= SUPERCALL_FOLKPATCH_AUDIT_MIN && cmd <= SUPERCALL_FOLKPATCH_AUDIT_MAX);
}

long folkpatch_supercall(int is_authed, long cmd, long arg1, long arg2,
                         long arg3, long arg4);

long folkpatch_uts_set(const char __user *u_release,
                       const char __user *u_version);
long folkpatch_uts_reset(void);

long folkpatch_pathhide_add(const char __user *path);
long folkpatch_pathhide_remove(const char __user *path);
long folkpatch_pathhide_list(char __user *out, int out_len);
long folkpatch_pathhide_clear(void);
long folkpatch_pathhide_enable(int enable);
long folkpatch_pathhide_status(void);
long folkpatch_pathhide_uid_add(uid_t uid);
long folkpatch_pathhide_uid_remove(uid_t uid);
long folkpatch_pathhide_uid_list(char __user *out, int out_len);
long folkpatch_pathhide_uid_clear(void);
long folkpatch_pathhide_uid_mode(int enable);
long folkpatch_pathhide_filter_system(int enable);

long folkpatch_netisolate_enable(int enable);
long folkpatch_netisolate_status(void);
long folkpatch_netisolate_uid_add(uid_t uid);
long folkpatch_netisolate_uid_remove(uid_t uid);
long folkpatch_netisolate_uid_list(char __user *out, int out_len);
long folkpatch_netisolate_uid_clear(void);

#endif
