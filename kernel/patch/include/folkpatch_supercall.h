/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_FOLKPATCH_SUPERCALL_H_
#define _KP_FOLKPATCH_SUPERCALL_H_

#include <ktypes.h>
#include <linux/uaccess.h>
#include <uapi/scdefs.h>

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

#endif
