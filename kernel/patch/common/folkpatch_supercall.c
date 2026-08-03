/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <uapi/asm-generic/errno.h>
#include <folkpatch_supercall.h>

long folkpatch_supercall(int is_authed, long cmd, long arg1, long arg2,
                         long arg3, long arg4)
{
    if (!is_authed) return -EPERM;
    switch (cmd) {
    case SUPERCALL_UTS_SET:
        return folkpatch_uts_set((const char __user *)arg1,
                                 (const char __user *)arg2);
    case SUPERCALL_UTS_RESET:
        return folkpatch_uts_reset();
    case SUPERCALL_SU_AUDIT_LIST:
        return folkpatch_suaudit_list((struct su_audit_entry __user *)arg1,
                                      (int)arg2);
    case SUPERCALL_SU_AUDIT_CLEAR:
        return folkpatch_suaudit_clear();
    default:
        break;
    }
    (void)arg3;
    (void)arg4;
    return -ENOSYS;
}
