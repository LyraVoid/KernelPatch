/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <uapi/asm-generic/errno.h>
#include <folkpatch_supercall.h>
#include <user_event.h>
#include <kputils.h>

#define FOLKPATCH_EVENT_LEN 64

long folkpatch_report_event(const char __user *u_event,
                            const char __user *u_args)
{
    char event[FOLKPATCH_EVENT_LEN];
    char args[FOLKPATCH_EVENT_LEN];
    long len;

    if (!u_event) return -EINVAL;
    len = compat_strncpy_from_user(event, u_event, sizeof(event));
    if (len <= 0 || len >= sizeof(event)) return -EINVAL;

    args[0] = '\0';
    if (u_args) {
        len = compat_strncpy_from_user(args, u_args, sizeof(args));
        if (len < 0 || len >= sizeof(args)) return -EINVAL;
    }
    return report_user_event(event, args);
}

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
    case SUPERCALL_REPORT_EVENT:
        return folkpatch_report_event((const char __user *)arg1,
                                      (const char __user *)arg2);
    case SUPERCALL_SU_AUDIT_LIST:
        return folkpatch_suaudit_list((struct su_audit_entry __user *)arg1,
                                      (int)arg2);
    case SUPERCALL_SU_AUDIT_CLEAR:
        return folkpatch_suaudit_clear();
    case SUPERCALL_PATHHIDE_ADD:
        return folkpatch_pathhide_add((const char __user *)arg1);
    case SUPERCALL_PATHHIDE_REMOVE:
        return folkpatch_pathhide_remove((const char __user *)arg1);
    case SUPERCALL_PATHHIDE_LIST:
        return folkpatch_pathhide_list((char __user *)arg1, (int)arg2);
    case SUPERCALL_PATHHIDE_CLEAR:
        return folkpatch_pathhide_clear();
    case SUPERCALL_PATHHIDE_ENABLE:
        return folkpatch_pathhide_enable((int)arg1);
    case SUPERCALL_PATHHIDE_STATUS:
        return folkpatch_pathhide_status();
    case SUPERCALL_PATHHIDE_UID_ADD:
        return folkpatch_pathhide_uid_add((uid_t)arg1);
    case SUPERCALL_PATHHIDE_UID_REMOVE:
        return folkpatch_pathhide_uid_remove((uid_t)arg1);
    case SUPERCALL_PATHHIDE_UID_LIST:
        return folkpatch_pathhide_uid_list((char __user *)arg1, (int)arg2);
    case SUPERCALL_PATHHIDE_UID_CLEAR:
        return folkpatch_pathhide_uid_clear();
    case SUPERCALL_PATHHIDE_UID_MODE:
        return folkpatch_pathhide_uid_mode((int)arg1);
    case SUPERCALL_PATHHIDE_FILTER_SYSTEM:
        return folkpatch_pathhide_filter_system((int)arg1);
    case SUPERCALL_NETISOLATE_ENABLE:
        return folkpatch_netisolate_enable((int)arg1);
    case SUPERCALL_NETISOLATE_STATUS:
        return folkpatch_netisolate_status();
    case SUPERCALL_NETISOLATE_UID_ADD:
        return folkpatch_netisolate_uid_add((uid_t)arg1);
    case SUPERCALL_NETISOLATE_UID_REMOVE:
        return folkpatch_netisolate_uid_remove((uid_t)arg1);
    case SUPERCALL_NETISOLATE_UID_LIST:
        return folkpatch_netisolate_uid_list((char __user *)arg1, (int)arg2);
    case SUPERCALL_NETISOLATE_UID_CLEAR:
        return folkpatch_netisolate_uid_clear();
    default:
        break;
    }
    (void)arg3;
    (void)arg4;
    return -ENOSYS;
}
