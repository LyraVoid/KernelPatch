/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_FOLKPATCH_SUAUDIT_H_
#define _KP_FOLKPATCH_SUAUDIT_H_

#include <ktypes.h>
#include <linux/uaccess.h>
#include <uapi/scdefs.h>

int folkpatch_suaudit_init(void);
void folkpatch_suaudit_record(uid_t uid, pid_t pid, pid_t tgid,
                              uid_t to_uid, const char *scontext,
                              const char *comm);
long folkpatch_suaudit_list(struct su_audit_entry __user *entries, int num);
long folkpatch_suaudit_clear(void);

#endif
