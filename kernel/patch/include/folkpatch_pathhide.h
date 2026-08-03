/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_FOLKPATCH_PATHHIDE_H_
#define _KP_FOLKPATCH_PATHHIDE_H_

#include <ktypes.h>
#include <linux/uaccess.h>

int folkpatch_pathhide_init(void);
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

#endif
