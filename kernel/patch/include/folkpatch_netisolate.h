/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_FOLKPATCH_NETISOLATE_H_
#define _KP_FOLKPATCH_NETISOLATE_H_

#include <ktypes.h>
#include <linux/uaccess.h>

int folkpatch_netisolate_init(void);
long folkpatch_netisolate_enable(int enable);
long folkpatch_netisolate_status(void);
long folkpatch_netisolate_uid_add(uid_t uid);
long folkpatch_netisolate_uid_remove(uid_t uid);
long folkpatch_netisolate_uid_list(char __user *out, int out_len);
long folkpatch_netisolate_uid_clear(void);

#endif
