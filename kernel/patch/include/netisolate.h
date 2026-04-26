/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_NETISOLATE_H_
#define _KP_NETISOLATE_H_

int netisolate_init(void);
long call_netisolate_enable(int enable);
long call_netisolate_status(void);
long call_netisolate_uid_add(int uid);
long call_netisolate_uid_remove(int uid);
long call_netisolate_uid_list(char __user *out_buf, int outlen);
long call_netisolate_uid_clear(void);

#endif
