/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_PATHHIDE_H_
#define _KP_PATHHIDE_H_

int pathhide_init(void);
long call_pathhide_add(const char __user *u_path);
long call_pathhide_remove(const char __user *u_path);
long call_pathhide_list(char __user *out_buf, int outlen);
long call_pathhide_clear(void);
long call_pathhide_enable(int enable);
long call_pathhide_status(void);

#endif
