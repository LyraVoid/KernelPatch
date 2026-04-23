/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_SUCOMPAT_H_
#define _KP_SUCOMPAT_H_

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <hook.h>

extern const char sh_path[];
extern const char default_su_path[];
extern const char legacy_su_path[];
extern const char apd_path[];

struct allow_uid
{
    uid_t uid;
    struct su_profile profile;
    struct list_head list;
    struct rcu_head rcu;
};

int is_su_allow_uid(uid_t uid);
int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext);
int su_remove_allow_uid(uid_t uid);
int su_allow_uid_nums();
int su_allow_uids(int is_user, uid_t *out_uids, int out_num);
int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *profile);
int su_reset_path(const char *path);
const char *su_get_path();

int get_ap_mod_exclude(uid_t uid);
int set_ap_mod_exclude(uid_t uid, int exclude);
int list_ap_mod_exclude(uid_t *uids, int len);

int su_audit_nums();
int su_audit_list(int is_user, struct su_audit_entry *out_entries, int out_num);
int su_audit_clear();
void su_audit_record(uid_t uid, pid_t pid, pid_t tgid, uid_t to_uid, const char *sctx, const char *comm);

#endif
