/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <uapi/asm-generic/errno.h>
#include <folkpatch_supercall.h>

long folkpatch_supercall(int is_authed, long cmd, long arg1, long arg2,
                         long arg3, long arg4)
{
    (void)is_authed;
    (void)cmd;
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)arg4;
    return -ENOSYS;
}
