#!/usr/bin/env python3
"""Run source-based host regressions without an Android device or ARM toolchain."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel"


def function(path, name):
    text = path.read_text()
    import re
    match = re.search(r"^(?:static )?(?:int|void) " + name + r"\([^\n]*\)\n\{", text, re.M)
    assert match, name
    start = text.index("{", match.start())
    # These C functions follow the repository's column-zero closing-brace style.
    end = text.index("\n}", start) + 2
    return text[match.start():end]


def run(args, **kwargs):
    subprocess.run(args, check=True, timeout=60, **kwargs)


def kernel_tests(tmp):
    hide = KERNEL / "patch/common/selinux_hide.c"
    policy = KERNEL / "patch/common/selinux_sepolicy.c"
    code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef int hook_err_t;
#define HOOK_NO_ERR 0
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_mb() ((void)0)
#define logkfw(...) ((void)0)
#define logkfi(...) ((void)0)
#define log_boot(...) ((void)0)
typedef int atomic_t;
static int atomic_cmpxchg(int *p, int old, int value) {
    int previous = *p; if (*p == old) *p = value; return previous;
}
static int atomic_xchg(int *p, int value) { int old = *p; *p = value; return old; }
static bool selinux_hide_enabled;
static atomic_t selinux_hide_control_busy;
static bool selinux_hide_is_supported(void) { return true; }
static unsigned long sel_write_context_addr = 1, sel_write_access_addr = 2,
    selinux_setprocattr_addr = 3, sel_read_handle_status_addr = 4, sel_mmap_handle_status_addr = 5;
static void *orig_context_write, *orig_access_write, *orig_setprocattr,
    *orig_sel_read_handle_status, *orig_sel_mmap_handle_status;
static void *my_write_context, *my_write_access, *my_setprocattr,
    *my_sel_read_handle_status, *my_sel_mmap_handle_status;
static void fill_fake_status_bytes(void) {}
static void init_fake_status(void) {}
static int installs, fail_at;
static int hook(void *func, void *replace, void **backup) {
    (void)func; (void)replace; ++installs; *backup = (void *)100;
    return installs == fail_at ? -EIO : 0;
}
static bool g_load_hook_installed;
#define KP_SEPOLICY_WITH_POLICY_MIN_VERSION 604
static int kver = 604;
static bool selinux_sepolicy_supported(void) { return true; }
static unsigned long lookup_name_with_suffix(const char *s) { (void)s; return 1; }
static void *after_security_load_policy_3, *after_security_load_policy_4;
static int load_result, load_calls;
static int hook_wrap3(void *p, void *b, void *a, void *u) {
    (void)p; (void)b; (void)a; (void)u; ++load_calls; return load_result;
}
#define hook_wrap4 hook_wrap3
static const char *boot_log;
static size_t printed;
static const char *get_boot_log(void) { return boot_log; }
static void printk(const char *fmt, const char *buf) {
    (void)fmt; assert(strlen(buf) <= 1023); printed += strlen(buf);
}
'''
    for name in ("kp_install_hook", "selinux_hide_install_hooks", "selinux_hide_enable", "selinux_hide_disable"):
        code += function(hide, name) + "\n"
    code += function(policy, "kp_install_load_hook") + "\n"
    code += function(KERNEL / "patch/patch.c", "print_bootlog") + "\n"
    code += r'''
int main(void) {
    sel_write_context_addr = 0;
    assert(selinux_hide_enable() == -ENOENT && installs == 0 && !selinux_hide_enabled);
    sel_write_context_addr = 1; fail_at = 3;
    assert(selinux_hide_enable() == -EIO && !selinux_hide_enabled);
    assert(orig_context_write && orig_access_write && !orig_setprocattr);
    fail_at = 0;
    assert(selinux_hide_enable() == 0 && installs == 6 && selinux_hide_enabled);
    assert(selinux_hide_disable() == 0 && !selinux_hide_enabled && orig_context_write);
    assert(selinux_hide_enable() == 0 && installs == 6);
    selinux_hide_control_busy = 1;
    assert(selinux_hide_disable() == -EBUSY && selinux_hide_enabled);
    load_result = -EIO;
    assert(kp_install_load_hook() == -EIO && !g_load_hook_installed);
    load_result = 0;
    assert(kp_install_load_hook() == 0 && g_load_hook_installed);
    assert(kp_install_load_hook() == 0 && load_calls == 2);
    char input[8193]; memset(input, 'x', sizeof(input) - 1); input[8192] = 0;
    boot_log = input; print_bootlog(); assert(printed == 8192);
    printed = 0; input[1022] = '\n'; print_bootlog(); assert(printed == 8192);
    puts("PASS: missing symbols, partial install/retry, resident disable, busy control, load retry, long panic logs");
}
'''
    source = tmp / "kernel_test.c"
    source.write_text(code)
    binary = tmp / "kernel_test"
    run(["gcc", "-std=gnu11", "-fsanitize=address,undefined", "-g", str(source), "-o", str(binary)])
    run([str(binary)])


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="kernelpatch-tests-") as directory:
        temp = Path(directory)
        kernel_tests(temp)
