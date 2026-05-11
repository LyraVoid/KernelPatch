#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/random.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/mm.h>
#include "selinuxhide.h"
struct file{};

typedef ssize_t (*sel_write_access)(struct file *file, char *buf, size_t size);
typedef ssize_t (*sel_write_context)(struct file *file, char *buf, size_t size);
sel_write_access ori_sel_write_access,back_sel_write_access;
sel_write_context ori_sel_write_context,back_sel_write_context;

ssize_t hk_sel_write_context(struct file *file, char *buf, size_t size){

    uid_t uid = current_uid();
    if(uid < 10000){
        return back_sel_write_context(file,buf,size);
    }
    char tmp[64];
    if (strstr(buf, "magisk")) {
        pr_info("selinux-hide: found MASGISK\n");
        return -22;
    }
    if (strstr(buf, "ksu")) {
        pr_info("selinux-hide: found Kernelsu\n");
        return -22;
    }

    pr_info("selinux-hide context uid: %d buf: %s\n",uid,buf);
    // 默认允许
    return back_sel_write_context(file,buf,size);
}

ssize_t hk_sel_write_access(struct file *file, char *buf, size_t size){

    uid_t uid = current_uid();
    if(uid < 10000){
        return back_sel_write_access(file,buf,size);
    }
    if (strstr(buf, "magisk")) {
        pr_info("selinux-hide: found MASGISK\n");
        return -22;
    }
    if (strstr(buf, "ksu")) {
        pr_info("selinux-hide: found Kernelsu\n");
        return -22;
    }
    if(strstr(buf,"system_server") && strstr(buf,"2000000")){
        pr_info("selinux-hide: found system can execmem\n");
        return -22;
    }
    if(strstr(buf,"lsposed")){
        pr_info("selinux-hide: found LSPosed\n");
        return -22;
    }
    pr_info("selinux-hide access uid: %d buf: %s\n",uid,buf);
    // 默认允许
    return back_sel_write_access(file,buf,size);
}


int sehide_init(void)
{
    ori_sel_write_access = (void*)kallsyms_lookup_name("sel_write_access");
    ori_sel_write_context = (void*)kallsyms_lookup_name("sel_write_context");
    hook_err_t err = hook(ori_sel_write_access,hk_sel_write_access,(void**)&back_sel_write_access);
    if(err){
        pr_info("selinux-hide hook err:%d\n",err);
    }
    hook_err_t err1 = hook(ori_sel_write_context,hk_sel_write_context,(void**)&back_sel_write_context);
    if(err1){
        pr_info("selinux-hide hook err:%d\n",err1);
    }
    pr_info("selinux-hide: %p,%p\n");
    return 0;
}

int ksu_selinux_hide_disable(void)
{
    pr_info("selinux_hide: exit selinux hide\n");
    unhook(ori_sel_write_access);
    unhook(ori_sel_write_context);
    pr_info("selinux_hide: uninstall hook success");
    return 0;
}
