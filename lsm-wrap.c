#define pr_fmt(fmt) "LSM-Wrap: " fmt
#define CONFIG_LSMWRAP_ENABLED 1

#include <linux/lsm_hooks.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/sched.h>    /* current */
#include <linux/string_helpers.h>

#include <linux/ratelimit.h>
#include <linux/spinlock.h>

static void report_load(const char *origin, struct file *file, char *operation) {
    char *cmdline, *pathname;

    pathname = kstrdup_quotable_file(file, GFP_KERNEL);
    cmdline = kstrdup_quotable_cmdline(current, GFP_KERNEL);

    pr_notice("%s %s obj=%s%s%s pid=%d cmdline=%s%s%s\n",
              origin, operation,
              (pathname && pathname[0] != '<') ? "\"" : "",
              pathname,
              (pathname && pathname[0] != '<') ? "\"" : "",
              task_pid_nr(current),
              cmdline ? "\"" : "", cmdline, cmdline ? "\"" : "");

    kfree(cmdline);
    kfree(pathname);
}

extern struct security_hook_heads security_hook_heads;

#ifdef CONFIG_SECURITY_SELINUX_DISABLE
extern void security_delete_hooks(struct security_hook_list *hooks, int count);
#endif

static int enabled = CONFIG_LSMWRAP_ENABLED;

static DEFINE_SPINLOCK(lsmwrap_spinlock);

static void lsmwrap_sb_free_security(struct super_block *mnt_sb) {
    /*
     * When unmounting the filesystem we acknowledge the superblock release
     */
    pr_info("umount fs\n");
}

static int lsmwrap_read_file(struct file *file, enum kernel_read_file_id id) {
    struct super_block *load_root;
    const char *origin = kernel_read_file_id_str(id);

    /* This handles the older init_module API that has a NULL file. */
    if (!file) {
        report_load(origin, NULL, "LSM old API for NULL case");
        return 0;
    }

    /* handle VFS internals */
    load_root = file->f_path.mnt->mnt_sb;

    report_load(origin, file, "LSM hook before spin-lock");

    /* First loaded module/firmware defines the root for all others. */
    spin_lock(&lsmwrap_spinlock);

    report_load(origin, file, "LSM hook inside spin-lock");
    /* check some sensitive properties */

    spin_unlock(&lsmwrap_spinlock);

    report_load(origin, file, "LSM hook after spin-lock");

    return 0;
}

void lsmwrap_task_free(struct task_struct *task) {
    pr_info("LSM hook task-free");
}

static struct security_hook_list lsmwrap_hooks[] = {
        LSM_HOOK_INIT(sb_free_security, lsmwrap_sb_free_security),
        LSM_HOOK_INIT(kernel_read_file, lsmwrap_read_file),
        LSM_HOOK_INIT(task_free, lsmwrap_task_free),
};

void __initlsmwrap_add_hooks(void) {
    pr_info("initing LSM-Wrap (currently %sabled)", enabled ? "en" : "dis");
    security_add_hooks(lsmwrap_hooks, ARRAY_SIZE(lsmwrap_hooks));
}

#if 0
static int __init lsmwrap_init_as_module(void)
{
    printk(KERN_DEBUG "initing LSM-Wrap as a module!\n");
    security_add_hooks(lsmwrap_hooks, ARRAY_SIZE(lsmwrap_hooks));

    return 0;
}

#ifdef CONFIG_SECURITY_SELINUX_DISABLE
static void __exit lsmwrap_exit_as_module(void)
{
    security_delete_hooks(lsmwrap_hooks, ARRAY_SIZE(lsmwrap_hooks));
    printk(KERN_DEBUG "exiting LSM-Wrap module\n");
}
module_exit(lsmwrap_exit_as_module);
#endif

module_init(lsmwrap_init_as_module);
#endif

module_param(enabled, int, 0);
MODULE_PARM_DESC(enabled, "Simple LSM-Wrap module (default: true)");
MODULE_AUTHOR("AI");
MODULE_DESCRIPTION("lsmwrap: no-www-yet");
MODULE_LICENSE("GPL");