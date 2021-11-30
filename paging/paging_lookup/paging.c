#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <asm/pgtable.h>

#include <linux/version.h>
#include <linux/debugfs.h>
#include <linux/kasan.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <asm/pgtable.h>
#include <linux/fdtable.h>
#include <linux/kvm_host.h>
#include <linux/sched/mm.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");


#define CONFIG_DEVICE_NAME "ptdump"
struct mm_struct *mm = NULL;


static pgd_t *get_task_pgd(int pid, struct task_struct *task)
{
	/* select host or extended page tables */
	mm = get_task_mm(task);
	if (!mm)
	    return NULL;
	return mm->pgd;
}

static void mapping(u64 pml4, u64 linear)
{
	linear &= 0xffffffffffff; // only 48 bits
	int pgd_off = linear >> 39; // 39 ~ 47
	int pud_off = (linear << (64-39)) >> (64 - 9); // 30 ~ 38
	int pmd_off = (linear << (64-30)) >> (64 - 9); // 21 ~ 29
	int pte_off = (linear << (64-21)) >> (64 - 9); // 12 ~ 20
	int page_off = linear & 0xfff; // 0 ~ 11

        void *lv4  = pml4;
        void *lv3  = (u64)phys_to_virt(*(u64 *)(lv4 + pgd_off*8)&0x0000fffffffff000);
	void *lv2  = (u64)phys_to_virt(*(u64 *)(lv3 + pud_off*8)&0x0000fffffffff000);
	void *lv1  = (u64)phys_to_virt(*(u64 *)(lv2 + pmd_off*8)&0x0000fffffffff000);
	void *lv0  = (u64)phys_to_virt(*(u64 *)(lv1 + pte_off*8)&0x0000fffffffff000);
	void *addr = (u64)(lv0 + page_off);

	printk("pgd_off = %x\n", pgd_off);
	printk("pud_off = %x\n", pud_off);
	printk("pmd_off = %x\n", pmd_off);
	printk("pte_off = %x\n", pte_off);
	printk("page_off = %x\n", page_off);
        printk("*addr = %llx\n", *(u64 *)addr);

	printk("lv4 = %llx\n", __pa(lv4));
	printk("lv3 = %llx\n", (u64)(__pa(lv4)+pgd_off*8));
	printk("lv2 = %llx\n", (u64)(__pa(lv3)+pud_off*8));
	printk("lv1 = %llx\n", (u64)(__pa(lv2)+pmd_off*8));
	printk("lv0 = %llx\n", (u64)(__pa(lv1)+pte_off*8));
	printk("addr= %llx\n", (__pa(lv0)+page_off));
}

static long ptdump_ioctl(struct file *file, unsigned int cmd, unsigned long param)
{
	struct pid *pids;
	struct task_struct *task;
	pgd_t *pgd;
	pid_t pid = 0;

        

	if (pid == 0) {
	    pid = task_pid_nr(current);
	}

	/* obtain the pid struct from the pid */
	pids = find_get_pid(pid);
	if (pids == NULL) {
		return -1;
	}

	task = pid_task(pids, PIDTYPE_PID);
	if (task == NULL) {
		return -1;
	}
	
	/* select either host, extended or shadow page tables*/
	pgd = get_task_pgd(pid, task);
	if (!pgd) {
		return -1;
	}
	printk(KERN_DEBUG "pgd = %px\n", pgd);
	printk(KERN_DEBUG "param = %llx\n", param);
	mapping(pgd, param);
	
	/* release the references */
	mmput(mm);
	return 0;
}


struct proc_ops ptdump_ops = {
	.proc_ioctl = ptdump_ioctl,
	.proc_compat_ioctl   = ptdump_ioctl
};


static int __init page_table_dump_init(void) {
	 struct proc_dir_entry *ptdump_proc = proc_create_data(CONFIG_DEVICE_NAME, 0644, NULL, &ptdump_ops, NULL);
	if (ptdump_proc == NULL) {
		remove_proc_entry(CONFIG_DEVICE_NAME, NULL);
		printk(KERN_ALERT "[ptdump] ERROR: could not initialize the procfs entry!\n");
		return -ENOMEM;
	}
	return 0;
}

static void __exit page_table_dump_exit(void) {
	remove_proc_entry(CONFIG_DEVICE_NAME, NULL);
}

module_init(page_table_dump_init);
module_exit(page_table_dump_exit);
