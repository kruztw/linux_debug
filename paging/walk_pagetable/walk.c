#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/debugfs.h>
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

pid_t pid;

#ifndef __x86_64__
  #error "wrong arch"
#endif

#ifndef X86_CR4_PKE
//defined in Linux >= 4.6
#define X86_CR4_PKE_BIT		22 /*Protection Keys support */
#define X86_CR4_PKE		_BITUL(X86_CR4_PKE_BIT)
#endif

static inline u64 bitmask_numbits(int numbits)
{
	return (1LL << numbits) - 1;
}


/* A 4k intel page table with 512 64bit entries. */
struct page_table{
	void* entry[512];
};

/* Each level of page tables is responsible for 9 bits of the virtual address.
 * PML4 39:47 (inclusive)
 * PDPT 30:38 (inclusive)
 * PD   21:29 (inclusive)
 * PT   12:20 (inclusive)
 * (0:11 are the offset in a 4K page)
 * The position of the bit of the virtual memory address that the page table level refers to.
 */
enum pt_addr_bit { PML4=39, PDPT=30, PD=21, PT=12 };

/* Valid intel page sizes*/
char* string_page_size(enum pt_addr_bit bitpos)
{
	size_t pagesize;
	pagesize = 1 << bitpos;
	switch(pagesize){
		case 1024*1024*1024:
			return "1GB";
		case 2*1024*1024:
			return "2MB";
		case 4*1024:
			return "4KB";
		default:
			return "<BUG PAGESIZE>";
	}
}

/* page table bits 51:M reserved, must be 0. Create global bitmask once.*/
static u64 pte_reserved_flags;


static int check_entry(u64 e){
	/* 51:M reserved, must be 0*/
	if(e & pte_reserved_flags){
		return 0;
	}
	if(e & _PAGE_PSE){
		//TODO references a page directly, probably sanity check address?
	}
	if(!(e & _PAGE_PRESENT) && e){
		return 1;
	}
	return 1;
}	

struct dumptbl_state {
	int maxphyaddr;

	struct page_table *pml4; /*pointer to pml4 page table in virtual memory*/
	int pml4_i; /*current index into the pml4, points to a pml4e (pml4 entry)*/
	u64 pml4_baddr; /*virtual memory base address mapped by current pml4e*/

	struct page_table *pdpt;
	int pdpt_i;
	u64 pdpt_baddr;

	struct page_table *pd;
	int pd_i;
	u64 pd_baddr;

	struct page_table *pt;
	int pt_i;
	u64 pt_baddr;

	// compress output, don't print same entries all over
	u64 last_addr;
	u64 last_flags;
	int skipped;
};


static inline u64 entry_extract_flags(u64 entry)
{
	// TODO dump more flags?
	return entry & (_PAGE_NX | _PAGE_RW | _PAGE_USER | _PAGE_PWT | _PAGE_PCD | _PAGE_ACCESSED);
}


/*The part of the virtual address defined by the page table entry at index for the page table level indicated by bitpos*/
static inline u64 pte_addr_part(int index, enum pt_addr_bit bitpos)
{
	return ((u64)index) << bitpos;
}

int dump_entry(struct seq_file *s, struct dumptbl_state *state, enum pt_addr_bit bitpos)
{
	char *str_level;
	struct page_table *table; 
	int i; 
	u64 e;

	int ret = 1; 

	u64 *baddr; //pointer to state struct with base address of current entry. To be set in this function.
	u64 outer_baddr; //base address of the outer page tables (base address of entry = outer_baddr | baddr)
	u64 addr_max; //maximum virtual address described by the current page table entry

	int _direct_mapping = 0; //entry maps a page directly

	switch(bitpos){
		case PML4:
			table = state->pml4;
			i = state->pml4_i;
			str_level = "pml4";
			baddr = &state->pml4_baddr;
			outer_baddr = 0;
			if(pte_addr_part(i, 39) & (1LL << 47) /*highest bit set*/){
				outer_baddr = (0xffffLL << 48);
			}
			break;
		case PDPT:
			table = state->pdpt;
			i = state->pdpt_i;
			str_level = "  pdpt";
			outer_baddr = state->pml4_baddr;
			baddr = &state->pdpt_baddr;
			break;
		case PD:
			table = state->pd;
			i = state->pd_i;
			str_level = "      pd";
			outer_baddr = state->pdpt_baddr;
			baddr = &state->pd_baddr;
			break;
		case PT: /*final level*/
			table = state->pt;
			i = state->pt_i;
			str_level = "        pt";
			outer_baddr = state->pd_baddr;
			baddr = &state->pt_baddr;
			break;
	}

	e = (u64)table->entry[i];


	if(!(e & _PAGE_PRESENT)){
		/*skip page which is marked not present. Do not emit any output.*/
		return 0;
	}
	*baddr = outer_baddr | pte_addr_part(i, bitpos);
	addr_max = bitmask_numbits(bitpos);
	addr_max |= *baddr;

	if((e & _PAGE_PSE) || bitpos == PT){
		// PSE for 2MB or 1GB direct mapping
		// bitpos == PT, then the _PAGE_PSE bit is the PAT bit. But for 4k pages, we always have a direct mapping
		_direct_mapping = 1;
		ret = 0; // do not descend to any deeper page tables!
	}

		
	seq_printf(s, "%s v %px %px %s %s %s %s %s %s", str_level,
		(void*)*baddr, (void*)addr_max,
		e & _PAGE_RW ? "W" : "R",
		e & _PAGE_USER ? "U" : "K" ,
		e & _PAGE_PWT ? "PWT" : "",
		e & _PAGE_PCD ? "PCD" : "",
		e & _PAGE_ACCESSED ? "A" : "",
		e & _PAGE_NX ? "NX" : ""
		);
	if(_direct_mapping){
		seq_printf(s, " -> %s page", string_page_size(bitpos));
	}
	seq_printf(s, "\n");
	

	state->last_addr = addr_max;
	state->last_flags = entry_extract_flags(e);
	return ret;
}

void* next_page_table_vaddr(u64 pagetbl_entry)
{
	void *vaddr; //virtual addr of page table entry
	phys_addr_t paddr; //physical addr of page table entry

	/*pagetble_entry bits 51:12 contains the physical address of the next page table level*/
	u64 bm = bitmask_numbits(51 - 12 + 1) << 12;
	paddr = pagetbl_entry & bm;

	vaddr = phys_to_virt(paddr);
	if(!virt_addr_valid(vaddr) || !IS_ALIGNED(paddr, 4096)){
		printk("CRITICAL: invalid addr!\n");
		return NULL; /*error*/
	}
	return vaddr;
}

static pgd_t *get_task_pgd(int pid, struct task_struct *task)
{
	int retval;
	struct mm_struct *mm = get_task_mm(task);
	if (!mm)
		return NULL;
	return mm->pgd;
}

static int dump_pagetable(struct seq_file *s)
{
    struct pid *pids;
	struct task_struct *task;
	pgd_t *pgd;

    printk("pid = %d\n", pid);
	if (pid == 0) 
		pid = task_pid_nr(current);

	pids = find_get_pid(pid);
	if (pids == NULL) {
		seq_printf(s, "pid: %d not found\n", pid);
	    goto error;
	}

	task = pid_task(pids, PIDTYPE_PID);
	if (task == NULL) {
		seq_printf(s, "task == NULL\n");
	    goto error;
	}
	
	pgd = get_task_pgd(pid, task);
	if (!pgd) {
		seq_printf(s, "pgd == NULL\n");
		goto error;
	}

	struct dumptbl_state state = {0};

    u64 cr0, cr3, cr4 = 0;

	state.maxphyaddr = boot_cpu_data.x86_phys_bits;
    pte_reserved_flags = bitmask_numbits(51 - state.maxphyaddr + 1); //bitmap with up to 51 bit set
	pte_reserved_flags <<= state.maxphyaddr;

    void *cr3_pt_base = __pa(pgd);
	state.pml4 = phys_to_virt(cr3_pt_base);
	seq_printf(s, "page table in virtual  memory at 0x%px\n", state.pml4);
	seq_printf(s, "page table in physical memory at 0x%px\n\n", cr3_pt_base);

	for(state.pml4_i = 0; state.pml4_i < 512; ++state.pml4_i){
		if(dump_entry(s, &state, PML4)){
			state.pdpt = next_page_table_vaddr((u64)state.pml4->entry[state.pml4_i]);
			for(state.pdpt_i = 0; state.pdpt_i < 512; ++state.pdpt_i){
				if(dump_entry(s, &state, PDPT)){
					state.pd = next_page_table_vaddr((u64)state.pdpt->entry[state.pdpt_i]);
					for(state.pd_i = 0; state.pd_i < 512; ++state.pd_i){
						if(dump_entry(s, &state, PD)){
							state.pt = next_page_table_vaddr((u64)state.pd->entry[state.pd_i]);
							for(state.pt_i = 0; state.pt_i < 512; ++state.pt_i){
								dump_entry(s, &state, PT);
							}
							state.pt = NULL;
							state.pt_i = 0;
							state.pt_baddr = 0;
						}
					}
					state.pd = NULL;
					state.pd_i = 0;
					state.pd_baddr = 0;
				}
			}
			state.pdpt = NULL;
			state.pdpt_i = 0;
			state.pdpt_baddr = 0;
		}
	}

	return 0;
error:
    pid = 0;
	return -1;
}

static int pagetbl_seq_show(struct seq_file *s, void *v)
{
	dump_pagetable(s);
	return 0;
}


static int pagetbl_open(struct inode *inode, struct file *file)
{
    single_open(file, pagetbl_seq_show, NULL);
	return 0;
}

static ssize_t write_pid(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos)
{	
	char str_pid[0x10] = {};
    copy_from_user(str_pid, buffer, count);
	kstrtoint(str_pid, 10, &pid);
	return count;
}


static const struct file_operations pagetbl_file_ops = {
        .owner                   = THIS_MODULE,
        .open                    = pagetbl_open,
        .read                    = seq_read,
		.write                   = write_pid,
        .llseek                  = seq_lseek,
        .release                 = single_release // not seq_release because we use single_open
};


struct dentry *pagetbl_debug_root;

static int __init test_module_init(void)
{
	pagetbl_debug_root = debugfs_create_dir("walk", NULL);
	if (!pagetbl_debug_root)
		return -ENOMEM;

	if (!debugfs_create_file("pagetable", 0444, pagetbl_debug_root, NULL, &pagetbl_file_ops))
		goto fail;

	return 0;
fail:
	debugfs_remove_recursive(pagetbl_debug_root);
	return -ENOMEM;
}
module_init(test_module_init);

static void __exit test_module_exit(void)
{
	debugfs_remove_recursive(pagetbl_debug_root);
}

module_exit(test_module_exit);

MODULE_AUTHOR("Cornelius Diekmann");
MODULE_LICENSE("GPL");
