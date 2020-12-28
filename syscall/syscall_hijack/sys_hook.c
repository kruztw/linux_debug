#include<linux/syscalls.h> /* kallsyms_lookup_name */

uint16_t syscall_idx = __NR_uname;
unsigned long *sys_call_table;
void * orig_func_addr;

#define remove_wp() \
({ \
	__asm__ __volatile__ ("mov %%cr0, %%rax \n and $0xfffffffffffeffff, %%rax \n mov %%rax, %%cr0"::: "rax"); /* remove write protection (bit16) */ \
});

#define recover_wp() \
({ \
	__asm__ __volatile__ ("mov %%cr0, %%rax \n or $0x10000, %%rax \n mov %%rax, %%cr0"::: "rax"); /* remove write protection (bit16) */ \
});


void hooking_syscall(void *hook_addr, uint16_t syscall_offset)
{
    remove_wp();
	sys_call_table[syscall_offset] = (unsigned long)hook_addr;
	recover_wp();
}

void unhooking_syscall(void *orig_addr, uint16_t syscall_offset)
{
    remove_wp();
	//printk("cr0 = %llx\n", read_cr0());
	sys_call_table[syscall_offset] = (unsigned long)orig_addr;
	recover_wp();
}

int foo(void)
{
	printk("Hello from hook!");
	return 0;
}

static int __init my_init(void)
{
	sys_call_table = (long unsigned int *)kallsyms_lookup_name("sys_call_table");
	orig_func_addr = (void*)sys_call_table[syscall_idx];
	hooking_syscall(foo, syscall_idx);
	return 0;
}

static void __exit my_exit(void)
{
	unhooking_syscall(orig_func_addr, syscall_idx);
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
