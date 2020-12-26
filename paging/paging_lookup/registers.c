/*
 * make && make unload && make load && cat /proc/my_proc
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int my_show(struct seq_file *fd, void *v) {
    u64 rax, rbx, rcx, rdx, rdi, rsi, r8, r9, r10, r11, r12, r13, r14, r15, rsp;
    u64 cr0, cr2, cr3, cr4;
    u64 cs, ss, ds, es, fs, gs;
    char buf[0x300] = {};
    int	 len = 0;
    
    asm( " mov %%rax, %0 " : "=m" (rax) :: "rax" );
    asm( " mov %%rbx, %0 " : "=m" (rbx) :: "rbx" );
    asm( " mov %%rcx, %0 " : "=m" (rcx) :: "rcx" );
    asm( " mov %%rdx, %0 " : "=m" (rdx) :: "rdx" );
    asm( " mov %%rdi, %0 " : "=m" (rdi) :: "rdi" );
    asm( " mov %%rsi, %0 " : "=m" (rsi) :: "rsi" );
    asm( " mov %%r8 , %0 " : "=m" (r8 ) :: "r8"  );
    asm( " mov %%r9 , %0 " : "=m" (r9 ) :: "r9"  );
    asm( " mov %%r10, %0 " : "=m" (r10) :: "r10" );
    asm( " mov %%r11, %0 " : "=m" (r11) :: "r11" );
    asm( " mov %%r12, %0 " : "=m" (r12) :: "r12" );
    asm( " mov %%r13, %0 " : "=m" (r13) :: "r13" );
    asm( " mov %%r14, %0 " : "=m" (r14) :: "r14" );
    asm( " mov %%r15, %0 " : "=m" (r15) :: "r15" );
    asm( " mov %%rsp, %0 " : "=m" (rsp) :: "rsp" );
    __asm__ __volatile__ ("mov %%cs, %%rax \n mov %%rax,%0": "=m" (cs)   :: "rax");
    __asm__ __volatile__ ("mov %%ss, %%rax \n mov %%rax,%0": "=m" (ss)   :: "rax");
    __asm__ __volatile__ ("mov %%ds, %%rax \n mov %%rax,%0": "=m" (ds)   :: "rax");
    __asm__ __volatile__ ("mov %%es, %%rax \n mov %%rax,%0": "=m" (es)   :: "rax");
    __asm__ __volatile__ ("mov %%fs, %%rax \n mov %%rax,%0": "=m" (fs)   :: "rax");
    __asm__ __volatile__ ("mov %%gs, %%rax \n mov %%rax,%0": "=m" (gs)   :: "rax");
    __asm__ __volatile__ ("mov %%cr0, %%rax \n mov %%rax,%0": "=m" (cr0) :: "rax");
    __asm__ __volatile__ ("mov %%cr2, %%rax \n mov %%rax,%0": "=m" (cr2) :: "rax");
    __asm__ __volatile__ ("mov %%cr3, %%rax \n mov %%rax,%0": "=m" (cr3) :: "rax");
    __asm__ __volatile__ ("mov %%cr4, %%rax \n mov %%rax,%0": "=m" (cr4) :: "rax");
    

    len += sprintf( buf+len, "rax=0x%08X    "  , rax);
    len += sprintf( buf+len, "rbx=0x%08X    "  , rbx);
    len += sprintf( buf+len, "rcx=0x%08X    "  , rcx);
    len += sprintf( buf+len, "rdx=0x%08X    ", rdx);
    len += sprintf( buf+len, "rdi=0x%08X    "  , rdi);
    len += sprintf( buf+len, "rsi=0x%08X    "  , rsi);
    len += sprintf( buf+len, "rsp=0x%08X    \n"  , rsp);
    len += sprintf( buf+len, "r8=0x%08X    "   , r8 );
    len += sprintf( buf+len, "r9=0x%08X    "   , r9 );
    len += sprintf( buf+len, "r10=0x%08X    "  , r10);
    len += sprintf( buf+len, "r11=0x%08X    "  , r11);
    len += sprintf( buf+len, "r12=0x%08X    "  , r12);
    len += sprintf( buf+len, "r13=0x%08X    "  , r13);
    len += sprintf( buf+len, "r14=0x%08X    "  , r14);
    len += sprintf( buf+len, "r15=0x%08X    \n", r15);
    len += sprintf( buf+len, "cs=0x%08X    "   , cs );
    len += sprintf( buf+len, "ss=0x%08X    "   , ss );
    len += sprintf( buf+len, "ds=0x%08X    "   , ds );
    len += sprintf( buf+len, "es=0x%08X    "   , es );
    len += sprintf( buf+len, "fs=0x%08X    "   , fs );
    len += sprintf( buf+len, "gs=0x%08X    \n" , gs );
    len += sprintf( buf+len, "cr0=0x%08X    "  , cr0);
    len += sprintf( buf+len, "cr2=0x%08X    "  , cr2);
    len += sprintf( buf+len, "cr3=0x%08X    "  , cr3);
    len += sprintf( buf+len, "cr4=0x%08X    "  , cr4);
    buf[len] = '\n';

    seq_printf(fd, buf);
    return 0;
}

static int my_open(struct inode *inode, struct  file *file) {
  return single_open(file, my_show, NULL);
}

static const struct file_operations my_fops = {
  .owner = THIS_MODULE,
  .open = my_open,
  .read = seq_read,
  .release = single_release,
};

static int __init my_init(void) {
  proc_create("registers", 0, NULL, &my_fops);
  return 0;
}

static void __exit my_exit(void) {
  remove_proc_entry("registers", NULL);
}

MODULE_LICENSE("GPL");
module_init( my_init );
module_exit( my_exit );
