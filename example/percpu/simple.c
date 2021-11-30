/* reference: https://biscuitos.github.io/blog/HISTORY-PERCPU/#A */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/percpu.h>

struct node_percpu {
        unsigned long index;
        unsigned long offset;
};


static int TestCase_alloc_percpu(void)
{
        struct node_percpu __percpu *np, *ptr;
        int cpu;

        /* Allocate percpu */
        np = alloc_percpu(struct node_percpu);
        if (!np) {
                printk("%s __alloc_percpu failed.\n", __func__);
                return -ENOMEM;
        }

        /* setup */
        for_each_possible_cpu(cpu) {
                ptr = per_cpu_ptr(np, cpu);
                ptr->index = cpu * 0x10;
        }

        /* usage */
        for_each_possible_cpu(cpu) {
                ptr = per_cpu_ptr(np, cpu);
                printk("CPU-%d Index %#lx\n", cpu, ptr->index);
        }

        /* free percpu */
        free_percpu(np);
        return 0;
}

static int my_init (void)
{
    TestCase_alloc_percpu();
    return 0;
}

static void my_exit (void)
{
    return;   
}

module_init (my_init);
module_exit (my_exit);
MODULE_LICENSE ("GPL");
