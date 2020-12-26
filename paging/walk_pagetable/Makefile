# echo "<pid>" > /sys/kernel/debug/walk/pagetable
# cat /sys/kernel/debug/walk/pagetable | less
# compare with /proc/<pid>/maps

name=walk
obj-m := ${name}.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	-rmmod ${name}
	-insmod ./${name}.ko
	-rm *.o *mod* *Mod* .*
