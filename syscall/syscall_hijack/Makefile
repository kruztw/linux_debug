# make && make unload && make load && sleep 3 && uname && dmesg
#
# environ: ubuntu 20.04
#
# make 會呼叫 uname, 記得先 make unload

ifneq	($(KERNELRELEASE),)
obj-m	:= sys_hook.o 

else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
default: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	rm -r -f .tmp_versions .*.cmd *.o *.symvers modules* *.mod* 

load:
	-insmod ./sys_hook.ko
unload:
	-rmmod sys_hook
endif

