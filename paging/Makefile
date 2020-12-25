# 參考 https://cloud.tencent.com/developer/article/1421792 
# 內核必須懂(七)
# make
# make load
# ./a.out
#
# 可以用 ./fileview /dev/dram 觀察 (步驟請參考連結)
# 也可以用 dmesg 查看結果 (詳情請見 paging.c)
#
# paging.c : 透過 ioctl 喂入 linear_address (見 test.c , addr: &a) , 並按照連結流程找出 a 在 DRAM 的位址
# registers.c : 將暫存器印出來, 跟這邊沒什麼關係, 當初是為了方便觀察 CR3 , 但實際上用不到
# dram.c : 將 DRAM 的 page 載入, 並用 fileview 觀察 (./fileview /dev/dram)

ifneq	($(KERNELRELEASE),)
obj-m	:= registers.o paging.o dram.o 

else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
default: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	rm -r -f .tmp_versions .*.cmd *.o *.symvers modules* *.mod* 

load:
	-insmod ./registers.ko
	-insmod ./paging.ko
	-insmod ./dram.ko
	-mknod /dev/dram c 88 0 # chardev major minor, 可透過 /proc/devices 觀察, 這邊我是直接寫 88
unload:
	-rmmod registers
	-rmmod paging
	-rmmod dram
	-rm /dev/dram
endif

