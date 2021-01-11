# run as root
# :name:type:offset:magic:mask:interpreter:flags 

PWD := $(shell pwd)

all: hello.c
	gcc hello.c -o hello
	echo ":say_hi:E::hi::${PWD}/hello:" > /proc/sys/fs/binfmt_misc/register
	touch a.hi
	chmod +x ./a.hi
	./a.hi

clean: 
	- echo "-1" > /proc/sys/fs/binfmt_misc/say_hi
	- rm ./a.hi ./hello
	
  
