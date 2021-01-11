# run as root
# :name:type:offset:magic:mask:interpreter:flags 

PWD := $(shell pwd)
echo_flag := -e

all: hello.c
	# extention example
	gcc hello.c -o hello
	echo ":say_hi:E::hi::${PWD}/hello:" > /proc/sys/fs/binfmt_misc/register
	chmod +x ./a.hi
	./a.hi
	# magic_number example
	echo ":hello_beef:M::\xde\xad\xbe\xef::${PWD}/hello:" > /proc/sys/fs/binfmt_misc/register
	chmod +x ./beef
	./beef
	
	

clean:
	- echo "-1" > /proc/sys/fs/binfmt_misc/say_hi
	- echo "-1" > /proc/sys/fs/binfmt_misc/hello_beef
	- rm ./hello
	
  
