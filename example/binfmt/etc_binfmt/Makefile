# run as root
# :name:type:offset:magic:mask:interpreter:flags 

PWD := $(shell pwd)
echo_flag := -e

all: hello.c
	gcc hello.c -o hello
	# extention example
	echo ":say_hi:E::hi::${PWD}/hello:" > /etc/binfmt.d/hello.conf
	# magic_number example
	echo ":hello_beef:M::\xde\xad\xbe\xef::${PWD}/hello:" > /etc/binfmt.d/eat_beef.conf
	systemctl restart systemd-binfmt
	chmod +x ./a.hi
	chmod +x ./beef
	./a.hi
	./beef
	
	

clean:
	- rm /etc/binfmt.d/hello.conf
	- rm /etc/binfmt.d/eat_beef.conf
	- rm ./hello
	systemctl restart systemd-binfmt
	
  
