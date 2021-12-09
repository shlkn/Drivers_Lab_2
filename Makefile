obj-m := lab2.o

KDIR := /home/iliyash/Kernel_src/linux

all:
	$(MAKE) -C $(KDIR) M=$$PWD 



clean:
	rm -rf lab2 *.o *.ko *.mod *.dwo *.mod.c Module.symvers modules.order prog1
	sudo dmesg -c
check:
	cppcheck --enable=all --inconclusive --library=posix lab2.c
	$(KDIR)/scripts/checkpatch.pl -f lab2.c
load:
	sudo mknod /dev/lab2 c 237 0
	sudo chmod 777 /dev/lab2
	sudo insmod lab2.ko
rm:
	sudo rmmod lab2.ko
reload:
	$(MAKE) -C $(KDIR) M=$$PWD 
	sudo rmmod lab2.ko
	sudo insmod lab2.ko
	sudo dmesg -c
us:
	gcc write.c -o write
	gcc read.c -o read
	gcc ReadAll.c -o readall
	