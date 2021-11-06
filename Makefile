obj-m := lab2.o

KDIR := /home/iliyash/kernel_src/linux

all:
	$(MAKE) -C $(KDIR) M=$$PWD 



clean:
	rm -rf lab2 *.o *.ko *.mod *.dwo *.mod.c Module.symvers modules.order
check:
	cppcheck --enable=all --inconclusive --library=posix lab2.c
	$(KDIR)/scripts/checkpatch.pl -f lab2.c
load:
	sudo insmod lab2.ko
rm:
	sudo rmmod lab2.ko
reload:
	sudo rmmod lab2.ko
	sudo insmod lab2.ko
