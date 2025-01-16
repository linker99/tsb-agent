#
# Makefile for kernel platform
#

obj-m := tt.o
tt-objs := test.o

PWD = $(shell pwd)
KERNELDIR = /lib/modules/$(shell uname -r)/build
CONFIG_MODULE_SIG = n
 
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules 
clean: 
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean 

