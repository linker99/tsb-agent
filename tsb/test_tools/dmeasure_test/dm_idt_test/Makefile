#
# Makefile for dmeasure idt
#

obj-m := httc_idt.o
httc_idt-objs := dm_idt_test.o

PWD = $(shell pwd)
KERNELDIR = /lib/modules/$(shell uname -r)/build

CONFIG_MODULE_SIG = n

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules 
clean: 
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean 

