#
# Makefile for dmeasure net
#

CROSS_COMPILE ?= 
ARCH ?= arm
CC:= $(CROSS_COMPILE)gcc
LD:= $(CROSS_COMPILE)ld


PWD = $(shell pwd)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
CONFIG_MODULE_SIG = n

obj-m := httc_net.o
httc_net-objs := dm_net_test.o


default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules 
clean: 
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean 

