#
# Makefile for dmeasure filesystem
#

CROSS_COMPILE ?= 
ARCH ?= arm
CC:= $(CROSS_COMPILE)gcc
LD:= $(CROSS_COMPILE)ld


PWD = $(shell pwd)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
CONFIG_MODULE_SIG = n

obj-m := httc_filesystem.o
httc_filesystem-objs := dm_filesystem_test.o


default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules 
clean: 
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean 

