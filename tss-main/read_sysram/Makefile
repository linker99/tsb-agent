# Makefile 4.0
obj-m := read_sysram.o
CURRENT_PATH := $(shell pwd)
LINUX_KERNEL := $(shell uname -r)
#LINUX_KERNEL_PATH := /usr/src/linux-headers-$(LINUX_KERNEL)
LINUX_KERNEL_PATH := /lib/modules/$(shell uname -r)/build

all:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules
clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean
