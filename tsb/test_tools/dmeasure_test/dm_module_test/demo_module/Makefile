
CROSS_COMPILE ?= 
ARCH ?= x86_64
CC:= $(CROSS_COMPILE)gcc
LD:= $(CROSS_COMPILE)ld

PWD = $(shell pwd)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

MODULE_NAME = hellomodule
$(MODULE_NAME)-objs := hello.o
obj-m := $(MODULE_NAME).o

.PHONY: modules
default: modules

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean distclean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
