CROSS_COMPILE ?=
ARCH ?=
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld


obj-m := hack_section.o
syscall_replace_attack-objs := hack_section.o

PWD = $(shell pwd)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
