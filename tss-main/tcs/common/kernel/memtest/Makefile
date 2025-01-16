#
#Design of TDDL
#

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

MODULE_NAME := memtest
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := mem.o

EXTRA_CFLAGS += -I$(obj)/..

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
#KERNELDIR ?=/usr/src/kylin-headers-4.4.131-20190902-generic

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@rm -fr *.ur-safe *.ver .cache.mk .tmp_versions
