ifneq ($(KERNELRELEASE),)
#	obj-m := remap_pfn_kmalloc.o
#	obj-m += remap_pfn_vmalloc.o
	TCF_INCLUDE ?= $(src)/../../tcf/include
	ccflags-y := -I$(TCF_INCLUDE)/tcsapi -I$(src)/../common/
	obj-m += httctdd.o
	httctdd-objs = netlink.o comm_driver.o tdd.o tdd_tpcm.o  cmd_man.o
#	obj-m += remap_pfn_alloc_pages.o
#	EXTRA_CFLAGS += -I$(obj)/../../simulator/ -I$(obj)/../netlink/
else
	PWD := $(shell pwd)
	#KERNELDIR ?= $(PWD)/../../linux-4.10.17
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	#CROSS_COMPILE=arm-none-linux-gnueabi-
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	@rm -rf *.o *.mod *.mod.c *.mod.o *.ko *.order *.symvers .*.cmd .tmp_versions .cache.mk *-safe
endif
