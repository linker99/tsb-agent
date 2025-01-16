#
#Design of TDDL
#

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

MODULE_NAME := tddl
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := tpcm_tddl.o tcm_tddl.o

ifdef HTTCUTILS_DEBUG
EXTRA_CFLAGS += -DHTTCUTILS_DEBUG
endif




ifdef MEM_TEST
EXTRA_CFLAGS += -DMEM_TEST
endif

ifdef PROJECT_CFLAGS
EXTRA_CFLAGS += $(PROJECT_CFLAGS)
endif
TCF_INCLUDE ?= $(obj)/../../tcf/include
UTILS_INCLUDE ?= $(obj)/../../httcutils/include
EXTRA_CFLAGS += -I$(obj)/../../tcs/tdd/ -I$(obj)/../common/ -I$(obj)/../common/kernel \
-I$(TCF_INCLUDE)/tcsapi

EXTRA_CFLAGS += -Werror

KBUILD_EXTRA_SYMBOLS=$(M)/../../tcs/tdd/Module.symvers
KBUILD_EXTRA_SYMBOLS+=$(M)/../common/kernel/memtest/Module.symvers
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
#KERNELDIR ?= /lib/modules/4.15.4-a0f1-sev/build
#KERNELDIR ?=/usr/src/kylin-headers-4.4.131-20190902-generic

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@rm -fr *.ur-safe *.ver .cache.mk .tmp_versions
