#
#Design of TPCMK utils
#

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

obj-m := nv_definespace.o nv_is_definespace.o nv_write.o nv_read.o\
	sm3_test.o sm3_part_test.o nv_err_test.o

ifdef PLATFORM
EXTRA_CFLAGS += -D$(PLATFORM)
endif

#EXTRA_CFLAGS += -I$(obj)/../../../../../tpcmdriver/ -I$(obj)/../../../tcsk/ -I$(obj)/../../../tcsk/expend -I$(obj)/../../../../common/ -I$(obj)/../../../../common/kernel/ -I$(obj)/../../../../include/tcsapi
EXTRA_CFLAGS += -I$(obj)/../../../../../tpcmdriver/ -I$(obj)/../../../tcsk/ -I$(obj)/../../../tcsk/expend -I$(obj)/../../../../common/ -I$(obj)/../../../../common/kernel/ -I$(obj)/../../../../../tcf/include/tcsapi
EXTRA_CFLAGS += -Werror

EXTRA_CFLAGS += -Wno-implicit-fallthrough

ifdef MEM_TEST
EXTRA_CFLAGS += -DMEM_TEST
endif

EXTRA_CFLAGS += -DHTTCUTILS_DEBUG

KBUILD_EXTRA_SYMBOLS=$(M)/../../../tcsk/expend/Module.symvers
KBUILD_EXTRA_SYMBOLS+=$(M)/../../../../common/kernel/memtest/Module.symvers
KBUILD_EXTRA_SYMBOLS+=$(M)/../../../../tcsapi/tcsk/Module.symvers
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@rm -fr *.ur-safe *.ver .cache.mk .tmp_versions
