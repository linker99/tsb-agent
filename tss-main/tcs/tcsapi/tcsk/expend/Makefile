#
#Desgin of TCS TCM
#


obj-m := httctcs-ex.o 
httctcs-ex-objs := tcsk_sm.o tcsk_tcm.o

ifdef HTTCUTILS_DEBUG
EXTRA_CFLAGS += -DHTTCUTILS_DEBUG
endif

ifdef MEM_TEST
EXTRA_CFLAGS += -DMEM_TEST
endif

#EXTRA_CFLAGS += -I$(obj)/.. -I$(obj)/../smk -I$(obj)/../../../../tpcmdriver/ -I$(obj)/../../../tddl/ -I$(obj)/../../../common/ -I$(obj)/../../../common/kernel -I$(obj)/../../../include/tcsapi
EXTRA_CFLAGS += -I$(obj)/.. -I$(obj)/../smk -I$(obj)/../../../../tpcmdriver/ -I$(obj)/../../../tddl/ -I$(obj)/../../../common/ -I$(obj)/../../../common/kernel -I$(obj)/../../../../tcf/include/tcsapi -I$(obj)/../../../tdd/

EXTRA_CFLAGS += -Werror
KBUILD_EXTRA_SYMBOLS=$(M)/../Module.symvers
KBUILD_EXTRA_SYMBOLS+=$(M)/../../../common/kernel/memtest/Module.symvers
ifeq ($(shell uname -r | awk -F. '{print $$1}'),5)
#        ifeq ($(shell uname -r | awk -F. '{print $$2}'),15)
                KBUILD_EXTRA_SYMBOLS+=$(M)/../../../tddl/Module.symvers
                KBUILD_EXTRA_SYMBOLS+=$(M)/../../../tdd/Module.symvers
#         endif
endif

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@rm -fr *.ur-safe *.ver .cache.mk .tmp_versions

