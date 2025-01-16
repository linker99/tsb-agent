#
#Desgin of TPCM MEAUSREMENT
#


obj-m := httctcs.o 

httctcs-objs := kutils.o tcs.o notify.o tcs_policy_mgmt.o \
		./smk/sm3.o ./smk/sm4.o tcs_sm.o tcs_kernel.o tcs_tcm.o tcs_power_manage.o\
		tcs_attest.o tcs_file_integrity.o tcs_license.o tcs_auth.o tcs_process.o tcs_policy.o \
		tcs_bmeasure.o tcs_dmeasure.o tcs_kernel.o tcs_kernel_policy.o tcs_maintain.o\
		tcs_protect.o tcs_tnc.o	tcsk_selftest.o

ifdef TSS_DEBUG
EXTRA_CFLAGS += -DTSS_DEBUG
endif

ifdef HTTCUTILS_DEBUG
EXTRA_CFLAGS += -DHTTCUTILS_DEBUG
endif




ifdef PROJECT_CFLAGS
EXTRA_CFLAGS += $(PROJECT_CFLAGS)
endif


TCF_INCLUDE ?= $(obj)/../../../tcf/include
EXTRA_CFLAGS += -I$(obj)/smk -I$(obj)/../../../tcs/tdd/ \
-I$(obj)/../../tddl/ \
-I$(obj)/../../common/ \
-I$(obj)/../../common/kernel \
-I$(TCF_INCLUDE)/tcsapi

EXTRA_CFLAGS += -Werror
KBUILD_EXTRA_SYMBOLS=$(M)/../../tddl/Module.symvers
KBUILD_EXTRA_SYMBOLS+=$(M)/../../tdd/Module.symvers
KBUILD_EXTRA_SYMBOLS+=$(M)/../../common/kernel/memtest/Module.symvers
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
#KERNELDIR ?=/usr/src/kylin-headers-4.4.131-20190902-generic

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@rm -fr *.ur-safe *.ver .cache.mk .tmp_versions

