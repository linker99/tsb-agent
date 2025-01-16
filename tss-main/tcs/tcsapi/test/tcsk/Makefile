#
#Design of TPCMK utils
#

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

obj-m :=\
	boot_measure.o\
	boot_measure_selftest.o\
	simple_bmeasure_selftest.o\
	simple_boot_measure.o\
	collect_measure.o\
	intercept_measure.o\
	simple_intercept_measure.o\
	set_systemtime.o\
	get_tpcmlog.o\
	get_license_status.o\
	get_license_info.o\
	get_license_entity.o\
	save_mem_data.o\
	read_mem_data.o\
	get_tpcm_features.o\
	get_trust_status.o\
	extern_bmeasure_selftest.o\
	extern_simple_bmeasure_selftest.o\
	get_kernel_policy.o\
	update_auth_policy.o\
	get_notify.o\
	get_critical_file_integrity_digest.o\
	tcsk_sync_trust_status.o\
	concurrent_test.o\
	tcsk_kernel_section_trust_status.o\
	tcsk_tpcm_selftest_test.o\
        collect_measure.o

ifdef PLATFORM
EXTRA_CFLAGS += -D$(PLATFORM)
endif
TCF_INCLUDE ?= $(obj)/../../../../tcf/include
UTILS_INCLUDE ?= $(obj)/../../../../httcutils/include
EXTRA_CFLAGS += -I$(obj)/../../../../tcs/tdd/ \
-I$(obj)/../../tcsk/ -I$(obj)/../../tcsk/smk/ \
-I$(obj)/../../../common/ -I$(obj)/../../../common/kernel/ \
-I$(TCF_INCLUDE)/tcsapi

EXTRA_CFLAGS += -Werror

EXTRA_CFLAGS += -Wno-implicit-fallthrough

ifdef MEM_TEST
EXTRA_CFLAGS += -DMEM_TEST
endif

EXTRA_CFLAGS += -DHTTCUTILS_DEBUG

KBUILD_EXTRA_SYMBOLS=$(M)/../../tcsk/Module.symvers
KBUILD_EXTRA_SYMBOLS+=$(M)/../../../common/kernel/memtest/Module.symvers
KBUILD_EXTRA_SYMBOLS+=$(M)/../../../tdd/Module.symvers
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@rm -fr *.ur-safe *.ver .cache.mk .tmp_versions
