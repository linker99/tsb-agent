#
# Makefile for kernel platform
#

CROSS_COMPILE ?=
ARCH ?=
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

OSVERSION :=$(shell uname -r)

obj-m := platform.o
platform-objs := main.o hook/hook.o hook/ksym.o hook/lsm.o hook/syscall.o \
				log/log_buff.o  log/log.o \
				utils/crc.o utils/klib_fileio.o utils/debug.o utils/vfs.o utils/write_protect.o \
				msg/miscdev.o msg/ioctl.o policy/log_config_policy.o policy/feature_configure.o \
				tpcm/tpcm_real.o sm/ecc.o sm/sm4.o  sm/sm3.o  sm/sm2.o \
				engine/engine.o notify/notify.o notify/ring_array.o protection/mod_protect.o \
				accessctl/accessctl.o procfs/procfs.o trust_score/trust_score.o

PWD = $(shell pwd)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
CONFIG_MODULE_SIG = n


EXTRA_CFLAGS += -I$(src)/../include


#EXTRA_CFLAGS += $(DEBUG)
EXTRA_CFLAGS += -DDEBUG
#EXTRA_CFLAGS += -DLOG_MEM
#EXTRA_CFLAGS += -DSOFT

#ifeq (${OSVERSION}, 4.19.90-17.ky10.aarch64)
#	EXTRA_CFLAGS += -DHTTC_WRITE_PROTECT_SWITCH
#else ifeq (${OSVERSION}, 4.19.90-23.15.v2101.ky10.aarch64)
#	EXTRA_CFLAGS += -DHTTC_WRITE_PROTECT_SWITCH
#endif

#TPCM
KBUILD_EXTRA_SYMBOLS =$(M)/tcsModule.symvers
KBUILD_EXTRA_SYMBOLS += $(M)/../httc_file_capture/file_capture/Module.symvers
export KBUILD_EXTRA_SYMBOLS

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
