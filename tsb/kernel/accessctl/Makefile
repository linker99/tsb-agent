#
# Makefile for smeasure
#

CROSS_COMPILE ?=
ARCH ?=
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

obj-m := httcfac.o
httcfac-objs := fac.o \
		engine/ac_engine.o \
		policy/list_fac.o policy/hash_whitelist_path.o policy/regexp.o policy/regsub.o ../encryption/sm3/sm3.o

PWD = $(shell pwd)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

KBUILD_EXTRA_SYMBOLS += $(M)/../platform/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(M)/../dmeasure/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(M)/../smeasure/Module.symvers
CONFIG_MODULE_SIG = n


EXTRA_CFLAGS += -I$(src)/../include
EXTRA_CFLAGS += -I$(src)/../platform

EXTRA_CFLAGS += $(LOGLEVEL)

#EXTRA_CFLAGS += -DSANXIA_PLC

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
