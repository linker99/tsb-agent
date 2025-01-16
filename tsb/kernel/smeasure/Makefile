#
# Makefile for smeasure
#

CROSS_COMPILE ?= 
ARCH ?= arm
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

EXTRA_CFLAGS += -DCHECK_SHA1

ifdef WHITE_NOT_TPCM
EXTRA_CFLAGS += -DWHITE_NOT_TPCM
endif


ifeq (${DEBUG_FLAGS},on)
	EXTRA_CFLAGS += -DHTTC_DEBUG
endif


PWD = $(shell pwd)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := httcsmeasure.o
httcsmeasure-objs :=  smeasure.o \
			engine/smeasure_engine.o engine/smeasure_wqueue.o engine/smeasure_rbtree.o protection/process_protect.o \
			policy/hash_whitelist.o policy/hash_critical_confile.o policy/policy_whitelist_cache.o policy/flush_dcache.o \
			../encryption/sm3/sm3.o \

KBUILD_EXTRA_SYMBOLS = $(M)/../platform/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(M)/../httc_file_capture/file_capture/Module.symvers
#CONFIG_MODULE_SIG = n


EXTRA_CFLAGS += -I$(src)/../include
EXTRA_CFLAGS += -I$(src)/../platform

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules 
clean: 
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean 

