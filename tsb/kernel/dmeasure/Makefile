#
# Makefile for dmeasure
#

CROSS_COMPILE ?=
ARCH ?=
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

obj-m := httcdmeasure.o
httcdmeasure-objs := dmeasure_integration.o \
	dmeasure/dmeasure.o dmeasure/memcmp_action.o \
	policy/policy_dmeasure.o \
	section/section.o \
	syscall/syscall.o \
	modules/modules.o \
	idt/idt.o \
	net/net.o \
	filesystem/filesystem.o \
	task/task.o task/file_hash_cache.o \
	process_identity/process_identity.o ../encryption/sm3/sm3.o \
	utils/traceability.o

PWD = $(shell pwd)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

KBUILD_EXTRA_SYMBOLS = $(M)/../platform/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(M)/../smeasure/Module.symvers
CONFIG_MODULE_SIG = n

EXTRA_CFLAGS += -I$(src)/../include
EXTRA_CFLAGS += -I$(src)/../platform




EXTRA_CFLAGS += $(LOGLEVEL)
EXTRA_CFLAGS += -DDEBUG

#ifeq ($(ARCH),csky)
#	EXTRA_CFLAGS += -Dcsky
#endif

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

