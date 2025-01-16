ROOT := ../..
include $(ROOT)/rule.mk

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
TOP_PATH = $(shell pwd)


INCS := -I$(TOP_PATH)/include/ 

CFLAGS = -Wl,-rpath=/usr/local/httcsec/lib
#CFLAGS += -g -DTCM_USE_TAG_IN_STRUCTURE=1
#LDFLAGS := -L$(TOP_PATH)/../tss/user/  -lhttctsb 
LDFLAGS := -L$(TOP_PATH)/ -lhttctsb 


#SUBDIR=$(shell ls -d */)
#SOURCES=$(shell find $(SUBDIR) -name '*.c')
SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))
TARGETS := $(patsubst %.c, %, $(SOURCES))

ALL : $(TARGETS) #cleanobj

$(TARGETS) : %:%.o
	$(CC) $(INCS) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lm
%.o : %.c
	$(CC) $(INCS) $(CFLAGS) -c $< -o $@ $(LDFLAGS) -lm
	
#cleanobj:
#		rm -rf $(OBJECTS)
		
.PHONY: clean
clean:
	rm -rf $(TARGETS) $(OBJECTS)

install:
	cp -f $(TARGETS) $(TARGET_BIN_DIR)
uninstall:
	rm -f $(TARGET_BIN_DIR)/log_set_level

