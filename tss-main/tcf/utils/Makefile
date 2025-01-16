CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
UTILS_INCLUDE ?= ../../httcutils/include
INCS := -I../include  -I$(UTILS_INCLUDE)
CFLAGS += -g -O3 -Wl,-rpath=/usr/local/httcsec/lib/ -Werror #-Wall -Wextra
CFLAGS += -DTCM_USE_TAG_IN_STRUCTURE=1
CFLAGS += -DHTTCUTILS_DEBUG
LDFLAGS := -L.. -lhttctcf -lhttctsb -lhttctcs -L../../tcs/tcm/lib/.libs -ltcm -L../../httcutils -lhttcutils

SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))
TARGETS := $(patsubst %.c, %, $(SOURCES))

ALL : $(TARGETS) #cleanobj

$(TARGETS) : %:%.o
	$(CC) $(INCS) $(CFLAGS) $^ -o $@ $(LDFLAGS)
%.o : %.c
	$(CC) $(INCS) $(CFLAGS) -c $< -o $@ $(LDFLAGS)
	
#cleanobj:
#		rm -rf $(OBJECTS)
		
.PHONY: clean
clean:
	rm -rf $(TARGETS) $(OBJECTS)

