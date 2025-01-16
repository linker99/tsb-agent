SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))
TARGETS := $(patsubst %.c, %, $(SOURCES))

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
TCF_INCLUDE ?= ../../../../tcf/include
UTILS_INCLUDE ?= ../../../../httcutils/include
CFLAGS :=  -I../../tcsu \
-I$(obj)../../../common/ \
-I$(obj)../../../common/user/ \
-I$(UTILS_INCLUDE)/httcutils  -I$(TCF_INCLUDE)/tcsapi
CFLAGS += -g -O3 -Werror -Wl,-rpath=/usr/local/httcsec/lib
CFLAGS += -DHTTCUTILS_DEBUG

ifndef NO_TSB
LDFLAGS := -L../../../../httcutils -lhttcutils -L../../tcsu -lhttctcs -lhttctsb -L../../../tcm/lib/.libs/ -ltcm
else
LDFLAGS := -L../../../../httcutils -lhttcutils -L../../tcsu -lhttctcs -L../../../tcm/lib/.libs/ -ltcm
endif

ALL : $(TARGETS) #cleanobj

$(TARGETS) : %:%.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)
	
#cleanobj:
#		rm -rf $(OBJECTS)
		
.PHONY: clean
clean:
	rm -rf $(TARGETS) $(OBJECTS)
