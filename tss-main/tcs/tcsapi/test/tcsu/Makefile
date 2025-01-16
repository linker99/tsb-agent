SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))
TARGETS := $(patsubst %.c, %, $(SOURCES))

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
TCF_INCLUDE ?= ../../../../tcf/include
UTILS_INCLUDE ?= ../../../../httcutils/include
CFLAGS := -I../../tcsu -I../../../common/ \
-I../../../common/user/ -I../../../tcm/lib \
-I$(UTILS_INCLUDE)/httcutils  -I$(TCF_INCLUDE)/tcsapi
 
ifndef NO_TSB
LDFLAGS := -lpthread -L../../../../httcutils -lhttcutils -L../../tcsu -lhttctcs -L../../../../tsb -lhttctsb -L../../../tcm/lib/.libs/ -ltcm
else
LDFLAGS := -lpthread -L../../../../httcutils -lhttcutils -L../../tcsu -lhttctcs -L../../../tcm/lib/.libs/ -ltcm
endif

CFLAGS += -g -O3 -Wl,-rpath=/usr/local/httcsec/lib -Werror #-fgnu89-inline-Wall -Wextra -n
CFLAGS += -DTCM_USE_TAG_IN_STRUCTURE=1
CFLAGS += -DHTTCUTILS_DEBUG

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

