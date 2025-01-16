CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

SONAME = httcutils
TARGET = lib$(SONAME).so

SRCS = $(shell find ./src -name "*.c")
OBJS = $(patsubst %.c, %.o, $(SRCS))

PWD = `pwd`

INCS := -Iinclude
#LIBS := -Bstatic ../../tcm/lib/.libs/libtcm.a
#LIBS := -L /usr/lib/httc -lhttctcf -lhttctsb -lhttctcs -ltcm
#LDFLAGS := -L ../tcs/tcsapi/tcsu -l httctcs -L../tcs/tcm/lib/.libs -ltcm
#DEFS := -DTCM_USE_TAG_IN_STRUCTURE=1

CFLAGS += -g -Wall -Werror #-fgnu89-inline
ifdef HTTCUTILS_DEBUG
CFLAGS += -DHTTCUTILS_DEBUG
endif

ifdef MEM_TEST
CFLAGS += -DMEM_TEST
LDFLAGS += -lpthread
endif 



.SUFFIXES: .c .o
.c.o:
	$(CC) $(INCS) $(DEFS) $(CFLAGS) $(LDFLAGS) -c -fPIC -o $@ $^

all: $(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $(@) $(^) -shared -fPIC $(LDFLAGS) -Wl,-soname,lib$(SONAME).so


.PHONY:clean test all 
clean:
	rm -f $(OBJS) $(TARGET) lib$(SONAME).so  $(TESTS) test/*.o 
