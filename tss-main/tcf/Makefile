CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

SONAME = httctcf
TARGET = lib$(SONAME).so

SRCS = $(shell find ./src -name "*.c")
OBJS = $(patsubst %.c, %.o, $(SRCS))

PWD = `pwd`
UTILS_INCLUDE ?= ../httcutils/include
INCS := -Iinclude  -I$(UTILS_INCLUDE) -I../tcs/tcm/lib/
LDFLAGS := -L../tcs/tcsapi/tcsu -lhttctcs -L. -lhttctsb -L../tcs/tcm/lib/.libs -ltcm -L../httcutils/ -lhttcutils -lpthread
CFLAGS += -g -Wall -Werror -Wno-format-truncation

ifdef HTTCUTILS_DEBUG
CFLAGS += -DHTTCUTILS_DEBUG
endif

#ifdef PLATFORM
#CFLAGS += -D$(PLATFORM)
#endif
ifdef PROJECT_CFLAGS
CFLAGS += $(PROJECT_CFLAGS)
endif
.SUFFIXES: .c .o
.c.o:
	$(CC) $(INCS) $(DEFS) $(CFLAGS) -c -fPIC -o $@ $^

all: $(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $(@) $(^) -shared -fPIC $(LDFLAGS) -Wl,-rpath=/usr/local/httcsec/lib/ -Wl,-soname,lib$(SONAME).so 



.PHONY:clean test all mock
clean:
	rm -f $(OBJS) $(TARGET) lib$(SONAME).so	libhttctcs.so  	libhttctsb.so  

