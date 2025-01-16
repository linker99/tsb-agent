CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

SONAME = httctcs
TARGET = lib$(SONAME).so

SRCS = $(shell find . -name "*.c")
OBJS = $(patsubst %.c, %.o, $(SRCS))

ifndef NO_TSB
MOCKTSB_SRCS = $(shell find ../../mocktsb -name "*.c")
MOCKTSB_OBJS = $(patsubst %.c, %.o, $(MOCKTSB_SRCS))
endif

PWD = `pwd`
TCF_INCLUDE ?= ../../../tcf/include
UTILS_INCLUDE ?= ../../../httcutils/include
INCS := -I. -I../../tcm/lib/ -I../../tcm/lib/crypto/openssl/ \
-I../../tcm/lib/crypto/sm/ -I../../common/ \
-I../../common/user \
-I$(UTILS_INCLUDE)/httcutils -I$(TCF_INCLUDE) -I$(TCF_INCLUDE)/tcsapi
ifndef NO_TSB
LIBS := -lpthread -L. -lhttctsb -L ../../tcm/lib/.libs -ltcm -L ../../../httcutils -lhttcutils
else
LIBS := -lpthread -L ../../tcm/lib/.libs -ltcm -L ../../../httcutils -lhttcutils
endif

DEFS := -DTCM_USE_TAG_IN_STRUCTURE=1 -g

ifdef PROJECT_CFLAGS
CFLAGS += $(PROJECT_CFLAGS)
endif

ifdef HTTCUTILS_DEBUG
CFLAGS += -DHTTCUTILS_DEBUG
endif


CFLAGS += -Wall -Werror -pthread
.SUFFIXES: .c .o
.c.o:
	$(CC) $(INCS) $(DEFS) $(CFLAGS) -c -fPIC -o $@ $^

all: $(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $(@) $(^) -shared -fPIC $(LIBS) -Wl,-rpath=/usr/local/httcsec/lib/ -Wl,-soname,lib$(SONAME).so

libhttctsb.so:$(MOCKTSB_OBJS)
	$(CC) -o $(@) $(^) -shared -fPIC

mock:libhttctsb.so

.PHONY:clean
clean:
	rm -f $(OBJS) $(TARGET) lib$(SONAME).so
	rm -f libhttctsb.so $(MOCKTSB_OBJS)
