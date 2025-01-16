SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))
TARGETS := $(patsubst %.c, %, $(SOURCES))

CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld

CFLAGS := -I../../user/include/tcsapi -g -O3 -Werror -Wl,-rpath=/usr/local/httcsec/lib
LDFLAGS := -L../../user -lhttcutils -lhttctcs -L../../user/tcm-lib/lib/ -ltcm

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
