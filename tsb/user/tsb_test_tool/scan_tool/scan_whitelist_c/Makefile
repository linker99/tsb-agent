TARGET  := scan_whitelist_c

#PWD = $(shell pwd)
#$(info $(PWD))

ARCH ?=
ifeq ($(ARCH), ) 
ARCH=$(shell uname -m)
endif
CROSS_COMPILE ?=
CC:= $(CROSS_COMPILE)gcc -g
LD:= $(CROSS_COMPILE)ld  
#CC      :=  gcc -Wall

$(info ARCH=$(ARCH))

CFLAGS  := -lm -lpthread -ldl

$(TARGET):
	$(CC) sm3.c whitelist.c util.c -o $@ $(CFLAGS) $(INCLUDES)

  
clean :
	rm -fr $(TARGET)
    
