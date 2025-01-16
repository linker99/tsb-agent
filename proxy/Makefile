TARGET=tpcmproxy


ifdef UNIT_TEST
DIR=src_unit_test   
else
DIR=src   
endif

OBJPATH=./obj


FILES=$(foreach dir,$(DIR),$(wildcard $(dir)/*.c))

OBJS=$(patsubst %.c,%.o,$(FILES))

INCLUDES = $(foreach i,$(DIR),-I$i)


ifeq ($(OS),Windows_NT)
RM_FILE = if exist $(1) del /q $(1)
RM_DIR = if exist $(1) rmdir /s /q $(1)
MK_DIR = mkdir
else
RM_FILE = /bin/rm -f $(1)
RM_DIR = /bin/rm -rf $(1)
MK_DIR = /bin/mkdir
endif


CFLAGS= -Wall  -fPIC -g   $(INCLUDES)   -DSYSTEM_ENDIAN_CONV



ifdef DEBUG
CFLAGS +=  -DTPCM_DEBUG=$(DEBUG)
else
CFLAGS +=  -DTPCM_DEBUG=3
endif

ifdef TPCM_PLATFORM_BASIC
CFLAGS +=  -DTPCM_PLATFORM_BASIC=$(TPCM_PLATFORM_BASIC)
endif

ifdef MEM_TEST
CFLAGS += -DMEM_TEST
endif

ifdef MACHINE
CFLAGS +=  -DMACHINE_$(MACHINE)
endif
CFLAGS += -DNEW_ARCH



LFLAGS = -pthread -lcrypto -lssl

ifdef UNIT_TEST
LFLAGS += -L/usr/local/lib/ 
endif



.phony:  all clean

all: $(TARGET) 
	@echo Generate $(TARGET)

$(TARGET): $(OBJPATH) $(OBJS)
	@echo Linking $@
	$(CC)  $(LFLAGS) -o $@ $(OBJPATH)/*.o  $(LDSUFFIX)
	@echo Done.
	

$(OBJPATH):
	$(MK_DIR) $@

$(OBJS):%.o:%.c
	$(CC) $(CFLAGS) -c -o $(OBJPATH)/$(notdir $@) $< 


clean:
	- $(call RM_DIR,$(OBJPATH))
	- $(call RM_FILE,$(TARGET))






