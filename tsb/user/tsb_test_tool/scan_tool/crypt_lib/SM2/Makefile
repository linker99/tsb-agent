TARGET = libsm2.a

SOURCE  := $(wildcard *.c) $(wildcard *.cpp)
OBJS    := $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCE)))

all : $(TARGET)


CROSS_COMPILE ?= 
CC:= $(CROSS_COMPILE)gcc
LD:= $(CROSS_COMPILE)ld
AR:= $(CROSS_COMPLIE)ar


$(OBJS): $(SOURCE)
	$(CC) $(CXXFLAGS) $(LDFLAGS) -c $^
  
$(TARGET) : $(OBJS)
	$(AR) crs $@ $^

clean: 
	rm -rf $(out) *.o *.a *.so *~ core .depend .*.cmd *.ko *.mod.c *.unsigned *.symvers *.order .tmp_versions
