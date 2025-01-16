MAKE = make
SM2LIBDIRS = ./SM2
SM3LIBDIRS = ./SM3
TARGET := sign
LIBTARGET := libcrypt.so

INCLUDE := -I./SM2 -I./SM3

CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

ARCH ?= x86_64
CFLAGS :=
EXCFLAGS := -D$(ARCH)
LDFLAGS += -L$(SM2LIBDIRS) -lsm2 -L$(SM3LIBDIRS) -lsm3

all:
	$(MAKE) -C $(SM2LIBDIRS) all
	$(MAKE) -C $(SM3LIBDIRS) all
	$(CC) main.c $(CFLAGS) $(EXCFLAGS) $(LDFLAGS) $(INCLUDE) -o $(TARGET)

lib:
	$(CC) -o $(LIBTARGET) -shared -Wall -fPIC pymain.c $(SM2LIBDIRS)/*.c $(SM3LIBDIRS)/*.c $(CFLAGS) $(INCLUDE) $(EXCFLAGS)


clean:
	rm -f *.o $(TARGET) *.so
	$(MAKE) -C $(SM2LIBDIRS) clean
	$(MAKE) -C $(SM3LIBDIRS) clean
