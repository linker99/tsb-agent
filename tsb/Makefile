KERNELDIR = /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)/kernel
	
#HOOK=PATCH ZERO_USER=ON 
all:	
	$(MAKE)  DEBUG=ON ARCH=x86_64  -C $(KERNELDIR)  M=$(PWD) modules

.PHONY : all  clean 
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
