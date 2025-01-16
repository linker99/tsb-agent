
CROSS_COMPILE ?=
CC:= $(CROSS_COMPILE)gcc -g
LD:= $(CROSS_COMPILE)ld

CFLAGS= -fPIC -DDEBUG
#CFLAGS= -fPIC -m32
#LDFLAGS = -m32
TARGETS=libhttctsb.so libhttctcs.so measuredisk
OBJECTS=ioctl.o tsb_admin.o netauth.o
all:$(TARGETS)


libhttctcs.so:mocktcs.o
	$(CC) -o $(@) $(^) -shared -fPIC
measuredisk:libhttctcs.so
measuredisk:diskinfo.o sm3.o
	$(CC) $^ -o $@  -L. -lhttctcs -Wl,-rpath=/usr/local/httcsec/lib/
libhttctsb.so:$(OBJECTS)
	$(CC) ${CFLAGS} ${LDFLAGS} -shared -o $@ $(OBJECTS)
	@echo 'Finished building target: $@'
	@echo ' '
apps:
	$(CC) notice_block.c -o notice_block -L. -lhttctsb
	$(CC) notice_noblock.c -o notice_noblock -L. -lhttctsb
	$(CC) notice_write.c -g -o notice_write -L. -lhttctsb
	$(CC) notice_set_cache.c -g -o notice_set_cache -L. -lhttctsb
	$(CC) -c sm3.c -o sm3.o -L.
	$(CC) -c diskinfo.c -o diskinfo.o -L.
#	$(CC) diskinfo.o sm3.o -o diskinfo -L.
	$(CC) process_protect.c -g -o process_protect -L. -lhttctsb
	$(CC) query_udisk.c -g -o query_udisk -L. -lhttctsb
	$(CC) reload_cdrom.c -g -o reload_cdrom -L. -lhttctsb
	$(CC) reload_udisk.c -g -o reload_udisk -L. -lhttctsb
	$(CC) mark_udisk.c -g -o mark_udisk -L. -lhttctsb
	$(CC) recover_udisk.c -g -o recover_udisk -L. -lhttctsb
	$(CC) reload_net.c -g -o reload_net -L. -lhttctsb
	$(CC) clear_net.c -g -o clear_net -L. -lhttctsb

#$(CC) diskinfo.o sm3.o -o diskinfo -L. -lhttctcf

clean:
	-$(RM) *.o $(TARGETS) $(OBJECTS) notice_block global_test notice_noblock notice_write notice_set_cache process_protect diskinfo query_udisk reload_cdrom mark_udisk reload_udisk recover_udisk reload_net clear_net
	-@echo ' '
