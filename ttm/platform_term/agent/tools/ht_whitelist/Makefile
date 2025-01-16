ROOT := ../..
include $(ROOT)/rule.mk

TCF_LIB_PATH := /usr/local/httcsec/lib/
CONFIG_LIBRARY_PATH += -L${ROOT}/../depend/lib/
CONFIG_LIBRARY_PATH += -L/usr/lib/x86_64-linux-gnu/

CONFIG_INCLUDE_PATH = -I${ROOT}/include/common/ -I$(ROOT)/include/platform

CONFIG_LIBRARY= -lm -ldl -luuid -lpthread -lhttctcf -lhttctcs -lhttctsb -lhttcutils -ltcm -lsqlite3 -lcjson

WITH_RUNTIME_LIBRARY=-Wl,-rpath,'${TCF_LIB_PATH}:$$ORIGIN/../../ttm/lib/'

TARGET=ht_whitelist
OBJECT=ht_whitelist.o set_global_control_policy.o ht_io_file.o tools_log.o

$(TARGET):$(OBJECT)
	$(CC) $(OBJECT) $(CONFIG_LIBRARY) $(CONFIG_LIBRARY_PATH) $(WITH_RUNTIME_LIBRARY) $(WITH_STATIC_LIBRARY) -o $@

$(OBJECT): %.o: %.c
	$(CC) -c $< -o $@ $(CONFIG_INCLUDE_PATH)

clean:
	rm -f $(TARGET) $(OBJECT)

install:
	cp -f $(TARGET) $(TARGET_BIN_DIR)

uninstall:
	 -rm -f $(TARGET_BIN_DIR)/$(TARGET)
