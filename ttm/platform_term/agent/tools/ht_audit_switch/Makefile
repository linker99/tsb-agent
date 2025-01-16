ROOT := ../..
include $(ROOT)/rule.mk

TCF_LIB_PATH := /usr/local/httcsec/lib/
CONFIG_LIBRARY_PATH += -L${ROOT}/../depend/lib/

CONFIG_INCLUDE_PATH = -I${ROOT}/include/common/ -I$(ROOT)/include/platform

CONFIG_LIBRARY= -lm -ldl -lhttctcf -lhttctcs -lhttctsb  -lhttcutils -ltcm

WITH_RUNTIME_LIBRARY=-Wl,-rpath,'${TCF_LIB_PATH}:$$ORIGIN/../../ttm/lib/'

TARGET=ht_audit_switch
OBJECT=ht_audit_switch.o

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
