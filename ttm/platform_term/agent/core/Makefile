ROOT := ..
TCF_LIB_PATH := /usr/local/httcsec/lib/
INSTALL_PATH := ../..
include $(ROOT)/rule.mk

AGENT_INCLUDE_PATH := -I$(ROOT)/include/ -I$(ROOT)/include/core/ -I${ROOT}/include/common/ -I$(ROOT)/include/platform

AGENT_LIBRARY_PATH += -L${ROOT}/../depend/lib/

AGENT_RUNTIME_LIBRARY := -Wl,-rpath,'${TCF_LIB_PATH}:$$ORIGIN/../../ttm/lib/'

AGENT_LIBRARY := -lpthread -lm -ldl -lhttctcf -lhttctcs -lhttctsb -lhttcutils -ltcm -luuid -lsqlite3 -lcjson

TARGET=ht_agent
OBJECT= ${ROOT}/module/module_audit.o 

OBJECT += main.o agt_core.o agt_config.o agt_event.o agt_log.o \
	agt_module.o agt_timer.o agt_socket.o agt_util.o

all:$(TARGET)

$(TARGET):$(OBJECT)
	$(CC) $(OBJECT) ${AGENT_LIBRARY_PATH} $(AGENT_RUNTIME_LIBRARY) $(WITH_STATIC_LIBRARY) $(AGENT_LIBRARY) -o $@

$(OBJECT): %.o: %.c
	$(CC) -c $< -o $@ $(AGENT_INCLUDE_PATH)

clean:
	rm -f $(TARGET) $(OBJECT)

install:
	cp -f $(TARGET) $(TARGET_BIN_DIR)

uninstall:
	-rm -f $(TARGET_BIN_DIR)/$(TARGET)
