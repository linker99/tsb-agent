ROOT := ..
include $(ROOT)/rule.mk

AGENT_INCLUDE_PATH += -I. -I${ROOT}/include/common -I${ROOT}/include/platform

TARGET=libcommon.a
OBJECT= ht_util.o ht_string.o ht_mem.o ht_crypt.o rbtree.o ht_error.o

all:$(TARGET)

$(TARGET):$(OBJECT)
	ar -r $@ $(OBJECT)

$(OBJECT): %.o: %.c
	$(CC) -c -fPIC $< $(AGENT_INCLUDE_PATH) -o $@

clean:
	rm -f $(TARGET) $(OBJECT)
#	rm -f $(TARGET_LIB_DIR)/$(OTHER_DEPEND)

install:
	-cp -f $(OTHER_DEPEND) $(TARGET_LIB_DIR)
	-cp -f $(TARGET) $(TARGET_LIB_DIR)

uninstall:
	-rm -f $(TARGET_LIB_DIR)/$(TARGET)
