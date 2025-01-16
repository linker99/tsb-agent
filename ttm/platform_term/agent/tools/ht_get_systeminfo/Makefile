ROOT := ../..
include $(ROOT)/rule.mk

TARGET := ht_get_systeminfo

$(TARGET):
	gcc ht_get_systeminfo.c -g -o $@
install:
	cp -f $(TARGET) $(TARGET_BIN_DIR)
uninstall:
	-rf -f $(TARGET_BIN_DIR)/$(TARGET)

clean:
	rm -rf *.o $(TARGET)
