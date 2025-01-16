DEBUG=n
DEBUG_STACK=n
DEBUG_MSG=y


AGENT_WNO_FLAGS=-Wno-misleading-indentation -Wno-unused-function -Wno-pointer-sign

ifeq ($(DEBUG), y)
	CFLAGS=-Wall $(AGENT_WNO_FLAGS) -g -DDEBUG -rdynamic
else
	CFLAGS=-g -O0 -Wall $(AGENT_WNO_FLAGS)
endif

ifeq ($(DEBUG_STACK), y)
	CFLAGS+=-fsanitize=address -fstack-protector-all
endif

ifeq ($(DEBUG_MSG), y)
	ZDNS_AM_BUILD_INFO+=-DWITH_RUNNING_MSG
endif

AGENT_INCLUDE_INFO := -I.

#-Wunused-parameter
# packet capture driver pcap/pfring

CC=gcc $(CFLAGS) $(AGENT_BUILD_INFO)
AR=ar rcsu
CPP=g++ $(CFLAGS) $(AGENT_BUILD_INFO)

AM_LIBRARY=-lpthread -lm
WITH_STATIC_LIBRARY=${ROOT}/common/libcommon.a

TARGET_DIR=${ROOT}/../build/ttm
TARGET_BIN_DIR=${TARGET_DIR}/bin
TARGET_LIB_DIR=${TARGET_DIR}/lib
