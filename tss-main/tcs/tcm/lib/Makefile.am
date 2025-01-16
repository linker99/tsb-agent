
AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libtcm.la

INCLUDES = -I.

AM_CFLAGS = -pthread -ggdb -Wuninitialized -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -W #-Werror
AM_LDFLAGS = -pthread -lpthread @LIBTCMS_LIBRARY_PATH@ @LIBTCMS_LIBRARY@ 

sm_headers = crypto/sm/sm2_if.h  crypto/sm/sm3.h  crypto/sm/sm4.h
sm_sources = crypto/sm/ecc.c crypto/sm/sm2.c crypto/sm/sm2_if.c  crypto/sm/sm3.c  crypto/sm/sm4.c

include_HEADERS = $(sm_headers)\
	tcmfunc.h \
	tcm.h \
	tcmkeys.h \
	tcm_constants.h \
	tcm_error.h \
	tcm_structures.h \
	tcmutil.h \
	tcm_types.h \
	tcm_lowlevel.h \
	oiaposap.h \
	tcm_sizedbuffer.h \
	tcm_memory.h \
	tcm_key.h \
	tcm_store.h \
	tcm_load.h \
	cJSON.h \
	cJSON_Utils.h \
	util.h 

libtcm_la_SOURCES = $(sm_sources)\
	auditing.c bind.c chgauth.c \
	debug.c\
	eviction.c hmac.c identity.c keys.c keyswap.c \
	migrate.c miscfunc.c nv.c \
	oiaposap.c optin.c owner.c activatepek.c\
	pcrs.c rng.c seal.c serialize.c session.c \
	signature.c startup.c \
	tcmutil.c tcmutil_sock.c tcmutil_netlink.c tcmutil_dev.c tcmutil_tty.c tcmutil_unixio.c \
	tcmutil_libtpms.c  tcm_key.c tcm_store.c \
	transport.c  tcm_sizedbuffer.c tcm_memory.c tcm_load.c\
	cJSON.c cJSON_Utils.c

EXTRA_DIST = hmac.h oiaposap.h pcrs.h tcmutil.h
