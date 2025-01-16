#ifndef __HTTC_OS_VERSION_H__
#define __HTTC_OS_VERSION_H__

#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif

#if defined(CONFIG_64BIT)
#define  INVALID_DATA_FULL_FF   0xffffffffffffffff
#else
#define  INVALID_DATA_FULL_FF   0xffffffff
#endif

#endif // __HTTC_OS_VERSION_H__
