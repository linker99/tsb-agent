

#ifndef IOCTL_H_
#define IOCTL_H_
#include <sys/ioctl.h>
#include <errno.h>
#include "debug.h"
#ifdef __cplusplus
extern "C" {
#endif

#define MISC_DEV "/dev/httcsec"

#define HTTCSEC_MISC_DEVICE_TYPE  0xAF
#define HTTC_IO_COMMAND(cmd)  _IO(HTTCSEC_MISC_DEVICE_TYPE,(cmd))

int  httcsec_ioctl(unsigned long cmd,unsigned long param);

#ifdef __cplusplus
}
#endif

#endif /* IOCTL_H_ */
