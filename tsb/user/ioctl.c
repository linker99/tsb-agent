#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "ioctl.h"


int httcsec_ioctl(unsigned long cmd,unsigned long param){
	int fd = open(MISC_DEV, O_RDWR);//O_RDONLY|O_NONBLOCK
	if (fd == -1) {
		return -100;
	}
	int r = 0;

	if ((r =  ioctl(fd, cmd, param)) < 0) {
#ifdef __arm__
//		LOGE("ioctl cmd %lu ,param %lu fail,%s\n",cmd,param,strerror(errno));
#else
		pr_dev("ioctl cmd %lu ,param %lu fail,%s\n",cmd,param,strerror(errno));
#endif
		close(fd);
		return -1;
	}
	close(fd);
	return r;
}

