#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#include "lsm_version/lsm_4.17.c"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
#include "lsm_version/lsm_4.9.c"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 8)
#include "lsm_version/lsm_4.4.c"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include "lsm_version/lsm_3.10.c"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#include "lsm_version/lsm_2.6.32.c"
#endif
