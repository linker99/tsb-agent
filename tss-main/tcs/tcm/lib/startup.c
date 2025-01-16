/********************************************************************************/

/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <tcm.h>
#include <tcmfunc.h>
#include <tcmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tcm_types.h>
#include <tcm_constants.h>

uint32_t TCM_Startup(uint16_t type)
{
    uint32_t ret;
    uint32_t ordinal_no = htonl(TCM_ORD_Startup);
    STACK_TCM_BUFFER(tcmdata)
    uint16_t type_no = htons(type);


    /*lyf modify*/
    ret = TSS_buildbuff("00 c1 T l  s", &tcmdata,
                        ordinal_no,
                        type_no);
    if ((ret & ERR_MASK)) {
        return ret;
    }

    ret = TCM_Transmit(&tcmdata, "Startup");

    if (ret == 0 && tcmdata.used != 10) {
        ret = ERR_BAD_RESP;
    }

    return ret;
}



uint32_t TCM_Init()
{
    uint32_t ret;
    //	                   = 0xFFFFFFFF;
    uint32_t ordinal_no = htonl(TCM_ORD_Init);
    STACK_TCM_BUFFER(tcmdata);

	ret = TSS_buildbuff ("00 c1 T l ", &tcmdata, ordinal_no);
    if ((ret & ERR_MASK)) {
        return ret;
    }


//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//	system ("echo 1000 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif

    ret = TCM_Transmit(&tcmdata, "Init");

//#if defined(platform_C) || defined(platform_M) || defined(platform_2700)
//		system ("echo 500 > /sys/module/httctdd/parameters/recv_mdelay");
//#endif


    return ret;
}
