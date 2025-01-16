/**
****************************************************************************************
 * @FilePath: tcf_selftest.c
 * @Author: wll
 * @Date: 2023-06-19 09:57:07
 * @LastEditors: 
 * @LastEditTime: 2023-06-19 10:18:43
 * @Copyright: 2023 xxxTech CO.,LTD. All Rights Reserved.
 * @Descripttion: 
****************************************************************************************
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "tcf.h"
#include "tutils.h"
#include "httcutils/file.h"
#include "httcutils/debug.h"
#include <httcutils/convert.h>
#include "tcfapi/tcf_selftest.h"
#include "tcsapi/tcs_selftest.h"
#include "tcfapi/tcf_error.h"

/*固件程序自检接口*/

int tcf_tpcm_selftest(uint32_t *status){
	return tcs_tpcm_selftest (status);
}