/**
****************************************************************************************
 * @FilePath: tcf_selftest.h
 * @Author: wll
 * @Date: 2023-06-19 09:57:05
 * @LastEditors: 
 * @LastEditTime: 2023-06-19 09:57:48
 * @Copyright: 2023 xxxTech CO.,LTD. All Rights Reserved.
 * @Descripttion: 
****************************************************************************************
*/
#ifndef  _TCF_SELFTEST_H_
#define  _TCF_SELFTEST_H_

#include <stdint.h>
/*固件程序自检接口*/

int tcf_tpcm_selftest (uint32_t *status);


#endif