/**
****************************************************************************************
 * @FilePath: tcs_selftest.h
 * @Author: wll
 * @Date: 2023-06-19 09:57:26
 * @LastEditors: 
 * @LastEditTime: 2023-06-19 10:18:36
 * @Copyright: 2023 xxxTech CO.,LTD. All Rights Reserved.
 * @Descripttion: 
****************************************************************************************
*/

#ifndef _TCSK_SELFTEST_H_
#define _TCSK_SELFTEST_H_
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/time.h>
#endif
/* tcs tpcm自检接口*/
int tcsk_tpcm_selftest (uint32_t *status);


#endif