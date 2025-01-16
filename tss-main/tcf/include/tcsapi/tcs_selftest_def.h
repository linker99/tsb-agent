/**
****************************************************************************************
 * @FilePath: tcs_selftest_def.h
 * @Author: wll
 * @Date: 2023-06-19 10:00:26
 * @LastEditors: 
 * @LastEditTime: 2023-06-19 10:23:24
 * @Copyright: 2023 xxxTech CO.,LTD. All Rights Reserved.
 * @Descripttion: 
****************************************************************************************
*/
#ifndef _TCS_SELFTEST_DEF_H_
#define _TCS_SELFTEST_DEF_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "mem.h"
#include "sys.h"
#include "file.h"
#include "debug.h"
#include "convert.h"
#include "transmit.h"
#include "tpcm_command.h"
#include "tcs_config.h"
#include "tcs_attest.h"
#include "tcs_error.h"
#include "tutils.h"

#pragma pack(push, 1)

typedef struct {
	RESPONSE_HEADER;
	uint32_t status;
}tpcm_selftest_rsp_st;

#pragma pack(pop)


#endif
