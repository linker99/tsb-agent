/**
****************************************************************************************
 * @FilePath: tcsk_tpcm_selftest_test.c
 * @Author: wll
 * @Date: 2023-06-26 15:18:16
 * @LastEditors: 
 * @LastEditTime: 2023-06-26 15:20:24
 * @Copyright: 2023 xxxTech CO.,LTD. All Rights Reserved.
 * @Descripttion: 
****************************************************************************************
*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "tdd.h"
#include "memdebug.h"
#include "kutils.h"
#include "tcsk_selftest.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_tpcm_selftest test");



static uint32_t get_error_flag(uint32_t data){

   uint32_t i=0;
   uint32_t flag=0;
   for(i=0;i<32;i++){
       flag = (data>>i)&0x1;
       if(flag==1){
            printk("ERROR :%d\n",i);
       }
   }
   return 0;
}

int tcsk_tpcm_selftest_init(void)
{
	int ret = 0;
	uint32_t status = 0;
	ret = tcsk_tpcm_selftest(&status);
	printk("ret %d\n",ret);
	if(ret!=0){
    	printk ("resut %d\n",status);
		get_error_flag(status);
	}
	return 0;
}

void tcsk_tpcm_selftest_exit(void)
{
	printk ("[%s:%d]\n", __func__, __LINE__);
}


module_init(tcsk_tpcm_selftest_init);
module_exit(tcsk_tpcm_selftest_exit);


