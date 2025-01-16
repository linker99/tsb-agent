/**
****************************************************************************************
 * @FilePath: ne_err_test.c
 * @Author: wll
 * @Date: 2024-07-02 16:08:26
 * @LastEditors: 
 * @LastEditTime: 2024-07-02 16:08:26
 * @Copyright: 2024 xxxTech CO.,LTD. All Rights Reserved.
 * @Descripttion: 
****************************************************************************************
*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "tcsk_tcm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("tcsk_nv_error test");

static uint32_t index = 0;
static int size = 0;

static void usage(void)
{
	printk ("\n");
	printk (" Usage: insmod nv_err_test.ko index=INDEX size=SIZE\n");
	printk ("    eg. insmod nv_err_test.ko index=1 size=1000\n");
	printk ("\n");
}




int test_nv_definespace_rw_init(void)
{
	int ret = 0,i=10;
    char *data =NULL; 
	if (!index || !size){
		usage ();
		return -1;
	}
	if(size<20)size=20;
    if (NULL == (data = kmalloc (size+1, GFP_KERNEL))){
		printk ("Kmallc mem error.\n");
		return -1;
	}
	memset (data, 0, size + 1);
    memcpy(data,"hello world",strlen("hello world")+1);
	ret = tcsk_nv_is_definespace(index, size);
	if(ret){
	    ret = tcsk_nv_definespace (index, size);
	    if(ret){
		    printk ("Error: tcsk_nv_definespace fail! ret:0x%016x!\n", ret);
			goto OUT;
	    }
    }
	while (i--)
    {
        ret = tcsk_nv_write ((uint32_t)index, (uint8_t *)data, (uint32_t)(strlen (data) + 1));
	    if(ret){
	    	printk ("Error: tcsk_nv_write fail! ret:0x%016x!\n", ret);
			goto OUT;
	    }                      
        ret = tcsk_nv_read ((uint32_t)index, (uint8_t*)data, (uint32_t *)(&size));
	    if(ret){
	    	printk ("Error: tcsk_nv_read fail! ret:0x%016x!\n", ret);
			goto OUT;
	    }
	    printk ("Nv data: %s\n", data);
    }
OUT:
    if(data) kfree (data);
    return 0;
}

void test_nv_definespace_rw_exit(void)
{
	printk("[%s:%d]\n", __func__, __LINE__);
}

module_param(index, uint, S_IRUGO | S_IWUSR);
module_param(size, int, S_IRUGO | S_IWUSR);

module_init(test_nv_definespace_rw_init);
module_exit(test_nv_definespace_rw_exit);


