//#include "<asm/desc.h>"
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include "support.h"
#include "d_syscall_attack.c"



static int test_init(void){
        printk("TEST module  INIT\n");
        httc_syscall_init();
        dmeasure_test_modify_sycall_init();
        return 0;
}

static void test_exit(void){
        dmeasure_test_modify_sycall_exit();
        httc_syscall_exit();
        printk("TEST module Exit\n");
}
module_init(test_init);
module_exit(test_exit);

MODULE_AUTHOR("HTTC");
MODULE_DESCRIPTION("HTTCSEC ATTACK");
MODULE_LICENSE("Dual BSD/GPL");


