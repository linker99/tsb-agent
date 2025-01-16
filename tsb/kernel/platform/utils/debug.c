#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/atomic.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "../../include/common.h"
#include "../msg/command.h"

//#include "../../include/tsbapi/tsb_admin.h"



struct tsb_user_set_log_level
{
        int type;
};


void dump_hex(void *p, int bytes)
{
	int i = 0;
	char *data = p;
	int add_newline = 1;

	if (bytes != 0) {
		printk("0x%.2x.", (unsigned char)data[i]);
		i++;
	}
	while (i < bytes) {
		printk("0x%.2x.", (unsigned char)data[i]);
		i++;
		if (i % 16 == 0) {
			printk("\n");
			add_newline = 0;
		} else
			add_newline = 1;
	}
	if (add_newline)
		printk("\n");
}
EXPORT_SYMBOL(dump_hex);
void dump_hex_string(void *p, int bytes)
{
	int i = 0;
	char *data = p;
	int add_newline = 1;

	if (bytes != 0) {
		printk("%.2x", (unsigned char)data[i]);
		i++;
	}
	while (i < bytes) {
		printk("%.2x", (unsigned char)data[i]);
		i++;
		if (i % 16 == 0) {
			printk("\n");
			add_newline = 0;
		} else
			add_newline = 1;
	}
	if (add_newline)
		printk("\n");
}
EXPORT_SYMBOL(dump_hex_string);
void dump_hex_string_for_crc32(void *p, int bytes)
{
	int i = 0;
	char *data = p;
	int add_newline = 1;
	int len = bytes - 1;
	
	if (bytes != 0) {
		printk("%.2x", (unsigned char)data[len - i]);
		i++;
	}
	while (i < bytes) {
		printk("%.2x", (unsigned char)data[len - i]);
		i++;
		if (i % 16 == 0) {
			printk("\n");
			add_newline = 0;
		} else
			add_newline = 1;
	}
	if (add_newline)
		printk("\n");
}
EXPORT_SYMBOL(dump_hex_string_for_crc32);
//#ifdef DEBUG
void httc_dump_hex (const void *p, int bytes)
{
    int i = 0;
    const unsigned char *data = p;
    int hexlen = 0;
    int chrlen = 0;
    char hexbuf[70];
    char chrbuf[20];
   
    for (i = 0; i < bytes; i ++){
		unsigned char  c = ((data[i] >> 4)& 0xf) + 0x30 ;//high (to 0123456789)
		 if(c > 0x39) c += 0x07;// (to ABCDEF);
		 hexbuf[hexlen++] = c;

		 c = (data[i] & 0xf) + 0x30 ;//high (to 0123456789)
		if(c > 0x39) c += 0x07;// (to ABCDEF);
		hexbuf[hexlen++] = c;

		c = data[i];
		if(c < 33 || c > 126)c = '.';
		chrbuf[chrlen++] = c;

		if (i % 16 == 15){
		 hexbuf[hexlen] = 0;
		 chrbuf[chrlen] = 0;
		 printk("%X: %s %s\n", (i & 0xFFFFFFF0), hexbuf, chrbuf);

		hexlen = 0;
		chrlen = 0;
	  }
    }

    if(i % 16){
     hexbuf[hexlen] = 0;
     chrbuf[chrlen] = 0;
     printk( "%X: %s %s\n", (i & 0xFFFFFFF0), hexbuf, chrbuf);
    }
}
EXPORT_SYMBOL(httc_dump_hex);
void httc_dump_hex_name(const char *name,const void *data, int len){
	printk("[DATA HEX]  %s length=%d]\n",name,len);
	httc_dump_hex(data,len);

}
EXPORT_SYMBOL(httc_dump_hex_name);

 unsigned int  LOG_MODE=1;

static long ioctl_set_log_mode(unsigned long param)
{
    long ret=0;
	 struct  tsb_user_set_log_level tsb_param; 
     	 ret =copy_from_user(&tsb_param, (void *)param, sizeof(struct tsb_user_set_log_level));
   
    if (ret)
    {
		printk("Enter:[%s:%ld], copy_from_user set log mode err!\n", __func__,ret);
    }
	LOG_MODE=tsb_param.type;
	printk("LOG_MODE:%d\r\n",LOG_MODE);
	return ret;

}
static long ioctl_get_log_mode(unsigned long param)
{
    int ret,mode;
	printk("get log mode -----\r\n");
       mode=LOG_MODE;
	ret = copy_to_user((void __user *)param, (void *)&mode, sizeof(unsigned int) );
	
    if (ret)
    {
    	printk("Enter:[%s], copy_to_user get log mode err!\n", __func__);
    }

    return ret;

   
}

int get_log_mode(void)
{
 return LOG_MODE;
}
EXPORT_SYMBOL(get_log_mode);

void set_log_mode(unsigned int  mode)
{
   LOG_MODE=mode;
}
EXPORT_SYMBOL(set_log_mode);
EXPORT_SYMBOL(LOG_MODE);



int debug_log_init(void)
{
    int ret=0;
	printk("debug log init -------\r\n");
	ret=httcsec_io_command_register(COMMAND_SET_LOG_MODE, (httcsec_io_command_func)ioctl_set_log_mode);
    if (ret)
        {
            printk("Command NR duplicated %d.\n",COMMAND_SET_LOG_MODE);
			goto out;
           
        }
		ret=httcsec_io_command_register(COMMAND_GET_LOG_MODE, (httcsec_io_command_func)ioctl_get_log_mode);
		if (ret)
        {
            printk("Command NR duplicated %d.\n",COMMAND_GET_LOG_MODE);
           
        }
	out:	
    return ret;
}

void debug_log_exit(void)
{
  httcsec_io_command_unregister(COMMAND_SET_LOG_MODE, (httcsec_io_command_func)ioctl_set_log_mode);
   httcsec_io_command_unregister(COMMAND_GET_LOG_MODE, (httcsec_io_command_func)ioctl_get_log_mode);

}


//#endif
