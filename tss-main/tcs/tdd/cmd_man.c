#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock_types.h>
#include <linux/atomic.h>
#include <asm/io.h>
#include "cmd_man.h"
#include "tdd_tpcm.h"
struct share_memory_area{
	int offset;
	int unit_size;
	int size;
};

#define BUFFER_AREA_NUM 10
struct share_memory_area areas[BUFFER_AREA_NUM] = {
		{0x200000,0x1000,0x200000},//4k,2m
		{0x400000,0x2000,0x200000},//8K
		{0x600000,0x4000,0x200000},//16K
		{0x800000,0x8000,0x200000},//32K
		{0xA00000,0x10000,0x200000},//64K
		{0xC00000,0x20000,0x200000},//128K
		{0xE00000,0x40000,0x200000},//256K
		{0x1000000,0x80000,0x200000},//256K
		{0x1200000,0x100000,0x400000},//1m,4m
		{0x1600000,0x200000,0x800000}//2m,8m
};
#define TPCM_BUFFER_AREA_OFFSET 	  0x200000//2M
#define TPCM_BUFFER_AREA_SIZE  	    0x1C00000//28M
#define TPCM_CMD_HEADER_AREA_OFFSET 0x1E00000//30M
#define TPCM_CMD_HEADER_AREA_SIZE  	 0x100000//1M
#define TPCM_SHARE_MEMORY_SIZE 		0x1F00000//31M

#define CMD_BUFFER_NUMBER (TPCM_CMD_HEADER_AREA_SIZE/sizeof(struct cmd_header ))

void *sharemem_base;
struct cmd_header * cmd_header_base;
struct share_memory * share_memory_base;
void * data_buffer_base;
void * data_buffer_end;
short cmd_headers[CMD_BUFFER_NUMBER];
short buffer_next[BUFFER_AREA_NUM];
//void *data_buffer_base[BUFFER_AREA_NUM];
short *buffer_head[BUFFER_AREA_NUM];

int cmd_next = CMD_BUFFER_NUMBER - 1;

static DEFINE_SPINLOCK(buffer_lock);


int shm_init(void){
	int i,j;
	int num,r,ret;
	//sharemem_base = ioremap_nocache(
	//		(unsigned long)TPCM_SHARE_BUFFER, (unsigned long)TPCM_SHARE_MEMORY_SIZE);
	sharemem_base = vmalloc(TPCM_SHARE_MEMORY_SIZE);
	if (!sharemem_base){
		ret = -ENOMEM;
		return ret;
	}
	share_memory_base = sharemem_base;
	cmd_header_base = sharemem_base + TPCM_CMD_HEADER_AREA_OFFSET;
	data_buffer_base = sharemem_base + TPCM_BUFFER_AREA_OFFSET;
	data_buffer_end = data_buffer_base + TPCM_BUFFER_AREA_SIZE;
	//huge_data_buffer_base = sharemem_base + TPCM_HUGE_DATA_BUFFER_OFFSET;
	//huge_data_buffer_end = sharemem_base + TPCM_HUGE_DATA_BUFFER_END ;
	printk("Share memory base = 0x%lx,Command memory base = 0x%lx\n"
			,(unsigned long)sharemem_base,(unsigned long)cmd_header_base);
	printk("data_buffer_base = 0x%lx,data_buffer_end= 0x%lx\n",
			(unsigned long)data_buffer_base,(unsigned long)data_buffer_end);
	if( sharemem_base == 0 )return -1;
	for(i=0;i<CMD_BUFFER_NUMBER;i++){
		cmd_headers[i] = i - 1;
	}

	for(i=0;i<BUFFER_AREA_NUM;i++){

		num =  areas[i].size/areas[i].unit_size;
		buffer_next[i] = num -1;
		buffer_head[i] = kmalloc(num * sizeof(short),GFP_KERNEL);
		if(!buffer_head[i]){
			printk("No memory for share memory management\n");
			r = -1;
			goto error;
		}
		for(j=0;j<num;j++){
			buffer_head[i][j] = j - 1;
		}
	}
	return 0;
error:
	for(i=0;i<BUFFER_AREA_NUM;i++){
		if(buffer_head[i])kfree(buffer_head[i]);
	}
	return -1;

}

void shm_exit(void){
	int i;
	for(i=0;i<BUFFER_AREA_NUM;i++){
		kfree(buffer_head[i]);
	}
	vfree(sharemem_base);
	return;
}


int tdd_free_cmd_header(struct cmd_header * header){
	int index;
	int r = 0;
	index = ((unsigned long)header - (unsigned long)cmd_header_base)/sizeof(struct cmd_header);
	if(index < 0 || index >= CMD_BUFFER_NUMBER){
		printk("[%s:%d] hter command header address %p\n",__func__, __LINE__,header);
		return -1;
	}
	spin_lock(&buffer_lock);
	if(cmd_headers[index] != -2){
		printk("Duplicated Free command header at index %d\n",index);
		r = -1;
	}
	else{
#ifdef __DEBUG__
		printk("Free command header at index %d\n",index);
#endif
		cmd_headers[index] = cmd_next;
		cmd_next = index;
	}
	spin_unlock(&buffer_lock);
	return r;
}
EXPORT_SYMBOL_GPL(tdd_free_cmd_header);

struct cmd_header *tdd_alloc_cmd_header(void ){
	int index;
	struct cmd_header *cmd = 0;
	spin_lock(&buffer_lock);
	if(cmd_next != -1){
		index = cmd_next;
		cmd_next = cmd_headers[index];
		cmd_headers[index] = -2;//set to in use
#ifdef __DEBUG__
		printk("Get command at index %d\n",index);
#endif
		cmd =  cmd_header_base + index;
	}
	spin_unlock(&buffer_lock);
	return cmd;
}
EXPORT_SYMBOL_GPL(tdd_alloc_cmd_header);

unsigned long tdd_get_phys_addr(void *buffer){
	if(buffer >= sharemem_base + TPCM_SHARE_MEMORY_SIZE
		|| buffer < sharemem_base)
	{
		return (unsigned long)buffer;
	}
//	printk("----tdd_get_phys_addr: %d---\n", buffer - sharemem_base);
	return buffer - sharemem_base;//返回buffer - sharemem_base
}
EXPORT_SYMBOL_GPL(tdd_get_phys_addr);



static inline int get_area_point(void *buffer){
	int i;
	for(i = 0 ; i< BUFFER_AREA_NUM -1  ;i++){
		if(buffer < sharemem_base + areas[i + 1].offset){
			break;
		}
	}

	return i;
}

int tdd_free_data_buffer(void *buffer){
	int area,diff,index,r = 0;
	if(buffer >= data_buffer_end){
		printk("[%s:%d]Free data buffer  hter 1 %p\n",__func__, __LINE__,buffer);
		return -1;
	}
	if(buffer < data_buffer_base){
		printk("[%s:%d]Free data buffer   hter 2 %p,data_buffer_base=%p\n",__func__, __LINE__,buffer,data_buffer_base);
		return -1;
	}
	area  = get_area_point(buffer);
	diff = buffer -(sharemem_base + areas[area].offset);
	if(diff % areas[area].unit_size){
		printk("[%s:%d]Free  data align  hter , area = %d,address =  %p\n",__func__, __LINE__,area,buffer);
		return -1;
	}
	index = diff/areas[area].unit_size;

	spin_lock(&buffer_lock);
	if(buffer_head[area][index] != -2){
		printk("Duplicated freee data buffer at area %d, index %d\n",area,index);
		r = -1;
	}
	else{
#ifdef __DEBUG__
		printk("Free data buffer at area %d, index %d\n",area,index);
#endif
		buffer_head[area][index] = buffer_next[area];
		buffer_next[area] = index;
	}
	spin_unlock(&buffer_lock);

	return r;
}
EXPORT_SYMBOL_GPL(tdd_free_data_buffer);

static inline int get_area(int size){
	int i;
	for(i = 0 ; i< BUFFER_AREA_NUM -1  ;i++){
		if(size <= areas[i].unit_size){
			break;
		}
	}
	return i;
}



void  *tdd_alloc_data_buffer(unsigned int size){
	int area,index;
	void *buf = 0;
	if(size == 0 || size > areas[BUFFER_AREA_NUM - 1].unit_size){
		return 0;
	}
	area = get_area(size);
	spin_lock(&buffer_lock);
#ifdef __DEBUG__
	printk("Try to Alloc size = %x,area = %d\n",size,area);
#endif
	for(;area < BUFFER_AREA_NUM ;area++){
		if(buffer_next[area] != -1){
			index = buffer_next[area];
			buffer_next[area] = buffer_head[area][index];
			buffer_head[area][index] = -2;//set to in use
#ifdef __DEBUG__
			printk("Get Buffer size=%x,at  area %d,index %d\n",size,area,index);
#endif
			buf = sharemem_base  + areas[area].offset
					+ index * areas[area].unit_size;
#ifdef __DEBUG__
			printk("Get buf = %p\n",buf);
#endif
			break;
		}
	}
	spin_unlock(&buffer_lock);
	return buf;
}
EXPORT_SYMBOL_GPL(tdd_alloc_data_buffer);

void *tdd_alloc_data_buffer_api(unsigned int size)
{
    return tdd_alloc_data_buffer (size);
}
EXPORT_SYMBOL_GPL(tdd_alloc_data_buffer_api);








