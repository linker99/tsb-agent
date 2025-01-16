#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>          //使用当前时钟做种子
#include <sys/time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <error.h>
#include <pthread.h>
#include <tpcm_sys.h>
#include <tpcm_debug.h>
//#include <tpcm_time.h>
#include "message.h"
extern unsigned long sharemem_addr;
#define SHARE_MAX_SIZE 0x1F00000

static pthread_mutex_t mutex;
struct mapdata{
	uint64_t addr;
	uint64_t length;
};
#if (0)
static void msleep(unsigned int miliseconds){
	usleep(miliseconds * 1000);
}
#endif
 //wanans 2022-1013_019
 static int rand_bytes(unsigned char *buffer,int length)
{
	int i;
	      //初始化随机数
    for( i = 0; i < length;i++ )                          //打印出10个随机数
    	buffer[i] = (unsigned char)(rand() & 0xff);
    return 0;
}




static struct timeval start_time;
 //wanans 2022-1012_015
 void mark_start_time(){
	//struct timeval tv;
	struct timezone tz;
	gettimeofday(&start_time , &tz);
}

#define TIME_NORMALIZE(t)  ((t).seconds += (t).millis/1000,(t).millis%=1000)

 //wanans 2022-1015_073
 static int get_time(struct tpcm_sys_time *time){
	struct timeval tv;
	struct timezone tz;
	gettimeofday (&tv , &tz);
	time->seconds = (uint32_t)(tv.tv_sec - start_time.tv_sec);
	time->millis = (uint32_t)(tv.tv_usec/1000);
	TIME_NORMALIZE(*time);
	return 0;
}
struct mem_map{
	uint64_t paddr;
	int type;
	//void *base;
	//int fd;
	unsigned mapsize;

	char base[0];
};
struct map_req{
	unsigned long paddr;
	void *buffer;
	int length;
}__attribute__((packed));

int httcsec_ioctl(unsigned long cmd,unsigned long param);
 //wanans 2022-1014_060
 static MAPObject map(uint64_t paddr,unsigned length,void **vadrr){
	struct mem_map *map;
	tpcm_debug("Map input 0x%lx,%d\n",paddr,length);
	if(paddr  <  SHARE_MAX_SIZE){
		if(paddr + length > SHARE_MAX_SIZE){
			tpcm_error("mapping out of sharemem\n");
			return 0;
		}
		map = malloc(sizeof(struct mem_map));
		if(!map){
			tpcm_error("No memory for maping\n");
			return 0;
		}
		*vadrr = (void *)(sharemem_addr +  paddr);
	//	return  (sharemem_addr +  paddr);
		map->type = 1;
		return map;
	}
	else{
		struct map_req req;
		map = malloc(sizeof(struct mem_map) + length);
		if(!map){
			tpcm_error("No memory for maping\n");
			return 0;
		}
		req.paddr = paddr;
		req.length = length;
		req.buffer = map->base;
		//ninfo.notify_sequence = cmd_sequence;

		if(!httcsec_ioctl(1,(unsigned long)&req)){
		//	tpcm_error("Map result %d\n",result);
			//debug_dump_hex(map->base,length);
			//tpcm_debug ("map Successfull!\n");
			map->type = 2;
			map->paddr = paddr;
			//map->base =(void *)map_base;
			//map->fd = fd;
			map->mapsize = length;
			tpcm_debug("Mapped kernel object %p,length=%d \n",(void *)map->base,map->mapsize);
			*vadrr = map->base;
			return map;
		}
		else{
			tpcm_error("Send fail");
			free(map);
			return 0;
		}

//		unsigned char *map_base;
//		char buffer[1024];
//		FILE *f;  int n, fd;
//		fd = open ("/dev/mem", O_RDONLY | O_SYNC);
//		if (fd == -1)    {
//			tpcm_error("open /dev/mem fail!\n");
//			free(map);
//			return 0;
//		}
//
//
//		lseek(fd, 0x47620000, SEEK_SET);
//		read(fd,buffer,1024);
//		debug_dump_hex(buffer,1024);
//		int off = paddr & 0xFFFF;
//
//		unsigned maplength = length + off;
//		if(maplength & 0xFFFF){
//			maplength = (maplength - (maplength & 0xFFFF)) + 0x10000;
//		}
//		tpcm_error("map length off= %d,maplength=%d,paddr=%lx,map_arr %lx\n",off,maplength,paddr,(paddr - off));
//		map_base =    mmap (0, maplength, PROT_READ, MAP_SHARED, fd, paddr - off);
//		if(map_base == MAP_FAILED){
//			perror("Map error\n");
//		}
//		if (map_base == 0)    {
//			tpcm_error ("NULL pointer!\n");
//			free(map);
//			close(fd);
//			return 0;
//		}
//		else {
//			tpcm_error ("map Successfull!\n");
//			map->type = 2;
//			map->base =(void *)map_base;
//			map->fd = fd;
//			map->mapsize = maplength;
//			tpcm_error("Mapped dev/mem object %p,length=%d,fd=%d \n",map->base,map->mapsize,map->fd);
//			*vadrr = (void *)(map_base + off);
//			return map;
//		}

	}
}
 //wanans 2022-1015_067
 static void unmap(MAPObject apobj){
	//int length;
	struct mem_map *map = (struct mem_map *)apobj;
	if(map->type == 1){
		tpcm_debug("Unmap share opject\n");
		free(map);
		return;
	}
	else if(map->type == 2){
		tpcm_debug("Unmap kernel opject %p,length=%d\n",(void *)map->base,map->mapsize);
		//free(map->base);
		//..munmap(map->base,map->mapsize);
		//close(map->fd);
	}
	else{
	//	tpcm_error("Unimplement unmapping out of sharemem\n");
	}
	free(map);
}

static void unmap_modified(MAPObject apobj){
	//int length;
	struct mem_map *map = (struct mem_map *)apobj;
	if(map->type == 1){
		free(map);
		tpcm_debug("Unmap share opject\n");
		return;
	}
	else if(map->type == 2){
		tpcm_debug("Unmap kernel opject %p,length=%d\n",(void *)map->base,map->mapsize);
		//free(map->base);
		//..munmap(map->base,map->mapsize);
		//close(map->fd);

		struct map_req req;
		req.paddr = map->paddr;
		req.length = map->mapsize;
		req.buffer = map->base;
		//ninfo.notify_sequence = cmd_sequence;

		if(!httcsec_ioctl(2,(unsigned long)&req)){
			tpcm_debug("Unmap modified share opject error\n");
		}
	}
	else{
		tpcm_error("Unimplement unmapping out of sharemem\n");
	}
	free(map);
}
static void  get_memory_status(uint32_t *total,uint32_t* used){
	*total = 196 * 1024 * 1024;
	*used = 5 * 1024 * 1024;
}
static uint32_t get_cpu_id(){
	return 1;
}
static void udelay(uint32_t us){
	usleep(us);
}
static void mdelay(uint32_t us){
	usleep(us*1000);
}
void dcache_cleaninv_range(void *addr, size_t size){
	
//	memcpy();//写入主机内存
	memset(addr,1,size);

}
void dcache_clean_range(void *addr, size_t size){
//	memcpy();//写入主机内存
}
void dcache_inv_range(void *addr, size_t size){
	memset(addr,1,size);
}

static pthread_mutex_t mutex;

 //wanans 2022-1012_003
 int system_init(){
//	if (pthread_mutex_init(&mutex) != 0){
//		tpcm_error(stdout, "lock error!\n");
//		return -1;
//	}
	return 0;
}
 //wanans 2022-1015_069
 static void disable_irq(uint64_t *status ){
	pthread_mutex_lock(&mutex);
}
 //wanans 2022-1015_070
 static void enable_irq(uint64_t status ){
	pthread_mutex_unlock(&mutex);
}

#ifdef MEM_TEST
static int memory_num;
static int map_num;
 //wanans 2022-1015_071
 static void * test_tpcm_malloc(size_t size){
	void  *p = NULL;
	if (size == 0)
	{
		return p;
	}

	p = malloc(size);
	if(p){
		tpcm_info("Increase memory number %d,p=%p\n",++memory_num,p);
	}
	return p;
}
static void test_tpcm_free(void *p){
	if (p)
	{
		free(p);
		tpcm_info("Decrease memory number %d,p=%p\n",--memory_num,p);
	}

}
static MAPObject test_tpcm_map(uint64_t  paddr,unsigned length,void **vadrr){
	MAPObject  p = map(paddr,length,vadrr);
	if(p){
		tpcm_info("Increase map number %d\n",++map_num);
	}
	return p;
}

static void test_tpcm_unmap(MAPObject apobj){
	unmap(apobj);
	tpcm_info("Decrease map number %d\n",--map_num);
}

static void test_tpcm_unmap_modified(MAPObject apobj){
	unmap_modified(apobj);
	tpcm_info("Decrease map number %d\n",--map_num);
}

#endif


struct tpcm_sys tpcm_sys ={

		.dcache_clean_range = dcache_clean_range,
		.dcache_cleaninv_range = dcache_cleaninv_range ,
		.dcache_inv_range =dcache_inv_range,
		.disable_irq = disable_irq,
		.enable_irq = enable_irq,
#ifdef MEM_TEST
		.free = test_tpcm_free,
		.malloc = test_tpcm_malloc,
		.map = test_tpcm_map,
		.unmap = test_tpcm_unmap,
		.unmap_modified = test_tpcm_unmap_modified,
#else
		.map = map,
		.unmap = unmap,
		.unmap_modified = unmap_modified,
		.free = free,
		.malloc = malloc,
#endif

		.get_cpu_id = get_cpu_id,
		.get_memory_status = get_memory_status,

		.mdelay = mdelay,
		.printf = (PRINT_FUNC)printf,
		.level_printf = (PRINT_FUNC_LEVEL)NULL,
		.rand = rand_bytes,
		.get_time = get_time,
		.udelay = udelay,


};
