#include <flash.h>
#include <string.h>
#include <tpcm_sys.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <tpcm_debug.h>
#include "tpcm_constants.h"
#include "sm_util.h"
#if (TPCM_PLATFORM_BASIC == 1)
#include "tpcm_util.h"
#endif


#define FLASH_AREA 0x3100000//48M
#define FLASH_NUM 6

#define  TPCM_BLOCK_SIZE  0x1000   //4K?

#if (/*TPCM_PLATFORM_BASIC == 1*/0)

struct flash_size {
	int offset;
	int length;
	unsigned int flag;
};

struct flash_size flash_num[FLASH_NUM] = {
		[FLASH_REGIN_TPCM_DATA] = {0x400000,0x2B00000,FLASH_FLAG_WRITE_ENABLE|FLASH_FLAG_READ_ENABLE},//12M
		[FLASH_REGIN_CPU_FIRMWARE_CODE] = {0x0,0x280000,FLASH_FLAG_READ_ENABLE|FLASH_FLAG_UPGRADE_ENABLE},//0.5
		[FLASH_REGIN_BOOT_DATA] = {0x3000000,0x100000,FLASH_FLAG_WRITE_ENABLE|FLASH_FLAG_READ_ENABLE},//0.5
		[FLASH_REGIN_BOOT_CODE] = {0x280000,0x180000,FLASH_FLAG_READ_ENABLE|FLASH_FLAG_UPGRADE_ENABLE},//for flash test
		[FLASH_REGIN_TPCM_CODE] = {0x280000,0x180000,FLASH_FLAG_READ_ENABLE|FLASH_FLAG_UPGRADE_ENABLE}
};

unsigned int tpcm_sys_flash_flag(int zone)
{
	if( zone < 0 || zone > FLASH_NUM - 1 )
		return 0;
	return flash_num[zone].flag;
}

#else
struct flash_size {
	int offset;
	int length;
	int writeable;
};

struct flash_size flash_num[FLASH_NUM] = {
		[FLASH_REGIN_TPCM_DATA] = {0x400000,0x2B00000,1},//12M
		[FLASH_REGIN_CPU_FIRMWARE] = {0x0,0x280000,0},//0.5
		[FLASH_REGIN_BOOT_CONFIG] = {0x3000000,0x100000,1},//0.5
		[FLASH_REGIN_BOOT_CODE] = {0x280000,0x180000,0},//for flash test
		[FLASH_REGIN_TPCM] = {0x280000,0x180000,1},
		[FLASH_REGIN_UPDATE] = {0,0x400000,1}

};
#endif

 //wanans 2022-1017_093
 int tpcm_sys_flash_size(int zone){
	if( zone < 0 || zone > FLASH_NUM - 1 )
		return 0;
	return flash_num[zone].length;
}
 //wanans 2022-1017_097
 int tpcm_sys_flash_offset(int zone){
	if( zone < 0 || zone > FLASH_NUM - 1 )
			return 0;
	return flash_num[zone].offset;
}



#if  CONFIG_SUPPORT_FLASH_ENCRYPT

#if 0
int tpcm_sys_get_flash_key(unsigned char *key, unsigned int * key_len,unsigned char *iv, unsigned int * iv_len)
{
	unsigned char source[TPCM_SM4_KEY_LENGTH]={0x01,0x03,0x02,0x04,0x07,0x06,0x05,0x08,0x01,0x02,0x04,0x03,0x05,0x08,0x07,0x06};
	unsigned char result[32]={0};

	if ((key == NULL) || (key_len == NULL) || (iv == NULL) || (iv_len == NULL))
	{
		tpcm_error("para\n");
		return 1;
	}

	 sm3_buffer(result,source,TPCM_SM4_KEY_LENGTH);
	 *key_len = TPCM_SM4_KEY_LENGTH;
	 *iv_len = TPCM_SM4_IV_LENGTH;
	 memcpy(key,result,*key_len);
	 memcpy(iv,result+TPCM_SM4_KEY_LENGTH,*iv_len);

	 tpcm_dump("key :",key,*key_len);
	 tpcm_dump("iv :",iv,*iv);

	return (0);
}
#endif


 //wanans 2022-1015_089
 int tpcm_sys_flash_read_internal(int zone,char *buffer,int offset,int length){
//	tpcm_sys_printf("flash_read No implement\n");
	int fd, ret;
	tpcm_debug("flash_write zone=%d,offset = %x,length= %x \n", 	zone, offset, length);
	if(offset + length > flash_num[zone].length || zone < 0 || zone > FLASH_NUM - 1
		|| offset < 0 || length <= 0){
		tpcm_error("flash read param error,zone=%d,offset = %x,length= %x \n", zone, offset, length);
		return -1;
	}
	fd = open("/opt/httc_flash", O_RDONLY);
	lseek(fd, flash_num[zone].offset + offset, SEEK_SET);
	ret = read(fd, buffer, length);
	if(ret != length){
		tpcm_error("read fail\n");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}




int tpcm_sys_flash_write_internal(int zone,char *buffer,int offset,int length){
//	tpcm_sys_printf("flash_write No implement\n");
	int fd, ret, i;
	uint8_t  *buf;
	tpcm_debug("flash_write zone=%d,offset = %x,length= %x \n", 	zone, offset, length);
	if(offset + length > flash_num[zone].length || zone < 0 || zone > FLASH_NUM - 1
		|| offset < 0 || length <= 0){
		tpcm_error("flash write param error,zone=%d,offset = %x,length= %x \n",
			zone, offset, length);
		return -1;
	}
#if (/*TPCM_PLATFORM_BASIC == 1*/0)
	if(!(flash_num[zone].flag &FLASH_FLAG_WRITE_ENABLE)){
#else
	if(flash_num[zone].writeable == 0){
#endif
		tpcm_warning("Unable to write zone:%d", zone);
		return -1;
	}


	buf = tpcm_sys_malloc(length);
	if(!buf){
		tpcm_error("malloc fail\n");
		return -1;
	}

	fd = open("/opt/httc_flash", O_RDWR);
	//lseek(fd, 0, SEEK_SET);
	lseek(fd, flash_num[zone].offset + offset, SEEK_SET);
	//tpcm_sys_printf("Fileoffset 0x%x\n",flash_num[zone].offset + offset);
	ret = read(fd,(char *)buf,length);
	if(ret != length){
		tpcm_error("write flash fail\n");
		close(fd);
		tpcm_sys_free(buf);
		return -1;
	}
	//DEBUG_SHOW_HEX("Flash read in ",buf,length);
	for(i = 0;i < length; i++){
		*((uint8_t *)buffer + i) &= buf[i];
	}
	lseek(fd, flash_num[zone].offset + offset, SEEK_SET);
	//DEBUG_SHOW_HEX("Flash write out ",buffer,length);
	ret = write(fd, buffer, length);
	if(ret != length){
		tpcm_error("write flash fail\n");
		tpcm_sys_free(buf);
		close(fd);
		return -1;
	}
	tpcm_sys_free(buf);
	close(fd);
	return 0;
}

#else //#if  CONFIG_SUPPORT_FLASH_ENCRYPT

 //wanans 2022-1017_094
 int tpcm_sys_flash_read(int zone,char *buffer,int offset,int length){
//	tpcm_sys_printf("flash_read No implement\n");
	int fd, ret;
	tpcm_debug("flash_write zone=%d,offset = %x,length= %x \n", 	zone, offset, length);
	if(offset + length > flash_num[zone].length || zone < 0 || zone > FLASH_NUM - 1
		|| offset < 0 || length <= 0){
		tpcm_error("flash read param error,zone=%d,offset = %x,length= %x \n", zone, offset, length);
		return -1;
	}
	fd = open("/opt/httc_flash", O_RDONLY);
	lseek(fd, flash_num[zone].offset + offset, SEEK_SET);
	ret = read(fd, buffer, length);
	if(ret != length){
		tpcm_error("read fail\n");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}




 //wanans 2022-1017_098
 int tpcm_sys_flash_write(int zone,char *buffer,int offset,int length){
//	tpcm_sys_printf("flash_write No implement\n");
	int fd, ret, i;
	uint8_t  *buf;
	tpcm_debug("flash_write zone=%d,offset = %x,length= %x \n", 	zone, offset, length);
	if(offset + length > flash_num[zone].length || zone < 0 || zone > FLASH_NUM - 1
		|| offset < 0 || length <= 0){
		tpcm_error("flash write param error,zone=%d,offset = %x,length= %x \n", 
			zone, offset, length);
		return -1;
	}
#if (/*TPCM_PLATFORM_BASIC == 1*/0)
	if(!(flash_num[zone].flag &FLASH_FLAG_WRITE_ENABLE)){
#else
	if(flash_num[zone].writeable == 0){
#endif
		tpcm_error("Unable to write zone:%d", zone);
		return -1;
	}


	buf = tpcm_sys_malloc(length);
	if(!buf){
		tpcm_error("malloc fail\n");
		return -1;
	}

	fd = open("/opt/httc_flash", O_RDWR);
	//lseek(fd, 0, SEEK_SET);
	lseek(fd, flash_num[zone].offset + offset, SEEK_SET);
	//tpcm_sys_printf("Fileoffset 0x%x\n",flash_num[zone].offset + offset);
	ret = read(fd,(char *)buf,length);
	if(ret != length){
		tpcm_error("write flash fail\n");
		close(fd);
		tpcm_sys_free(buf);
		return -1;
	}
	//DEBUG_SHOW_HEX("Flash read in ",buf,length);
	for(i = 0;i < length; i++){
		*((uint8_t *)buffer + i) &= buf[i];		
	}	
	lseek(fd, flash_num[zone].offset + offset, SEEK_SET);
	//DEBUG_SHOW_HEX("Flash write out ",buffer,length);
	ret = write(fd, buffer, length);
	if(ret != length){
		tpcm_error("write flash fail\n");
		tpcm_sys_free(buf);
		close(fd);
		return -1;
	}
	tpcm_sys_free(buf);
	close(fd);
	return 0;
}

#endif




int tpcm_sys_flash_erase(int zone,int offset,int length){
//	tpcm_sys_printf("flash_erase No implement\n");
	int fd, ret;
	char *buff;
	tpcm_debug("flash_write zone=%d,offset = %x,length= %x \n", 	zone, offset, length);
	if(offset + length > flash_num[zone].length || zone < 0 || zone > FLASH_NUM - 1
		|| offset < 0 || length <= 0){
		tpcm_error("flash erase param error,zone=%d,offset = %x,length= %x \n",
			zone, offset, length);
		return -1;
	}
	buff = (char *)tpcm_sys_malloc(length);		
	if(!buff){
		tpcm_error("malloc fail\n");
		return -1;
	}
	memset(buff,0xff,length);
	fd = open("/opt/httc_flash", O_RDWR);
	lseek(fd, 0, SEEK_SET);
	lseek(fd, flash_num[zone].offset + offset, SEEK_SET);
	ret = write(fd, buff, length);
	if(ret != length){
		tpcm_error("erase flash fail\n");
		tpcm_sys_free(buff);
		close(fd);
		return -1;
		}
	tpcm_sys_free(buff);
	close(fd);
	return 0;
}


int tpcm_sys_flash_block_size(void)
{
   return TPCM_BLOCK_SIZE;
}


 //wanans 2022-1012_002
 int flash_init(){

	int fd;
	char *buff = NULL;
	buff = (char *)tpcm_sys_malloc(FLASH_AREA);
	if(buff == NULL){
		tpcm_error("vmalloc fail\n");
		return -1;
		}
	memset(buff,0xff,FLASH_AREA);
	fd = open("/opt/httc_flash", O_RDWR | O_CREAT, S_IRWXU);
	if(fd < 0){
		tpcm_error("open flash fail\n");
		tpcm_sys_free(buff);
		return -1;
		}
	//offset = lseek(fd, FLASH_AREA, SEEK_SET);
	//offset = lseek(fd, 0, SEEK_SET);
	lseek(fd, FLASH_AREA, SEEK_SET);
	lseek(fd, 0, SEEK_SET);
	write(fd, buff,FLASH_AREA);
	tpcm_sys_free(buff);
	close(fd);
	return 0;
}
