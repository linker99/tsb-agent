#ifndef HYGON_N_MODULES_SYSTEM_FLASH_FLASH_H_
#define HYGON_N_MODULES_SYSTEM_FLASH_FLASH_H_
#include <stdint.h>
#include "tpcm_config.h"


enum{
	FLASH_REGIN_CPU_FIRMWARE = 0,
	FLASH_REGIN_TPCM_DATA,
	FLASH_REGIN_BOOT_CODE,//uboot or uefi bios
	FLASH_REGIN_BOOT_CONFIG,//bios data
	FLASH_REGIN_TPCM,
	FLASH_REGIN_UPDATE,
	FLASH_REGIN_PBF_CONFIG_DATA,
	FLASH_REGIN_MAX
};
int tpcm_sys_flash_read(int zone,char *buffer,int offset,int length);
int tpcm_sys_flash_write(int zone,char *buffer,int offset,int length);
int tpcm_sys_flash_erase(int zone,int offset,int length);
int tpcm_sys_flash_write_ex(int zone,char *buffer,int offset,int length);
int tpcm_sys_flash_size(int zone);
int tpcm_sys_flash_offset(int zone);
void tpcm_sys_flash_restore_config(void);

#if CONFIG_SUPPORT_FLASH_ENCRYPT
int tpcm_sys_get_flash_key(unsigned char *key, unsigned int * key_len,unsigned char *iv, unsigned int * iv_len);
#endif
//void flash_init(void);

#endif /* HYGON_N_MODULES_SYSTEM_FLASH_FLASH_H_ */
