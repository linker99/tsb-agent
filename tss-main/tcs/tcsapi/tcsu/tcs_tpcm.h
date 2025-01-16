#ifndef __TCS_TPCM_H__
#define __TCS_TPCM_H__

/** Reference type */
enum{
	RT_BOOT_MEASURE = 1,
	RT_WHILELIST,
};

/*
 * 文件完整度量、白名单度量
 * 将文件内容一次性输入，接口内部分段传输给TPCM处理 
 */
int tcsk_integrity_measure_easy (uint8_t *imKey, uint32_t imKeyLen, uint32_t type,
			uint8_t *data, uint32_t dataLen, uint32_t *tpcmRes, uint32_t *mrLen, uint8_t *mresult);

int tcs_flash_read (uint32_t zoon, uint32_t offset, uint32_t size, uint8_t *data, uint32_t *tpcmRes);
int tcs_flash_write (uint32_t zoon, uint32_t offset, uint32_t size, uint8_t *data, uint32_t *tpcmRes);
int tcs_flash_erase (uint32_t zoon, uint32_t offset, uint32_t size, uint32_t *tpcmRes);
int tcs_set_system_time(uint64_t nowtime, uint32_t *tpcmRes);
int tcs_get_version (uint32_t *size,uint8_t *version, uint32_t *tpcmRes);

#endif	/** __TCS_TPCM_H__ */

