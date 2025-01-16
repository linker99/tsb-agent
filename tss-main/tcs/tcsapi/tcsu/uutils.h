#ifndef __TCSU_UTILS_H__
#define __TCSU_UTILS_H__
#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

#pragma pack(push, 1)
struct tpcm_data{
	int be_size;
	uint8_t value[0];
};
struct tpcm_auth{
	uint32_t be_type;
	int be_size;
	uint8_t value[0];
};
#pragma pack(pop)

int httc_insert_uid_align4 (const char *uid, void *ptr);
int httc_insert_auth_align4 (int auth_type, int auth_length,unsigned char *auth, void *ptr);
int httc_insert_data_align4 (const char *data, int size, void *ptr);
int httc_insert_data (const char *data, int size, void *ptr);
int httc_extract_uid_align4_size (void *ptr);
int httc_extract_auth_align4_size (void *ptr);

#ifdef __cplusplus
}
#endif

#endif	/** __TCSU_UTILS_H__ */


