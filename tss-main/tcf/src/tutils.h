#ifndef __TUTILS_H__
#define __TUTILS_H__
#include <stdint.h>
enum{
	LOG_VERSION,
	NOTICE_VERSION,
};

#define is_bool_value_legal(val) ((((val)==0)||((val)==1))?1:0)

int httc_get_replay_counter(uint64_t *replay_counter);
int httc_write_version_notices (uint64_t version, int type);
int httc_write_source_notices (uint32_t source, int type);
int httc_get_version(uint64_t *version,int flag);
int httc_get_file_digest(const       char *file, unsigned char *digest);
int httc_get_file_integrity_subver(uint64_t version,uint32_t *sub);


#endif /** __TUTILS_H__ */

