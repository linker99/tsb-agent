#ifndef __TUTILS_H__
#define __TUTILS_H__
#include <stdint.h>

#define KEY_VERSION 0
#define NV_VERSION 1

int httc_get_replay_counter(uint64_t *replay_counter);
int is_tpcm_id_valid (const char *id);

#endif /** __TUTILS_H__ */

