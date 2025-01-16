#ifndef _POLICY_FAC_CACHE_H
#define _POLICY_FAC_CACHE_H

#include "sec_domain.h"

#define MAX_CACHE_NUMBER	1024
#define OBJ_NAME_LEN		512
#define HASH_STRING_LEN		OBJ_NAME_LEN + LEN_HASH

int check_policy_fac_cache(struct sec_domain *sec_p, int *result);
int set_policy_fac_cache(struct sec_domain *sec_p);
void policy_fac_cache_exit(void);
int policy_fac_cache_init(void);
void policy_fac_cache_clean(void);

#endif
