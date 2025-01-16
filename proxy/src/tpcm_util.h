#ifndef MODULES_BASEPLATFORM_TPCM_UTIL_H_
#define MODULES_BASEPLATFORM_TPCM_UTIL_H_



#define BIT(nr)			(1UL << (nr))


void policy_sm3( uint8_t *input, int ilen,uint8_t *hash);


#endif /* MODULES_BASEPLATFORM_TPCM_UTIL_H_ */
