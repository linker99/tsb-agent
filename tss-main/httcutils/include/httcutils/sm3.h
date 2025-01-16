#ifndef _SM3_H_
#define _SM3_H_


int ht_sm3_init(void *ctx);
int ht_sm3_update(void *ctx, const unsigned char *input, int ilen);
int ht_sm3_finish(void *ctx, unsigned char *output);
//int sm3_finup(void *ctx, const unsigned char *data, int len, unsigned char *out);
//int ht_sm3_check(int ctx_size);
#endif /* _SM3_H_ */
