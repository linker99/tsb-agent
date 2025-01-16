#ifndef __LIBCRYPT__H__
#define __LIBCRYPT__H__


int py_sm3_hash(const char *data, int data_len, char *hash);
int py_sm2_sign(const char *digest, int digest_len, char *sign);
int py_sm2_verify(const char *digest, int digest_len, const char *sign, int sign_len);


#endif // __LIBCRYPT__H__
