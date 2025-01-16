#ifndef _SM_IF_H_
#define _SM_IF_H_

#include <linux/fs.h>

#define IN
#define OUT
#define IO

/* sm2 interface */

int os_sm2_generate_key(OUT unsigned char **privkey, OUT unsigned int *privkey_len,
                                                OUT unsigned char **pubkey, OUT unsigned int *pubkey_len);

int generate_param_z(IN unsigned char *pubkey, IN unsigned int pubkey_len,
						IN  unsigned char *ID,IN unsigned id_len,OUT unsigned char z[32]);

int os_sm2_sign_withz(IN const unsigned char *dgst, IN int dlen,
                                IN unsigned char *privkey, IN unsigned int privkey_len,IN unsigned char z[32],
                                OUT unsigned char **sig, OUT unsigned int *siglen);

int os_sm2_sign(IN const unsigned char *dgst, IN int dlen,
		IN unsigned char *privkey, IN unsigned int privkey_len,
		unsigned char *pubkey, unsigned int pubkey_len,
		OUT unsigned char **sig, OUT unsigned int *siglen);

int os_sm2_verify(IN const unsigned char *dgst, IN int real_len,
		IN unsigned char *pubkey, IN unsigned int pubkey_len,
		IN unsigned char *sig, IN  unsigned int siglen);
#ifdef __KERNEL__ 
//SM2-FILE-START
int os_sm2_verify_file(IN struct file *file,IN int signlength, IN int exlen,
                                IN unsigned char *pubkey, IN unsigned int pubkey_len,
                                IN unsigned char *sig, IN  unsigned int siglen,IN unsigned char *ID,IN unsigned id_len);
//SM2-FILE-END
#else
int os_sm2_verify_file(IN char *path,IN int signlength, IN int exlen,
                                IN unsigned char *pubkey, IN unsigned int pubkey_len,
                                IN unsigned char *sig, IN  unsigned int siglen,IN unsigned char *ID,IN unsigned id_len);
#endif

int os_sm2_encrypt_pubkey(IN unsigned char *plain_text,IN unsigned int plain_text_len,IN unsigned char *pubkey,unsigned int pubkey_len,OUT unsigned char **cipher_text,unsigned int *cipher_text_len);

int os_sm2_decrypt_prikey(IN unsigned char *cipher_text,IN unsigned int cipher_text_len,IN unsigned char *prikey,unsigned int prikey_len,OUT unsigned char **plain_text,unsigned int *plain_text_len);

void os_mem_free(unsigned char **pmem);

void os_sm_kdf (unsigned char *outkey, unsigned int keylen, const unsigned char *share, unsigned int sharelen);


#endif
