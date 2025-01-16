#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sm2.h"
#include "sm2_if.h"
#include "sm3.h"

static int priv2str(SM2_PRIVATE_KEY *key, unsigned char **privkey, unsigned int *len)
{
    unsigned char *p = NULL;
    unsigned int size = 0;

    size = sizeof(key->d);

    p = SM2_MALLOC(size);
    if (!p)
        return -1;

    memcpy(p, key->d, size);

    *len = size;
    *privkey = p;

    return 0;
}

static int pub2str(SM2_PUBLIC_KEY *key, unsigned char **pubkey, unsigned int *len)
{
    unsigned char *p = NULL;
    unsigned int size = 0;

    size = sizeof(key->x) + sizeof(key->y);

    p = SM2_MALLOC(size);
    if (!p)
        return -1;

    memcpy(p, key->x, sizeof(key->x));
    memcpy(p + sizeof(key->x), key->y, sizeof(key->y));

    *len = size;
    *pubkey = p;

    return 0;
}

static int sign2str(SM2_SIGNATURE *signature, unsigned char **sign, unsigned int *len)
{
    unsigned char *p = NULL;
    unsigned int size = 0;

    size = sizeof(signature->r) + sizeof(signature->s);

    p = SM2_MALLOC(size);
    if (!p)
        return -1;

    memcpy(p, signature->r, sizeof(signature->r));
    memcpy(p + sizeof(signature->r), signature->s, sizeof(signature->s));

    *len = size;
    *sign = p;
    return 0;
}

static int str2priv(unsigned char *key, SM2_PRIVATE_KEY *privkey)
{
    privkey->bits = 256;
    memcpy(privkey->d, key, sizeof(privkey->d));

    return 0;
}

static int str2pub(unsigned char *key, SM2_PUBLIC_KEY *pubkey)
{
    pubkey->bits = 256;
    memcpy(pubkey->x, key, sizeof(pubkey->x));
    memcpy(pubkey->y, key + sizeof(pubkey->x), sizeof(pubkey->y));

    return 0;
}

static int str2sign(unsigned char *sign, SM2_SIGNATURE *signature)
{
    memcpy(signature->r, sign, sizeof(signature->r));
    memcpy(signature->s, sign + sizeof(signature->r), sizeof(signature->s));

    return 0;
}

int os_sm2_generate_key(OUT unsigned char **privkey, OUT unsigned int *privkey_len,
                        OUT unsigned char **pubkey, OUT unsigned int *pubkey_len)
{
	int r = -1;
	unsigned char *priv_key = NULL;
	unsigned char *pub_key = NULL;

	if (!(priv_key = malloc (32))){
		perror ("Malloc error");
		return -1;
	}
	if (!(pub_key = malloc (64))){
		perror ("Malloc error");
		free (priv_key);
		return -1;
	}

    r = ht_sm2_generate_keypair(priv_key, privkey_len, pub_key);
	if (r){
		printf ("ht_sm2_generate_keypair error: %d\n", r);
		free (priv_key);
		free (pub_key);
		return -1;
	}

	*privkey = priv_key;
	*pubkey = pub_key;
	*pubkey_len = 64;
	return 0;
}

int os_sm2_generate_key_ex(SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey)
{
	int r = 0;
	unsigned char *privkey = NULL;
	unsigned int privkey_len = 0;
	unsigned char *pubkey = NULL;
	unsigned int pubkey_len = 0;
	r = os_sm2_generate_key (&privkey, &privkey_len, &pubkey, &pubkey_len);
	if (r){
		printf ("ht_sm2_generate_keypair error: %d\n", r);
		free (privkey);
		free (pubkey);
		return -1;
	}
	str2priv (privkey, privatekey);
	str2pub (pubkey, publickey);
	free (privkey);
	free (pubkey);
    return r;
}

int os_generate_param_z(IN unsigned char *pubkey, IN unsigned int pubkey_len,
                        IN  unsigned char *ID, IN unsigned id_len, OUT unsigned char z[32])
{
	int r = -1;
	if ((r = ht_sm3_z (ID, id_len, pubkey, z))){
		printf ("ht_sm3_z error: %d\n", r);
		return -1;
	}

	return 0;
}

int os_generate_param_e(IN unsigned char *pubkey, IN unsigned int pubkey_len,
                        IN  unsigned char *ID, IN unsigned id_len, 
                        const unsigned char *msg, unsigned int msg_len, OUT unsigned char e[32])
{
	int r = -1;
	if ((r = ht_sm3_e (ID, id_len, pubkey, msg, msg_len, e))){
		printf ("ht_sm3_e error: %d\n", r);
		return -1;
	}

	return 0;
}

#if 0
int os_sm2_sign_withz(IN const unsigned char *dgst, IN int dlen,
                      IN unsigned char *privkey, IN unsigned int privkey_len, IN unsigned char z[32],
                      OUT unsigned char **sig, OUT unsigned int *siglen)
{
    EC_GROUP *ecgroup = NULL;
    int ret = SM2_ERR_NOERR;
    SM2_PRIVATE_KEY privatekey;
    SM2_SIGNATURE signature;

    (void)privkey_len;

    memset(&privatekey, 0, sizeof(privatekey));
    memset(&signature, 0, sizeof(signature));

    ret = sm2_init_standard(&ecgroup);
    if (SM2_ERR_NOERR != ret)
        return ret;

    (void)str2priv(privkey, &privatekey);

    ret = sm2_sign(ecgroup, &privatekey, z, dgst, dlen, &signature);
    if (SM2_ERR_NOERR != ret)
        goto cleanup;

    ret = sign2str(&signature, sig, siglen);
    if (SM2_ERR_NOERR != ret)
        goto cleanup;
cleanup:
    sm2_cleanup(ecgroup);
    return ret;
}
#endif

int os_sm2_sign(IN const unsigned char *msg, IN int msglen,
                IN unsigned char *privkey, IN unsigned int privkey_len,
                unsigned char *pubkey, unsigned int pubkey_len,
                OUT unsigned char **sig, OUT unsigned int *siglen)
{
	int r = -1;
	unsigned char *signedData = NULL;

	if (!(signedData = malloc (64))){
		perror ("Malloc error");
		return -1;
	}
	if ((r = ht_sm2_sign(signedData, siglen, msg, msglen,
					SM2_USER_ID, strlen (SM2_USER_ID), privkey, privkey_len, pubkey))){
		printf ("ht_sm2_sign error: %d\n", r);
		free (signedData);
		return -1;
	}
	*sig = signedData;
    return r;
}

int os_sm2_verify(IN const unsigned char *msg, IN int msglen,
                  IN unsigned char *pubkey, IN unsigned int pubkey_len,
                  IN unsigned char *sig, IN  unsigned int siglen)
{
	int r = -1;
	if ((r = ht_sm2_verify(sig, siglen, msg, msglen,
 				SM2_USER_ID, strlen (SM2_USER_ID), pubkey, pubkey_len))){
		printf ("ht_sm2_sign error: %d\n", r);
		return -1;
	}
	return 0;
}

int os_sm2_encrypt (
    IN unsigned char *plain_text, IN unsigned int plain_text_len,
    IN unsigned char *pubkey, IN unsigned int pubkey_len,
    OUT unsigned char **cipher_text, OUT unsigned int *cipher_text_len)
{
	int r = 0;
	unsigned char *cipher = NULL;

	if (!(cipher = malloc (plain_text_len + 128))){
		perror ("Malloc error");
		return -1;
	}
	if ((r = ht_sm2_encrypt(cipher, cipher_text_len,
				  plain_text, plain_text_len, pubkey, pubkey_len))){
		printf ("ht_sm2_encrypt error: %d\n", r);
		free (cipher);
		return -1;
	}
	*cipher_text = cipher;
	return 0;
}

int os_sm2_decrypt (
    IN unsigned char *cipher_text, IN unsigned int cipher_text_len,
    IN unsigned char *prikey, IN unsigned int prikey_len,
    OUT unsigned char **plain_text, OUT unsigned int *plain_text_len)
{
	int r = -1;
	unsigned char *plain = NULL;

	if (!(plain = malloc (cipher_text_len))){
		perror ("Malloc error");
		return -1;
	}
	if ((r = ht_sm2_decrypt (plain, plain_text_len,
				   cipher_text, cipher_text_len, prikey, prikey_len))){
		printf ("ht_sm2_decrypt error: %d\n", r);
		free (plain);
		return -1;
	}
	*plain_text = plain;
	return 0;
}

void os_sm_kdf(const unsigned char *share, unsigned int sharelen, unsigned int keylen, unsigned char *outkey)
{
    sm3_context ctx;
    unsigned char dgst[SM3_DIGEST_SIZE] = {0};
    int rlen = (int)keylen;
    unsigned int ct = 1;
    unsigned char *pp = outkey;
    unsigned char str_ct[4] = {0};

    while (rlen > 0) {
        sm3_init(&ctx);
        sm3_update(&ctx, share, sharelen);
        str_ct[0] = ct >> 24;
        str_ct[1] = ct >> 16;
        str_ct[2] = ct >> 8;
        str_ct[3] = ct;
        sm3_update(&ctx, (const unsigned char *)str_ct, sizeof(unsigned int));
        sm3_finish(&ctx, dgst);
        ++ct;
        memcpy(pp, dgst, rlen >= SM3_DIGEST_SIZE ? SM3_DIGEST_SIZE : rlen);

        rlen -= SM3_DIGEST_SIZE;
        pp += SM3_DIGEST_SIZE;
    }
}

int os_sm2_dh_key(
			const unsigned char Za[SM3_DIGEST_SIZE],/** 本地个人信息摘要 */
			const unsigned char Zb[SM3_DIGEST_SIZE],/** 对方个人信息摘要 */
			const SM2_PRIVATE_KEY *prikey_static_a,	/** 本地静态密钥私钥 */
			const SM2_PUBLIC_KEY *pubkey_static_b,	/** 对方静态密钥公钥 */
			SM2_PRIVATE_KEY *prikey_temp_a,			/** 本地临时密钥私钥 */
			SM2_PUBLIC_KEY *pubkey_temp_a,			/** 本地临时密钥公钥 */
			SM2_PUBLIC_KEY *pubkey_temp_b,			/** 对方临时密钥公钥 */	
			unsigned int okeylen,					/** 协商出的密钥信息长度 */
			unsigned char *outkey,					/** 协商出的密钥信息 */
			unsigned char S1[SM3_DIGEST_SIZE],		/** 本地验证数据 */
			unsigned char SA[SM3_DIGEST_SIZE], int role)		/** 提供对方验证数据 */
{
	int r = -1;
	unsigned int len_S1;
	unsigned int len_SA;
 	r = ht_sm2_dh_key(outkey, S1, &len_S1,  SA, &len_SA, okeylen, 
                       Za, SM3_DIGEST_SIZE, Zb, SM3_DIGEST_SIZE,
                       prikey_static_a->d, 32, prikey_temp_a->d, 32,
                       NULL, pubkey_static_b->x, pubkey_temp_a->x, pubkey_temp_b->x, role);
	if (r){
		printf ("ht_sm2_dh_key error: %d\n", r);
		return -1;
	}
	return 0;
}


