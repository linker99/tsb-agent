
#include "sm_if.h"
#include "sm2.h"
#include <string.h>

/* sm2 interface */

static int priv2str(SM2_PRIVATE_KEY *key, unsigned char **privkey, unsigned int *len)
{
	unsigned char *p = NULL;
	unsigned int size = 0;

	size = sizeof(key->d);

	p = SM2_MALLOC(size);
	if (!p)
		return SM2_ERR_MALLOC_FAILED;

	memcpy(p, key->d, size);

	*len = size;
	*privkey = p;

	return SM2_ERR_NOERR;
}

static int pub2str(SM2_PUBLIC_KEY *key, unsigned char **pubkey, unsigned int *len)
{
	unsigned char *p = NULL;
	unsigned int size = 0;

	size = sizeof(key->x) + sizeof(key->y);

	p = SM2_MALLOC(size);
	if (!p)
		return SM2_ERR_MALLOC_FAILED;        

	memcpy(p, key->x, sizeof(key->x));
	memcpy(p+sizeof(key->x), key->y, sizeof(key->y));

	*len = size;
	*pubkey = p;

	return SM2_ERR_NOERR;
}

static int sign2str(SM2_SIGNATURE *signature, unsigned char **sign, unsigned int *len)
{
	unsigned char *p = NULL;
	unsigned int size = 0;

	size = sizeof(signature->r) + sizeof(signature->s);

	p = SM2_MALLOC(size);
	if (!p)
		return SM2_ERR_MALLOC_FAILED;

	memcpy(p, signature->r, sizeof(signature->r));
	memcpy(p+sizeof(signature->r), signature->s, sizeof(signature->s));

	*len = size;
	*sign = p;
	return SM2_ERR_NOERR;
}

static int str2priv(unsigned char *key, SM2_PRIVATE_KEY *privkey)
{
	privkey->bits = 256;
	memcpy(privkey->d, key, sizeof(privkey->d));

	return SM2_ERR_NOERR;
}

static int str2pub(unsigned char *key, SM2_PUBLIC_KEY *pubkey)
{
	pubkey->bits = 256;
	memcpy(pubkey->x, key, sizeof(pubkey->x));
	memcpy(pubkey->y, key+sizeof(pubkey->x), sizeof(pubkey->y));

	return SM2_ERR_NOERR;
}

static int str2sign(unsigned char *sign, SM2_SIGNATURE *signature)
{
	memcpy(signature->r, sign, sizeof(signature->r));
	memcpy(signature->s, sign+sizeof(signature->r), sizeof(signature->s));

	return SM2_ERR_NOERR;
}

int os_sm2_generate_key(OUT unsigned char **privkey, OUT unsigned int *privkey_len,
		OUT unsigned char **pubkey, OUT unsigned int *pubkey_len)
{
	SM2_PRIVATE_KEY privatekey;
	SM2_PUBLIC_KEY publickey;
	EC_GROUP *ecgroup = NULL;
	int ret = SM2_ERR_NOERR;

	memset(&privatekey, 0, sizeof(privatekey));
	memset(&publickey, 0, sizeof(publickey));

	ret = sm2_init_standard(&ecgroup);
	if (SM2_ERR_NOERR != ret)
		return ret;

	ret = sm2_gen_keypair(ecgroup, &privatekey, &publickey);
	if (SM2_ERR_NOERR != ret)
		goto cleanup;

	ret = priv2str(&privatekey, privkey, privkey_len);
	if (SM2_ERR_NOERR != ret) {
		goto cleanup;
	}

	ret = pub2str(&publickey, pubkey, pubkey_len);
	if (SM2_ERR_NOERR != ret) {
		goto cleanup;
	}

cleanup:
	sm2_cleanup(ecgroup);
	return ret;
}

int generate_param_z(IN unsigned char *pubkey, IN unsigned int pubkey_len,
						IN  unsigned char *ID,IN unsigned id_len,OUT unsigned char z[32])
{
	EC_GROUP *ecgroup = NULL;
	int ret = SM2_ERR_NOERR;
	SM2_PUBLIC_KEY publickey;

	memset(&publickey, 0, sizeof(publickey));
	ret = sm2_init_standard(&ecgroup);

	if (SM2_ERR_NOERR != ret)
		return ret;

	(void)str2pub(pubkey, &publickey);
	ret = sm2_Z(ecgroup, ID, id_len*8, &publickey, z);

	return ret;
}

int os_sm2_sign_withz(IN const unsigned char *dgst, IN int dlen,
		IN unsigned char *privkey, IN unsigned int privkey_len,IN unsigned char z[32],
		OUT unsigned char **sig, OUT unsigned int *siglen)
{
	EC_GROUP *ecgroup = NULL;
	int ret = SM2_ERR_NOERR;
	//unsigned char Z[SM3_DIGEST_SIZE] = {0};
	SM2_PRIVATE_KEY privatekey;
	SM2_SIGNATURE signature;

	(void)privkey_len;

	memset(&privatekey, 0, sizeof(privatekey));
	memset(&signature, 0, sizeof(signature));
	//memset(Z, 0, SM3_DIGEST_SIZE);

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



int os_sm2_sign(IN const unsigned char *dgst, IN int dlen,
		IN unsigned char *privkey, IN unsigned int privkey_len,
		unsigned char *pubkey, unsigned int pubkey_len,
		OUT unsigned char **sig, OUT unsigned int *siglen)
{
	EC_GROUP *ecgroup = NULL;
	int ret = SM2_ERR_NOERR;
	unsigned char Z[SM3_DIGEST_SIZE] = {0};	
	unsigned char ID[128]="abc";
	SM2_PRIVATE_KEY privatekey;
	SM2_PUBLIC_KEY publickey;
	SM2_SIGNATURE signature;

	(void)privkey_len;

	memset(&privatekey, 0, sizeof(privatekey));
	memset(&publickey, 0, sizeof(publickey));
	memset(&signature, 0, sizeof(signature));
	memset(Z, 0, SM3_DIGEST_SIZE);

	ret = sm2_init_standard(&ecgroup);
	if (SM2_ERR_NOERR != ret)
		return ret;
	(void)str2pub(pubkey, &publickey);
	(void)str2priv(privkey, &privatekey);	
	ret = sm2_Z(ecgroup, ID, 3*8, &publickey, Z);
	ret = sm2_sign(ecgroup, &privatekey, Z, dgst, dlen, &signature);
	if (SM2_ERR_NOERR != ret)
		goto cleanup;

	ret = sign2str(&signature, sig, siglen);
	if (SM2_ERR_NOERR != ret)
		goto cleanup;
cleanup:
	sm2_cleanup(ecgroup);
	return ret;
}

int os_sm2_verify(IN const unsigned char *dgst, IN int real_len,
		IN unsigned char *pubkey, IN unsigned int pubkey_len,
		IN unsigned char *sig, IN  unsigned int siglen)
{
	EC_GROUP *ecgroup = NULL;
	int ret = SM2_ERR_NOERR;
	unsigned char Z[SM3_DIGEST_SIZE] = {0};
	unsigned char ID[128]="abc";
	SM2_PUBLIC_KEY publickey;
	SM2_SIGNATURE signature;
	
	(void)pubkey_len;
	(void)siglen;

	memset(Z, 0, SM3_DIGEST_SIZE);
	memset(&publickey, 0, sizeof(publickey));
	memset(&signature, 0, sizeof(signature));

	ret = sm2_init_standard(&ecgroup);
	if (SM2_ERR_NOERR != ret)
		return ret;

	(void)str2pub(pubkey, &publickey);
	(void)str2sign(sig, &signature);
	ret = sm2_Z(ecgroup, ID, 3*8, &publickey, Z);

	ret = sm2_verify(ecgroup, &publickey, Z, dgst, real_len, &signature);
	if (SM2_ERR_NOERR != ret)
		goto cleanup;

cleanup:
	sm2_cleanup(ecgroup);
	return ret;
}

int os_sm2_encrypt_pubkey(IN unsigned char *plain_text,IN unsigned int plain_text_len,IN unsigned char *pubkey,unsigned int pubkey_len,OUT unsigned char **cipher_text,unsigned int *cipher_text_len)
{
	int ret = SM2_ERR_NOERR;
	SM2_PUBLIC_KEY publickey = {0};
	EC_GROUP *ecgroup = NULL;
	unsigned char *ciphered = NULL;
	int olen = 0;

	(void)str2pub(pubkey, &publickey);
	ret = sm2_init_standard(&ecgroup);
	if (SM2_ERR_NOERR != ret)
		return ret;
	ret = sm2_encrypt(ecgroup, &publickey, plain_text, plain_text_len, NULL, &olen);
	if (SM2_ERR_NOERR != ret)
		goto cleanup;
	ciphered = (unsigned char *)SM2_MALLOC(olen);
	ret = sm2_encrypt(ecgroup, &publickey, plain_text, plain_text_len, ciphered, &olen);
	if (SM2_ERR_NOERR != ret)
		goto cleanup;
	(*cipher_text) = ciphered;
	(*cipher_text_len) = (unsigned int)olen;
cleanup:
	sm2_cleanup(ecgroup);
	//if (ciphered) free(ciphered);
	return ret;
}

int os_sm2_decrypt_prikey(IN unsigned char *cipher_text,IN unsigned int cipher_text_len,IN unsigned char *prikey,unsigned int prikey_len,OUT unsigned char **plain_text,unsigned int *plain_text_len)
{
	int ret = SM2_ERR_NOERR;
	SM2_PRIVATE_KEY privatekey = {0};
	EC_GROUP *ecgroup = NULL;
	unsigned char *plain = NULL;
	unsigned int ilen = cipher_text_len;
	unsigned int olen = 0;

	(void)str2priv(prikey, &privatekey);	
	ret = sm2_init_standard(&ecgroup);
	if (SM2_ERR_NOERR != ret)
		goto cleanup;
	ret = sm2_decrypt(ecgroup, &privatekey, cipher_text, ilen, NULL, &olen);
	if (SM2_ERR_NOERR != ret)
		goto cleanup;
	plain = (unsigned char *)SM2_MALLOC(olen);
	ret = sm2_decrypt(ecgroup, &privatekey, cipher_text, ilen, plain, &olen);
	if (SM2_ERR_NOERR != ret)
		goto cleanup;
	(*plain_text) = plain;
	(*plain_text_len) = olen;
cleanup:
	sm2_cleanup(ecgroup);
	//if (plain) free(plain);
	return ret;
}

void os_mem_free(unsigned char **pmem)
{
	if(pmem != NULL){
		SM2_FREE(*pmem);
	}
	*pmem = NULL;
}

void os_sm_kdf (unsigned char *outkey, unsigned int keylen, const unsigned char *share, unsigned int sharelen)
{
	sm_kdf (share, sharelen, keylen, outkey);
}




