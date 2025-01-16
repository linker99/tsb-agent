#include "bio.h"
#include "ossl_typ.h"
#include "asn1_locl.h"
#include "evp.h"
#include "evp_locl.h"
#include "pkcs7.h"
#include "ssl.h"
#include "x509.h"

const EVP_PKEY_METHOD rsa_pkey_meth = {0};
const EVP_PKEY_METHOD dh_pkey_meth = {0};
const EVP_PKEY_METHOD dsa_pkey_meth = {0};
const EVP_PKEY_METHOD hmac_pkey_meth = {0};
const EVP_PKEY_METHOD cmac_pkey_meth = {0};

const EVP_PKEY_ASN1_METHOD rsa_asn1_meths[2] = {{0}, {0}};
const EVP_PKEY_ASN1_METHOD dsa_asn1_meths[5] = {{0}, {0},{0}, {0},{0}};
const EVP_PKEY_ASN1_METHOD dh_asn1_meth = {0};
const EVP_PKEY_ASN1_METHOD hmac_asn1_meth = {0};
const EVP_PKEY_ASN1_METHOD cmac_asn1_meth = {0};

#ifdef __KERNEL__
int errno = 0;
FILE *stderr = NULL;
#endif

int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
    return 0;
}

void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
{
    return ;
}

int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
		CRYPTO_EX_DATA *from)
{
    return 0;
}

int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
		CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
		CRYPTO_EX_free *free_func)
{
    return 0;
}

int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val)
{
    return 0;
}

void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad,int idx)
{
    return NULL;
}

int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
			 ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
			 int en_de)
{
    return 0;
}

int PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
			     ASN1_TYPE *param,
			     const EVP_CIPHER *c, const EVP_MD *md, int en_de)
{
    return 0;
}

int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
			 ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md_type,
			 int en_de)
{
    return 0;
}


int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
			 ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
			 int en_de)
{
    return 0;
}

int RSA_sign(int type, const unsigned char *m, unsigned int m_len,
	     unsigned char *sigret, unsigned int *siglen, RSA *rsa)
{
    return 0;
}

int RSA_verify(int type, const unsigned char *m, unsigned int m_length,
	const unsigned char *sigbuf, unsigned int siglen, RSA *rsa)
{
    return 0;
}

int	RSA_up_ref(RSA *r)
{
    return 0;
}


int	DSA_up_ref(DSA *r)
{
    return 0;
}

int	DH_up_ref(DH *dh)
{
    return 0;
}

int CONF_parse_list(const char *list, int sep, int nospc,
	int (*list_cb)(const char *elem, int len, void *usr), void *arg)
{
    return 0;
}

void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si, EVP_PKEY **pk,
					X509_ALGOR **pdig, X509_ALGOR **psig)
{
	if (pk)
		*pk = si->pkey;
	if (pdig)
		*pdig = si->digest_alg;
	if (psig)
		*psig = si->digest_enc_alg;
}


void	RSA_free (RSA *r)
{
    return;
}

void	DSA_free (DSA *r)
{
    return;
}


static void u32_swap(void *a, void *b, int size)
{
	unsigned int t = *(unsigned int *)a;
	*(unsigned int *)a = *(unsigned int *)b;
	*(unsigned int *)b = t;
}

static void generic_swap(void *a, void *b, int size)
{
	char t;

	do {
		t = *(char *)a;
		*(char *)a++ = *(char *)b;
		*(char *)b++ = t;
	} while (--size > 0);
}

/*
 * sort - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp: pointer to comparison function
 * @swap: pointer to swap function or NULL
 *
 * This function does a heapsort on the given array. You may provide a
 * swap function optimized to your element type.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * qsort is about 20% faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */

void sort(void *base, size_t num, size_t size,
	  int (*cmp)(const void *, const void *),
	  void (*swap_fun)(void *, void *, int size))
{
	/* pre-scale counters for performance */
	int i = (num/2 - 1) * size, n = num * size, c, r;

	if (!swap_fun)
		swap_fun = (size == 4 ? u32_swap : generic_swap);

	/* heapify */
	for ( ; i >= 0; i -= size) {
		for (r = i; r * 2 + size < n; r  = c) {
			c = r * 2 + size;
			if (c < n - size && cmp(base + c, base + c + size) < 0)
				c += size;
			if (cmp(base + r, base + c) >= 0)
				break;
			swap_fun(base + r, base + c, size);
		}
	}

	/* sort */
	for (i = n - size; i >= 0; i -= size) {
		swap_fun(base, base + i, size);
		for (r = 0; r * 2 + size < i; r = c) {
			c = r * 2 + size;
			if (c < i - size && cmp(base + c, base + c + size) < 0)
				c += size;
			if (cmp(base + r, base + c) >= 0)
				break;
			swap_fun(base + r, base + c, size);
		}
	}
}


#ifdef __KERNEL__
void qsort(void *base, size_t nmemb, size_t size,
                  int(*compar)(const void *, const void *))
{
    return sort(base, nmemb, size, compar, NULL);
}
#endif

