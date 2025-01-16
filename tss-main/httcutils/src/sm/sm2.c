#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "httcutils/sys.h"
#include <httcutils/mem.h>
#include "httcutils/sm2.h"
#include "httcutils/sm3.h"
#include "httcutils/debug.h"
#include "sm3_impl.h"
#include "ecc.h"

enum
{

	ROLE_REQUESTOR = 0,
	ROLE_RESPONSER = 1
};

void sm2_shared_key(ecc_point *point, uint8_t *ZA, uint8_t *ZB, uint32_t keyLen, uint8_t *key);
static int ECC_Key_ex_hash2(uint8_t temp, uint8_t *y, uint8_t *hash, uint8_t *SA);
int sm2_point_mult(ecc_point *G, uint8_t *k, ecc_point *P);
//#include "tcm_debug.h"

struct ecc_curve ecc_curve = {
	.g = {
		.x = {
			0xC7, 0x74, 0x4C, 0x33, 0x89, 0x45, 0x5A, 0x71, 0xE1, 0x0B, 0x66, 0xF2, 0xBF, 0x0B, 0xE3, 0x8F,
			0x94, 0xC9, 0x39, 0x6A, 0x46, 0x04, 0x99, 0x5F, 0x19, 0x81, 0x19, 0x1F, 0x2C, 0xAE, 0xC4, 0x32},
		.y = {0xA0, 0xF0, 0x39, 0x21, 0xE5, 0x32, 0xDF, 0x02, 0x40, 0x47, 0x2A, 0xC6, 0x7C, 0x87, 0xA9, 0xD0, 0x53, 0x21, 0x69, 0x6B, 0xE3, 0xCE, 0xBD, 0x59, 0x9C, 0x77, 0xF6, 0xF4, 0xA2, 0x36, 0x37, 0xBC},
	},
	.p = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF},
	.n = {0x23, 0x41, 0xD5, 0x39, 0x09, 0xF4, 0xBB, 0x53, 0x2B, 0x05, 0xC6, 0x21, 0x6B, 0xDF, 0x03, 0x72, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF},
	.h = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	.a = {0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff},
	.b = {0x93, 0x0E, 0x94, 0x4D, 0x41, 0xBD, 0xBC, 0xDD, 0x92, 0x8F, 0xAB, 0x15, 0xF5, 0x89, 0x97, 0xF3, 0xA7, 0x09, 0x65, 0xCF, 0x4B, 0x9E, 0x5A, 0x4D, 0x34, 0x5E, 0x9F, 0x9D, 0x9E, 0xFA, 0xE9, 0x28},
};

static void ecc_b2e(uint8_t *e, const uint8_t *b)
{
	unsigned int i;

	for (i = 0; i < ECC_NUMWORD / 2; ++i)
	{
		if (e == b)
		{
			uint8_t temp;

			temp = e[i];
			e[i] = b[ECC_NUMWORD - i - 1];
			e[ECC_NUMWORD - i - 1] = temp;
		}
		else
		{
			e[i] = b[ECC_NUMWORD - i - 1];
			e[ECC_NUMWORD - i - 1] = b[i];
		}
	}
}

static void sm2_w(uint8_t *result, uint8_t *x)
{
	memcpy(result, x, 16);
	result[15] |= 0x80;
	memset(result + 16, 0, 16);
}

static int sm3_kdf(const unsigned char *seed, int send_len, unsigned char *mask, int mask_len)
{
	uint32_t ct = 0x00000001;
	uint8_t ct_char[32];
	uint8_t *hash = mask;
	uint32_t i, t;
	struct sm3_ctx_common md[1];

	t = mask_len / ECC_NUMWORD;
	for (i = 0; i < t; i++)
	{
		ht_sm3_init(md);
		ht_sm3_update(md, seed, send_len);
		digit2str32(ct, ct_char);
		ht_sm3_update(md, ct_char, 4);
		ht_sm3_finish(md, hash);
		hash += 32;
		ct++;
	}

	t = mask_len % ECC_NUMWORD;
	if (t)
	{
		ht_sm3_init(md);
		ht_sm3_update(md, seed, send_len);
		digit2str32(ct, ct_char);
		ht_sm3_update(md, ct_char, 4);
		ht_sm3_finish(md, ct_char);
		memcpy(hash, ct_char, t);
	}
	return 0;
}

static void sm3_z(const uint8_t *id, uint32_t idlen, ecc_point *pub, uint8_t *hash)
{
	uint8_t pubx[ECC_NUMWORD];
	uint8_t puby[ECC_NUMWORD];
	uint8_t a[ECC_NUMWORD];
	uint8_t b[ECC_NUMWORD];
	uint8_t gx[ECC_NUMWORD];
	uint8_t gy[ECC_NUMWORD];
	uint8_t idlen_char[2];
	struct sm3_ctx_common md[1];

	vli_set(pubx, pub->x);
	vli_set(puby, pub->y);

	digit2str16(idlen << 3, idlen_char);

	ecc_b2e(a, ecc_curve.a);
	ecc_b2e(b, ecc_curve.b);
	ecc_b2e(gx, ecc_curve.g.x);
	ecc_b2e(gy, ecc_curve.g.y);

	ht_sm3_init(md);
	ht_sm3_update(md, idlen_char, 2);
	ht_sm3_update(md, id, idlen);
	ht_sm3_update(md, a, ECC_NUMWORD);
	ht_sm3_update(md, b, ECC_NUMWORD);
	ht_sm3_update(md, gx, ECC_NUMWORD);
	ht_sm3_update(md, gy, ECC_NUMWORD);
	ht_sm3_update(md, pubx, ECC_NUMWORD);
	ht_sm3_update(md, puby, ECC_NUMWORD);
	ht_sm3_finish(md, hash);

	return;
}

static int ecc_valid_public_key(ecc_point *publicKey)
{
	uint8_t na[ECC_NUMWORD] = {3};
	uint8_t tmp1[ECC_NUMWORD];
	uint8_t tmp2[ECC_NUMWORD];

	if (ecc_point_is_zero(publicKey))
		return 1;

	if (vli_cmp(ecc_curve.p, publicKey->x) != 1 || vli_cmp(ecc_curve.p, publicKey->y) != 1)
		return 1;

	vli_mod_square_fast(tmp1, publicKey->y, ecc_curve.p);
	vli_mod_square_fast(tmp2, publicKey->x, ecc_curve.p);
	vli_mod_sub(tmp2, tmp2, na, ecc_curve.p);
	vli_mod_mult_fast(tmp2, tmp2, publicKey->x, ecc_curve.p);
	vli_mod_add(tmp2, tmp2, ecc_curve.b, ecc_curve.p);

	if (vli_cmp(tmp1, tmp2) != 0)
		return 1;

	return 0;
}

static int sm2_make_prikey(uint8_t *prikey)
{
	uint8_t pri[ECC_NUMWORD];
	int i = 10;

	do
	{
		httc_util_rand_bytes(pri, ECC_NUMWORD);
		if (vli_cmp(ecc_curve.n, pri) != 1)
		{
			vli_sub(pri, pri, ecc_curve.n);
		}

		if (!vli_is_zero(pri))
		{
			ecc_b2e(prikey, pri);
			return 0;
		}
	} while (i--);

	return -1;
}

static int sm2_make_pubkey(uint8_t *prikey, ecc_point *pubkey)
{
	ecc_point pub[1];
	uint8_t pri[ECC_NUMWORD];

	ecc_b2e(pri, prikey);
	ecc_point_mult(pub, &ecc_curve.g, pri, NULL);
	ecc_b2e(pubkey->x, pub->x);
	ecc_b2e(pubkey->y, pub->y);

	return 0;
}

//int sm2_make_keypair(uint8_t *prikey, ecc_point *pubkey)
//{
//	sm2_make_prikey(prikey);
//	sm2_make_pubkey(prikey, pubkey);
//	return 0;
//}

int sm2_point_mult(ecc_point *G, uint8_t *k, ecc_point *P)
{
	int rc = 0;

	ecc_point G_[1];
	ecc_point P_[1];
	uint8_t k_[ECC_NUMWORD];

	ecc_b2e(k_, k);
	ecc_b2e(G_->x, G->x);
	ecc_b2e(G_->y, G->y);

	ecc_point_mult(P_, G_, k_, NULL);

	ecc_b2e(P->x, P_->x);
	ecc_b2e(P->y, P_->y);

	return rc;
}

static int sm2_sign_impl(uint8_t *r, uint8_t *s, const uint8_t *prikey, const uint8_t *hash)
{
	uint8_t Rng[ECC_NUMWORD] = {
		0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC,
		0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21};
	uint8_t one[ECC_NUMWORD] = {1};
	uint8_t random[ECC_NUMWORD];
	uint8_t pri[ECC_NUMWORD];
	ecc_point p;

	ecc_b2e(pri, prikey);
#ifndef STANDARD_PART_5
	httc_util_rand_bytes(random, ECC_NUMWORD);
	if (vli_is_zero(random))
	{
		return 0;
	}
	vli_set(Rng, random);
	if (vli_cmp(ecc_curve.n, Rng) != 1)
	{
		vli_sub(Rng, Rng, ecc_curve.n);
	}
#endif
	ecc_b2e(Rng, Rng);
	ecc_point_mult(&p, &ecc_curve.g, Rng, NULL);
	vli_set(r, p.x);

	ecc_b2e(random, hash);
	vli_mod_add(r, r, random, ecc_curve.n);
	if (vli_cmp(ecc_curve.n, r) != 1)
	{
		vli_sub(r, r, ecc_curve.n);
	}

	if (vli_is_zero(r))
	{
		return 0;
	}

	vli_mod_mult(s, r, pri, ecc_curve.n);
	vli_mod_sub(s, Rng, s, ecc_curve.n);
	vli_mod_add(pri, pri, one, ecc_curve.n);
	vli_mod_inv(pri, pri, ecc_curve.n);
	vli_mod_mult(s, pri, s, ecc_curve.n);

	ecc_b2e(r, r);
	ecc_b2e(s, s);

	return 1;
}

static int sm2_verify_impl(ecc_point *pubkey, const uint8_t *hash, const uint8_t *r, const uint8_t *s)
{
	ecc_point result;
	uint8_t t[ECC_NUMWORD];
	uint8_t rr[ECC_NUMWORD];
	uint8_t ss[ECC_NUMWORD];
	ecc_point pub[1];

	ecc_b2e(pub->x, pubkey->x);
	ecc_b2e(pub->y, pubkey->y);
	ecc_b2e(rr, r);
	ecc_b2e(ss, s);

	if (vli_is_zero(rr) || vli_is_zero(ss))
	{
		return -1;
	}

	if (vli_cmp(ecc_curve.n, rr) != 1 || vli_cmp(ecc_curve.n, ss) != 1)
	{
		return -1;
	}

	vli_mod_add(t, rr, ss, ecc_curve.n);
	if (t == NULL)
		return -1;

	ecc_point_mult2(&result, &ecc_curve.g, pub, ss, t);
	ecc_b2e(t, hash);
	vli_mod_add(result.x, result.x, t, ecc_curve.n);

	if (vli_cmp(ecc_curve.n, result.x) != 1)
	{
		vli_sub(result.x, result.x, ecc_curve.n);
	}

	return vli_cmp(result.x, rr);
}
int ht_sm2_encrypt(unsigned char *C, unsigned int *Clen,
				   const unsigned char *M, int Mlen,
				   unsigned char *szPubkey_XY, int ul_PubkXY_len)
{
	//int sm2_encrypt(ecc_point *pubKey, uint8_t *M, uint32_t Mlen, uint8_t *C, uint32_t *Clen)
	ecc_point *pubKey = (ecc_point *)szPubkey_XY;
	uint8_t Rng[ECC_NUMWORD] = {
		0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC,
		0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21};
	uint8_t t[Mlen];
	ecc_point pub[1];

	ecc_point *C1 = (ecc_point *)(C + 1);
	uint8_t *C3 = (C + 1) + ECC_NUMWORD * 2;
	uint8_t *C2 = (C + 1) + ECC_NUMWORD * 2 + ECC_NUMWORD;
	ecc_point S;

	ecc_point kP;
	uint8_t *x2 = kP.x;
	uint8_t *y2 = kP.y;
	uint8_t *x2y2 = x2;
	struct sm3_ctx_common md[1];
	int i;

	C[0] = 0x04;

	ecc_b2e(pub->x, pubKey->x);
	ecc_b2e(pub->y, pubKey->y);

#ifndef STANDARD_PART_5
	httc_util_rand_bytes(Rng, ECC_NUMWORD);
#endif
	ecc_b2e(Rng, Rng);

	ecc_point_mult(C1, &ecc_curve.g, Rng, NULL);
	ecc_b2e(C1->x, C1->x);
	ecc_b2e(C1->y, C1->y);

	ecc_point_mult(&S, pub, ecc_curve.h, NULL);
	if (ecc_valid_public_key(&S) != 0)
		return -1;

	ecc_point_mult(&kP, pub, Rng, NULL);
	ecc_b2e(x2, x2);
	ecc_b2e(y2, y2);

	sm3_kdf(x2y2, ECC_NUMWORD * 2, t, Mlen);
	if (vli_is_zero(x2) | vli_is_zero(y2))
	{
		return 0;
	}

	for (i = 0; i < Mlen; i++)
	{
		C2[i] = M[i] ^ t[+i];
	}

	ht_sm3_init(md);
	ht_sm3_update(md, x2, ECC_NUMWORD);
	ht_sm3_update(md, M, Mlen);
	ht_sm3_update(md, y2, ECC_NUMWORD);
	ht_sm3_finish(md, C3);

	if (Clen)
		*Clen = Mlen + ECC_NUMWORD * 2 + ECC_NUMWORD + 1;

	return 0;
}
int ht_sm2_decrypt(unsigned char *M, unsigned int *Mlen,
				   const unsigned char *C, int Clen,
				   const unsigned char *prikey, int ulPri_dALen)
//int sm2_decrypt(uint8_t *prikey, uint8_t *C, uint32_t Clen, uint8_t *M, uint32_t *Mlen)
{

	uint8_t hash[ECC_NUMWORD] = {0};
	uint8_t pri[ECC_NUMWORD] = {0};

	ecc_point *C1 = NULL;
	const uint8_t *C3 = NULL;
	const uint8_t *C2 = NULL;
	ecc_point dB;
	ecc_point S;
	uint8_t *x2 = NULL;
	uint8_t *y2 = NULL;
	uint8_t *x2y2 = NULL;
	struct sm3_ctx_common md;
	int outlen = 0;
	int i = 0;

	//	ENTER();

	if (!C || (Clen < ECC_NUMWORD * 3) || (0x04 != C[0]))
	{
		httc_util_pr_error("parameter is error\n");
		return -1;
	}

	C1 = (ecc_point *)(C + 1);
	C3 = (C + 1) + ECC_NUMWORD * 2;
	C2 = (C + 1) + ECC_NUMWORD * 2 + ECC_NUMWORD;
	x2 = dB.x;
	y2 = dB.y;
	x2y2 = x2;
	outlen = Clen - ECC_NUMWORD * 3 - 1;

	ecc_b2e(pri, prikey);
	ecc_b2e(C1->x, C1->x);
	ecc_b2e(C1->y, C1->y);

	if (ecc_valid_public_key(C1) != 0)
	{
		httc_util_pr_error("ecc_valid_public_key error\n");
		return -1;
	}

	ecc_point_mult(&S, C1, ecc_curve.h, NULL);
	if (ecc_valid_public_key(&S) != 0)
	{
		httc_util_pr_error("ecc_valid_public_key(&S) error\n");
		return -1;
	}

	ecc_point_mult(&dB, C1, pri, NULL);
	ecc_b2e(x2, x2);
	ecc_b2e(y2, y2);

	sm3_kdf(x2y2, ECC_NUMWORD * 2, M, outlen);
	if (vli_is_zero(x2) | vli_is_zero(y2))
	{
		return 0;
	}

	for (i = 0; i < outlen; i++)
		M[i] = M[i] ^ C2[i];

	ht_sm3_init(&md);
	ht_sm3_update(&md, x2, ECC_NUMWORD);
	ht_sm3_update(&md, M, outlen);
	ht_sm3_update(&md, y2, ECC_NUMWORD);
	ht_sm3_finish(&md, hash);

	*Mlen = outlen;
	if (memcmp(hash, C3, ECC_NUMWORD) != 0)
	{
		httc_util_pr_error("memcmp  C3 error");
		return -1;
	}
	else
		return 0;
}

static int sm2_shared_point(const uint8_t *selfPriKey, const uint8_t *selfTempPriKey, ecc_point *selfTempPubKey,
							ecc_point *otherPubKey, ecc_point *otherTempPubKey, ecc_point *key)
{
	ecc_point selfTempPub;
	ecc_point otherTempPub;
	ecc_point otherPub;
	ecc_point U[1];

	uint8_t selfTempPri[ECC_NUMWORD];
	uint8_t selfPri[ECC_NUMWORD];
	uint8_t temp1[ECC_NUMWORD];
	uint8_t temp2[ECC_NUMWORD];
	uint8_t tA[ECC_NUMWORD];

	ecc_b2e(selfTempPri, selfTempPriKey);
	ecc_b2e(selfPri, selfPriKey);
	ecc_b2e(selfTempPub.x, selfTempPubKey->x);
	ecc_b2e(selfTempPub.y, selfTempPubKey->y);
	ecc_b2e(otherTempPub.x, otherTempPubKey->x);
	ecc_b2e(otherTempPub.y, otherTempPubKey->y);
	ecc_b2e(otherPub.x, otherPubKey->x);
	ecc_b2e(otherPub.y, otherPubKey->y);

	sm2_w(temp1, selfTempPub.x);
	vli_mod_mult(temp1, selfTempPri, temp1, ecc_curve.n);
	vli_mod_add(tA, selfPri, temp1, ecc_curve.n);
	if (ecc_valid_public_key(&otherTempPub) != 0)
		return -1;
	sm2_w(temp2, otherTempPub.x);
	ecc_point_mult(U, &otherTempPub, temp2, NULL);
	ecc_point_add(U, &otherPub, U);
	vli_mod_mult(tA, tA, ecc_curve.h, ecc_curve.n);
	ecc_point_mult(U, U, tA, NULL);

	ecc_b2e(key->x, U->x);
	ecc_b2e(key->y, U->y);

	return 0;
}

void sm2_shared_key(ecc_point *point, uint8_t *ZA, uint8_t *ZB, uint32_t keyLen, uint8_t *key)
{
	uint8_t Z[ECC_NUMWORD * 4];
	memcpy(Z, point->x, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD, point->y, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD * 2, ZA, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD * 3, ZB, ECC_NUMWORD);
	sm3_kdf(Z, ECC_NUMWORD * 4, key, keyLen);
}

static int ECC_Key_ex_hash1(uint8_t *x, ecc_point *RA, ecc_point *RB, const uint8_t ZA[], const uint8_t ZB[], uint8_t *hash)
{
	struct sm3_ctx_common md[1];

	ht_sm3_init(md);
	ht_sm3_update(md, x, ECC_NUMWORD);
	ht_sm3_update(md, ZA, ECC_NUMWORD);
	ht_sm3_update(md, ZB, ECC_NUMWORD);
	ht_sm3_update(md, RA->x, ECC_NUMWORD);
	ht_sm3_update(md, RA->y, ECC_NUMWORD);
	ht_sm3_update(md, RB->x, ECC_NUMWORD);
	ht_sm3_update(md, RB->y, ECC_NUMWORD);
	ht_sm3_finish(md, hash);

	return 0;
}

static int ECC_Key_ex_hash2(uint8_t temp, uint8_t *y, uint8_t *hash, uint8_t *SA)
{
	struct sm3_ctx_common md[1];

	ht_sm3_init(md);
	ht_sm3_update(md, &temp, 1);
	ht_sm3_update(md, y, ECC_NUMWORD);
	ht_sm3_update(md, hash, ECC_NUMWORD);
	ht_sm3_finish(md, SA);

	return 0;
}

int ht_sm2_generate_keypair(unsigned char *prikey, unsigned int *pulPriLen, unsigned char pubkey_XY[64])
{
	//sm2_make_keypair(prikey,(ecc_point *)pulPriLen);
	sm2_make_prikey(prikey);
	sm2_make_pubkey(prikey, (ecc_point *)pubkey_XY);
	*pulPriLen = 32;
	return 0;
}

//void dump_hex(const char *string, const unsigned char* buff, int length);
int ht_sm2_sign(unsigned char *signedData, unsigned int *pulSigLen,
				const unsigned char *message, int ilen,
				const unsigned char *id, int lenUID,
				const unsigned char *prikey, int ulPrikeyLen,
				unsigned char pubkey_XY[64])
{
	uint32_t mlen = 0;
	uint8_t *m = NULL;
	uint8_t e[32] = {0};
	uint8_t Za[32] = {0};
	//uint8_t id[18] = "ALICE123@YAHOO.COM";
	//ecc_point pub;
	struct sm3_ctx_common ctx;
	sm3_z(id, lenUID, (ecc_point *)pubkey_XY, Za);
	mlen = ilen + 32;
	m = httc_malloc(mlen);
	if (m)
	{
		memcpy(m, Za, 32);
		memcpy(m + 32, message, ilen);
		ht_sm3_init(&ctx);
		ht_sm3_update(&ctx, m, mlen);
		ht_sm3_finish(&ctx, e);
		//sm3_finup(&ctx, m, mlen, e);
		//dump_hex("e",e,32);
		if (sm2_sign_impl(signedData, signedData + ECC_NUMWORD, prikey, e))
		{
			*pulSigLen = ECC_NUMWORD + ECC_NUMWORD;
			httc_free(m);
			return 0;
		}
		else
		{
			httc_free(m);
			return -1;
		}
	}
	else
	{
		httc_util_pr_error("No memory for SM2Sign\n");
		return -1;
	}
}

int ht_sm2_verify(const unsigned char *sign, int sign_len,
				  const unsigned char *msg, int msg_len,
				  const unsigned char *user_id, int id_len,
				  const unsigned char *pub_key, int pubkey_len)
{
	uint8_t digest[ECC_NUMWORD];
	uint8_t Za[ECC_NUMWORD];
	//uint8_t id[18] = "ALICE123@YAHOO.COM";
	struct sm3_ctx_common ctx;
	sm3_z(user_id, id_len, (ecc_point *)pub_key, Za);
	//dump_hex("za1",Za,32);
	ht_sm3_init(&ctx);
	ht_sm3_update(&ctx, Za, ECC_NUMWORD);
	ht_sm3_update(&ctx, msg, msg_len);
	ht_sm3_finish(&ctx, digest);
	//dump_hex("e1",digest,32);
	return sm2_verify_impl((ecc_point *)pub_key, digest, sign, sign + ECC_NUMWORD);
}

int ht_sm3_z(const unsigned char *Userid, unsigned int idlen, unsigned char *pubkey/*64B*/, unsigned char *Zdata)
{
	ecc_point *pub_key = (ecc_point *)pubkey;
	
	if ((NULL == Userid) || (NULL == Zdata) || (NULL == pubkey))
	{
		return (-1);
	}
	
	sm3_z(Userid, idlen, pub_key, Zdata);
	
	return 0;
}

int ht_sm3_e(const unsigned char *Userid, unsigned int idlen, unsigned char *pubkey/*64B*/, const unsigned char *msgdate, unsigned int msgdatelen, unsigned char *Ehash/*32B*/)
{
	ecc_point *pub_key = (ecc_point *)pubkey;
	unsigned char Za[ECC_NUMWORD];
	struct sm3_ctx_common ctx;
	if ((NULL == Userid) || (NULL == pubkey) || (NULL == msgdate) || (NULL == Ehash) )
	{
		return (-1);
	}

	//calculation Z
	sm3_z(Userid, idlen, pub_key, Za);

	//calculation E
	ht_sm3_init(&ctx);
	ht_sm3_update(&ctx, Za, ECC_NUMWORD);
	ht_sm3_update(&ctx, msgdate, msgdatelen);
	ht_sm3_finish(&ctx, Ehash);

	return (0);
}



int ht_sm2_sign_digest(
				  unsigned char* signedData, unsigned int * pulSigLen,
				  const unsigned char* digest, int digest_len,
				  const unsigned char* prikey, unsigned long ulPrikeyLen)
{
	*pulSigLen = ECC_NUMWORD + ECC_NUMWORD;
	return !sm2_sign_impl(signedData, signedData + ECC_NUMWORD, prikey, digest);
}



int ht_sm2_verify_digest(const unsigned char *sign, int sign_len,	   //64 byte
						 const unsigned char *digest, int digest_len,  //32 byte
						 const unsigned char *pub_key, int pubkey_len) //64_byte
{
	return sm2_verify_impl((ecc_point *)pub_key, digest, sign, sign + ECC_NUMWORD);
}

/*
 * sm2 shared key generation with GM predefined curve params
 *
 * param:
 * @outkey            : [out] : caculated shared key
 * @dgst_S1, @lenDgst_S1 : [out] : output hashed data S1, *LenDgst will always return 32
 * @dgst_SA, @lenDgst_SA : [out] : output hashed data SA, *LenDgst will always return 32
 * @keylen         : [in] : expected shared key length in byte
 * @userID_A, @lenUID_A : [in] : input user A's ID and length
 * @userID_B, @lenUID_B : [in] : input user B's ID and length
 * @priKey_A, @priKeyLen_A : [in] : private key of side A
 * @rndKey_A, @rndKeyLen_A : [in] : random key of side A
 * @pubKey_Axy : [in] : public key (Ax, Ay) of side A
 * @pubKey_Bxy : [in] : public key (Bx, By) of side B
 * @RAxy       : [in] : temp key (RAx, RAy) of side A
 * @RBxy       : [in] : temp key (RBx, RBy) of side B
 * structure of pubkey should be :
 * [--32 byte of X coordinate--][--32 byte of Y coordinate--]
 * @role    : [in] : 0: requestor/1: responser
 *
 * return :
 * 0 : success
 * other errcode : operation failed
 */
//int sm2_dh_key( const unsigned char Za[SM3_DIGEST_SIZE], const unsigned char Zb[SM3_DIGEST_SIZE],
//	const SM2_PRIVATE_KEY *a_pri_key, const SM2_PUBLIC_KEY *a_pub_key,const SM2_PUBLIC_KEY *b_pub_key,
//	SM2_PRIVATE_KEY *r_a,SM2_PUBLIC_KEY *R_a,
//	SM2_PUBLIC_KEY *R_b, unsigned int keylen, unsigned char *outkey,
//	unsigned char S1[SM3_DIGEST_SIZE],unsigned char SA[SM3_DIGEST_SIZE])
int ht_sm2_dh_key(unsigned char *outkey,
				  unsigned char *dgst_S1, unsigned int *lenDgst_S1,
				  unsigned char *dgst_SA, unsigned int *lenDgst_SA,
				  int keylen,
				  const unsigned char *uid_a, int uid_len_a,
				  const unsigned char *uid_b, int uid_len_b,
				  const unsigned char *prikey_a, int prikey_len_a,
				  const unsigned char *prikey_temp_a, int rndKeyLen_A,
				  const unsigned char *pubkey_a, const unsigned char *pubkey_b,
				  const unsigned char *pubkey_temp_a, const unsigned char *pubkey_temp_b,
				  int role)
//int sm2_dh_key( const unsigned char Za[SM3_DIGEST_SIZE], const unsigned char Zb[SM3_DIGEST_SIZE],
//	const SM2_PRIVATE_KEY *a_pri_key, const SM2_PUBLIC_KEY *a_pub_key,const SM2_PUBLIC_KEY *b_pub_key,
//	SM2_PRIVATE_KEY *r_a,SM2_PUBLIC_KEY *R_a,
//	SM2_PUBLIC_KEY *R_b, unsigned int keylen, unsigned char *outkey,
//	unsigned char S1[SM3_DIGEST_SIZE],unsigned char SA[SM3_DIGEST_SIZE])
{

	//int rc	= TCM_SUCCESS ;

	//	ecc_point Ra;
	//	ecc_point PB;
	//	ecc_point Rb;
	ecc_point UV;
	uint8_t Z[128] = {0};
	uint8_t temp[2] = {0x02, 0x03};
	uint8_t hash1[32] = {0};

	if (uid_len_a != 32 || uid_len_a != 32 || uid_len_b != 32 || prikey_len_a != 32 || rndKeyLen_A != 32)
	{
		httc_util_pr_error("sm2_dh_key param length error\n");
		return -1;
	}
	//unsigned char flag=1;

	//	memcpy(Ra.x, R_a->x, SM2_BIGNUM_BUFSIZE);
	//	memcpy(Ra.y, R_a->y, SM2_BIGNUM_BUFSIZE);
	//
	//	memcpy(PB.x, b_pub_key->x, SM2_BIGNUM_BUFSIZE);
	//	memcpy(PB.y, b_pub_key->y, SM2_BIGNUM_BUFSIZE);
	//
	//	memcpy(Rb.x, R_b->x, SM2_BIGNUM_BUFSIZE);
	//	memcpy(Rb.y, R_b->y, SM2_BIGNUM_BUFSIZE);

	sm2_shared_point(prikey_a, prikey_temp_a, (ecc_point *)pubkey_temp_a, (ecc_point *)pubkey_b, (ecc_point *)pubkey_temp_b, &UV);
	if (role == ROLE_REQUESTOR)
	{
		memcpy(Z, UV.x, 32);
		memcpy(Z + 32, UV.y, 32);
		memcpy(Z + 64, uid_a, 32);
		memcpy(Z + 96, uid_b, 32);
		sm3_kdf(Z, 128, outkey, keylen);
		ECC_Key_ex_hash1(UV.x, (ecc_point *)pubkey_temp_a, (ecc_point *)pubkey_temp_b, (uint8_t *)uid_a, (uint8_t *)uid_b, hash1);
		ECC_Key_ex_hash2(temp[0], UV.y, hash1, dgst_S1);
		ECC_Key_ex_hash2(temp[1], UV.y, hash1, dgst_SA);
	}
	else
	{
		memcpy(Z, UV.x, 32);
		memcpy(Z + 32, UV.y, 32);
		memcpy(Z + 64, uid_b, 32);
		memcpy(Z + 96, uid_a, 32);
		sm3_kdf(Z, 128, outkey, keylen);
		ECC_Key_ex_hash1(UV.x, (ecc_point *)pubkey_temp_b, (ecc_point *)pubkey_temp_a, uid_b, uid_a, hash1);
		ECC_Key_ex_hash2(temp[0], UV.y, hash1, dgst_SA);
		ECC_Key_ex_hash2(temp[1], UV.y, hash1, dgst_S1);
	}

	//	rc = TCM_SUCCESS ;

	return 0;
}


