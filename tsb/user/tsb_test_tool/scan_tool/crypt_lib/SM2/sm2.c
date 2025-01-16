#include "sm2.h"

#include "ecdh.h"
#include "ecdsa.h"
#include "rand.h"
#include "ssl.h"
#include "stub.h"
#ifndef __KERNEL__
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#else
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/types.h>
//SM2-FILE-START
//#include <linux/fs.h>
//SM2-FILE-END
#endif


#ifndef __KERNEL__
#define SYSLOG(args...)  syslog(LOG_ERR,##args)
#endif

#define  NID_X9_62_prime_field 406
//#define _DEBUG 0

#define SIGN_HEAD "##<0xFF"
#define SIGN_TAIL "0xFF>##"
#define DEV_COMPANY_ID 		"0xFF"

static void BNPrintf(BIGNUM* bn)
{
	char *p=NULL;
	p=BN_bn2hex(bn);
	printf("%s",p);
	OPENSSL_free(p);
}

static int EC_bn2bin(BIGNUM *n, unsigned char *to)
{
	int len = BN_bn2bin(n, to);
	int i=SM2_BIGNUM_BUFSIZE-1;
	int gap=0;
	if((gap=(SM2_BIGNUM_BUFSIZE-len))>0)
		for(;i>=0;i--)
		{
			if(i>=gap)
				*(to+i)=*(to+i-gap);
			else
				*(to+i)=0;
		}
	return len;
}

static BIGNUM* EC_bin2bn(const unsigned char *from, int len, BIGNUM *ret)
{
	int i=0;
	for(;i<SM2_BIGNUM_BUFSIZE;i++)
		if(from[i])
			break;
	return BN_bin2bn(from+i, len-i, ret);
}

/** sm2_sign_setup
* precompute parts of the signing operation. 
* \param eckey pointer to the EC_KEY object containing a private EC key
* \param ctx_in  pointer to a BN_CTX object (may be NULL)
* \param kp pointer to a BIGNUM pointer for the inverse of k
* \param rp   pointer to a BIGNUM pointer for x coordinate of k * generator
* \return 1 on success and 0 otherwise
 */
static int sm2_sign_setup(const EC_GROUP *ecgroup, BN_CTX *ctx_in, BIGNUM **kp, BIGNUM **rp)
{
	BN_CTX   *ctx = NULL;
	BIGNUM	 *k = NULL, *r = NULL, *order = NULL, *X = NULL;
	EC_POINT *tmp_point=NULL;
//	const EC_GROUP *group;
	int 	 ret = SM2_ERR_NOERR;

// 	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL)
// 		return SM2_ERR_BAD_PARAM;

	if (ctx_in == NULL) 
	{
		if ((ctx = BN_CTX_new()) == NULL)
			return SM2_ERR_MALLOC_FAILED;
	}
	else
		ctx = ctx_in;

	k     = BN_new();	/* this value is later returned in *kp */
	r     = BN_new();	/* this value is later returned in *rp */
	order = BN_new();
	X     = BN_new();
	if (!k || !r || !order || !X)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto err;
	}
	if ((tmp_point = EC_POINT_new(ecgroup)) == NULL)
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
	if (!EC_GROUP_get_order(ecgroup, order, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
	
	do
	{
		/* get random k */	
		do {
			if (!BN_rand_range(k, order))
			{
				ret = SM2_ERR_RANDOM_FAILED;
				goto err;
			}
		} while (BN_is_zero(k));

		/* compute r the x-coordinate of generator * k */
		if (!EC_POINT_mul(ecgroup, tmp_point, k, NULL, NULL, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto err;
		}
		if (EC_METHOD_get_field_type(EC_GROUP_method_of(ecgroup)) == NID_X9_62_prime_field)
		{
			if (!EC_POINT_get_affine_coordinates_GFp(ecgroup,
				tmp_point, X, NULL, ctx))
			{
				ret = SM2_ERR_EC_LIB;
				goto err;
			}
		}
		else /* NID_X9_62_characteristic_two_field */
		{
			if (!EC_POINT_get_affine_coordinates_GF2m(ecgroup,
				tmp_point, X, NULL, ctx))
			{
				ret = SM2_ERR_EC_LIB;
				goto err;
			}
		}
		if (!BN_nnmod(r, X, order, ctx))
		{
			ret = SM2_ERR_BN_LIB;
			goto err;
		}
	} while (BN_is_zero(r));

	/* compute the inverse of k */
// 	if (!BN_mod_inverse(k, k, order, ctx))
// 	{
// 		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
// 		goto err;	
// 	}
	/* clear old values if necessary */
	if (*rp != NULL)
		BN_clear_free(*rp);
	if (*kp != NULL) 
		BN_clear_free(*kp);
	/* save the pre-computed values  */
	*rp = r;
	*kp = k;
err:
	if (SM2_ERR_NOERR != ret)
	{
		if (k != NULL) BN_clear_free(k);
		if (r != NULL) BN_clear_free(r);
	}
	if (!ctx_in) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (tmp_point) EC_POINT_free(tmp_point);
	if (X) BN_clear_free(X);
	return ret;
}


static int sm2_do_sign(const EC_GROUP *ecgroup, const BIGNUM *privatekey, const unsigned char Z[SM3_DIGEST_SIZE],
	const unsigned char *input, unsigned int ilen, ECDSA_SIG *signature, const BIGNUM *in_k, const BIGNUM *in_r)
{
	int ret = SM2_ERR_NOERR;
//	unsigned int i = 0, dgst_len = 0, degree = 0;
	unsigned int i = 0, dgst_len = 0;
	BIGNUM *k=NULL, *s, *r, *m=NULL,*tmp=NULL,*order=NULL;
	const BIGNUM *ck;
	BN_CTX     *ctx = NULL;
    BIGNUM *x=NULL, *a=NULL;	//new added
	unsigned char dgst[SM3_DIGEST_SIZE] = {0};
	sm3_context sm3_ctx;
	//const EC_POINT *pPoint = NULL;
	unsigned char *str = NULL;
	//char str_idlen[2] = {0};

	s = signature->s;
	r = signature->r;

	if ((ctx = BN_CTX_new()) == NULL || (order = BN_new()) == NULL ||
		(tmp = BN_new()) == NULL || (m = BN_new()) == NULL || 
		(x = BN_new()) == NULL || (a = BN_new()) == NULL)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto err;
	}
	if (!EC_GROUP_get_order(ecgroup, order, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}

	sm3_starts(&sm3_ctx);
	sm3_update(&sm3_ctx, Z, SM3_DIGEST_SIZE);
	sm3_update(&sm3_ctx, input, ilen);
	sm3_finish(&sm3_ctx, dgst);

	i = BN_num_bits(order);
	/* Need to truncate digest if it is too long: first truncate whole
	 * bytes.
	 */
	dgst_len = SM3_DIGEST_SIZE;
	if (8 * dgst_len > i)
		dgst_len = (i + 7)/8;
	if (!EC_bin2bn(dgst, dgst_len, m))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}
	/* If still too long truncate remaining bits with a shift */
	if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7)))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}
// 	fprintf(stdout,"m: ");
// 	BNPrintf(m);
// 	fprintf(stdout,"\n");
	do
	{
		if (in_k == NULL || in_r == NULL)
		{
			if (SM2_ERR_NOERR != (ret = sm2_sign_setup(ecgroup, ctx, &k, &x)))
				goto err;
			ck = k;
		}
		else
		{
			ck  = in_k;
			if (BN_copy(x, in_r) == NULL)
			{
				ret = SM2_ERR_MALLOC_FAILED;
				goto err;
			}
		}
		
		//r=(e+x1) mod n
		if (!BN_mod_add_quick(r, m, x, order))
		{
			ret = SM2_ERR_BN_LIB;
			goto err;
		}

		if(BN_is_zero(r))
			continue;
		BN_add(tmp,r,ck);
		if(BN_ucmp(tmp,order) == 0)
			continue;
		
		if (!BN_mod_mul(tmp, privatekey, r, order, ctx))
		{
			ret = SM2_ERR_BN_LIB;
			goto err;
		}
		if (!BN_mod_sub_quick(s, ck, tmp, order))
		{
			ret = SM2_ERR_BN_LIB;
			goto err;
		}
		BN_one(a);
		//BN_set_word((a),1);

		if (!BN_mod_add_quick(tmp, privatekey, a, order))
		{
			ret = SM2_ERR_BN_LIB;
			goto err;
		}
		/* compute the inverse of 1+dA */
		if (!BN_mod_inverse(tmp, tmp, order, ctx))
		{
			ret = SM2_ERR_BN_LIB;
			goto err;	
		}
// 		BNPrintf(tmp);
// 		fprintf(stdout,"\n");

		if (!BN_mod_mul(s, s, tmp, order, ctx))
		{
			ret = SM2_ERR_BN_LIB;
			goto err;
		}
		if (BN_is_zero(s))
		{
			/* if k and r have been supplied by the caller
			 * don't generate new k and r values */
			if (in_k != NULL && in_r != NULL)
			{
				ret = SM2_ERR_BAD_PARAM;
				goto err;
			}
		}
		else
			/* s != 0 => we have a valid signature */
			break;
	} while (1);

err:
	if (ctx) BN_CTX_free(ctx);
	if (m) BN_clear_free(m);
	if (tmp) BN_clear_free(tmp);
	if (order) BN_clear_free(order);
	if (k) BN_clear_free(k);
	if (x) BN_clear_free(x);
	if (a) BN_clear_free(a);
#ifdef __KERNEL__
	if (str) kfree(str);
#else
	if (str) free(str);
#endif
	return ret;
}


static int sm2_do_verify(const EC_GROUP *ecgroup, const EC_POINT *pub_key, const unsigned char Z[SM2_BIGNUM_BUFSIZE],
	const unsigned char *input, unsigned int ilen, const ECDSA_SIG *sig)
{
	int ret = SM2_ERR_NOERR;
//	int k = 0;
//	unsigned int i = 0, dgst_len = 0, degree = 0;
	unsigned int i = 0, dgst_len = 0;
	BN_CTX   *ctx = NULL;
	BIGNUM   *order, *R,  *m, *X,*t;
	EC_POINT *point = NULL;
// 	const EC_GROUP *group;
// 	const EC_POINT *pub_key;
	unsigned char dgst[SM3_DIGEST_SIZE] = {0};
	sm3_context sm3_ctx;
//	const EC_POINT *pPoint = NULL;
//	char str_idlen[2];
	unsigned char *str = NULL;

	/* check input values */
// 	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
// 	    (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL)
// 		return SM2_ERR_BAD_PARAM;

	ctx = BN_CTX_new();
	if (!ctx)
		return SM2_ERR_MALLOC_FAILED;

	BN_CTX_start(ctx);
	order = BN_CTX_get(ctx);	
	R     = BN_CTX_get(ctx);
	t     = BN_CTX_get(ctx);
	m     = BN_CTX_get(ctx);
	X     = BN_CTX_get(ctx);
	if (!X)
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}
	
	if (!EC_GROUP_get_order(ecgroup, order, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}

	if (BN_is_zero(sig->r)          || BN_is_negative(sig->r) || 
	    /*BN_ucmp(sig->r, order) >= 0 || */ BN_is_zero(sig->s)  ||
	    BN_is_negative(sig->s)      || BN_ucmp(sig->s, order) >= 0)
	{
		ret = SM2_ERR_BAD_SIGNATURE;	/* signature is invalid */
		printf("data is error.\n");
		goto err;
	}

	//t =(r+s) mod n
	if (!BN_mod_add_quick(t, sig->s, sig->r, order))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}
	if (BN_is_zero(t))
	{
		ret = SM2_ERR_BAD_SIGNATURE;	/* signature is invalid */
		printf("t is error.\n");
		goto err;
	}
	
	//point = s*G+t*PA
	if ((point = EC_POINT_new(ecgroup)) == NULL)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto err;
	}
	if (!EC_POINT_mul(ecgroup, point, sig->s, pub_key, t, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ecgroup)) == NID_X9_62_prime_field)
	{
		if (!EC_POINT_get_affine_coordinates_GFp(ecgroup,
			point, X, NULL, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto err;
		}
	}
	else /* NID_X9_62_characteristic_two_field */
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(ecgroup,
			point, X, NULL, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto err;
		}
	}
 	
	sm3_starts(&sm3_ctx);
	sm3_update(&sm3_ctx, Z, SM3_DIGEST_SIZE);
	sm3_update(&sm3_ctx, input, ilen);
	sm3_finish(&sm3_ctx, dgst);

	i = BN_num_bits(order);
	/* Need to truncate digest if it is too long: first truncate whole
	 * bytes.
	 */
	dgst_len = SM3_DIGEST_SIZE;
	if (8 * dgst_len > i)
		dgst_len = (i + 7)/8;
	if (!EC_bin2bn(dgst, dgst_len, m))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}
	/* If still too long truncate remaining bits with a shift */
	if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7)))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}

	/* R = m + X mod order */
	if (!BN_mod_add_quick(R, m, X, order))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}


	/*  if the signature is correct R is equal to sig->r */
	if (BN_ucmp(R, sig->r))
	{

			
		ret = SM2_ERR_BAD_SIGNATURE;
	}
#ifdef _DEBUG
	fprintf(stdout, "\nVerify    R = 0x");
	BNPrintf(R);
	fprintf(stdout, "\n");
#endif	
err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	if (point) EC_POINT_free(point);
#ifdef __KERNEL__
	if (str) kfree(str);
#else
	if (str) free(str);
#endif
	return ret;
}


static int sm2_compute_key(EC_POINT *dhpoint, const EC_GROUP *ecgroup, const BIGNUM *a_pri_key,
	const BIGNUM *a_r, const EC_POINT *b_pub_key, const EC_POINT *Ra, const EC_POINT *Rb)
{
	BN_CTX *ctx;
	EC_POINT *tmp=NULL;
	BIGNUM *x=NULL, *y=NULL, *order=NULL,*z=NULL;
	int ret = SM2_ERR_NOERR;
	int i, j;
	BIGNUM *x1,*x2,*t,*h;

	if ((ctx = BN_CTX_new()) == NULL || (tmp = EC_POINT_new(ecgroup)) == NULL)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto err;
	}
	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	order = BN_CTX_get(ctx);
	z = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	t = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);
	
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ecgroup)) == NID_X9_62_prime_field) 
	{
		if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, Ra, x, NULL, ctx)) 
		{
			ret = SM2_ERR_EC_LIB;
			goto err;
		}
	}
	else
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(ecgroup, Ra, x, NULL, ctx)) 
		{
			ret = SM2_ERR_EC_LIB;
			goto err;
		}
	}
	
	if (!EC_GROUP_get_order(ecgroup, order, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
		
	i = BN_num_bits(order);
	j = i/2 -1;
	BN_mask_bits(x,j);
	BN_set_word(y,2);
	BN_set_word(z,j);
	BN_exp(y,y,z,ctx);
	BN_add(x1,x,y);

	BN_mod_mul(t, x1, a_r, order, ctx);
	BN_mod_add_quick(t, t, a_pri_key, order);
	
	if (!EC_POINT_is_on_curve(ecgroup, Rb, ctx))
	{
		ret = SM2_ERR_DH_FAILED;
		goto err;		
	}

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ecgroup)) == NID_X9_62_prime_field) 
	{
		if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, Rb, x, NULL, ctx)) 
		{
			ret = SM2_ERR_EC_LIB;
			goto err;
		}
	}
	else
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(ecgroup, Rb, x, NULL, ctx)) 
		{
			ret = SM2_ERR_EC_LIB;
			goto err;
		}
	}

	i = BN_num_bits(order);
	j = i/2 -1;
	BN_mask_bits(x,j);
	BN_set_word(y,2);
	BN_set_word(z,j);
	BN_exp(y,y,z,ctx);
	BN_add(x2,x,y);

	//x2*Rb+Pb;
	if (!EC_POINT_mul(ecgroup, tmp, NULL, Rb, x2, ctx) )
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
	if (!EC_POINT_add(ecgroup, dhpoint, b_pub_key, tmp, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, dhpoint, x, y, ctx)) 
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
 	
	if(!EC_GROUP_get_cofactor(ecgroup, h, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}

	//h*t*(x2*Rb+Pb)
	if (!EC_POINT_mul(ecgroup, dhpoint, NULL, dhpoint, t, ctx) ) 
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
	if (EC_POINT_is_at_infinity(ecgroup, dhpoint))
		ret = SM2_ERR_DH_FAILED;
err:
	if (tmp) EC_POINT_free(tmp);
	if (ctx) BN_CTX_end(ctx);
	if (ctx) BN_CTX_free(ctx);
	return ret;
}


static int sm2_do_init(int type, EC_GROUP **ecgroup)
{
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL, *a = NULL, *b = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *P = NULL, *Q = NULL, *R = NULL;
	BIGNUM *x = NULL, *y = NULL, *n = NULL;
	int ret = SM2_ERR_NOERR;
	const char *str_p = NULL, *str_a = NULL, *str_b = NULL, *str_x = NULL, *str_y = NULL, *str_n = NULL;
	unsigned char randbuf[32]={0};
	RAND_seed(randbuf, 32);//XXX, just need for sm2.
	group = EC_GROUP_new(EC_GFp_mont_method()); /* applications should use EC_GROUP_new_curve_GFp
 	                                             * so that the library gets to choose the EC_METHOD */
	if (!group)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}
	
	ctx = BN_CTX_new();
	p = BN_new();
	a = BN_new();
	b = BN_new();
	
	if (!ctx || !p || !a || !b)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}
	
	if (1 != type)
	{
		str_p = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
		str_a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
		str_b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
		str_x = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
		str_y = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
		str_n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
	}
	else
	{
		str_p = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
		str_a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
		str_b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
		str_x = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
		str_y = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
		str_n = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
	}

	if (!BN_hex2bn(&p, str_p))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
	{
		ret = SM2_ERR_INIT_FAILED;
		goto cleanup;
	}
	if (!BN_hex2bn(&a, str_a))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!BN_hex2bn(&b, str_b))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}

	P = EC_POINT_new(group);
	Q = EC_POINT_new(group);
	R = EC_POINT_new(group);
	x = BN_new();
	y = BN_new();
	n = BN_new();
	if (!P || !Q || !R || !x || !y || !n)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}

	if (!BN_hex2bn(&x, str_x))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx)) // Gy最右边的bit为0
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	if (!EC_POINT_is_on_curve(group, P, ctx))
	{
		ret = SM2_ERR_INIT_FAILED;
		goto cleanup;
	}
	if (!BN_hex2bn(&n, str_n))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_GROUP_set_generator(group, P, n, BN_value_one()))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
#ifdef _DEBUG		
	fprintf(stdout, "\nChinese sm2 algorithm test -- Generator:\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf(y);
	fprintf(stdout, "\n");
#endif
	/* G_y value taken from the standard: */
	if (!BN_hex2bn(&n, str_y))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (0 != BN_cmp(y, n))		
	{
		ret = SM2_ERR_INIT_FAILED;
		goto cleanup;
	}
#ifdef _DEBUG	
	fprintf(stdout, "verify degree ...");
#endif
	if (EC_GROUP_get_degree(group) != 256)
	{
		ret = SM2_ERR_INIT_FAILED;
		goto cleanup;
	}
#ifdef _DEBUG
	fprintf(stdout, " ok\n");	
	fprintf(stdout, "verify group order ...");
	fflush(stdout);
#endif
	if (!EC_GROUP_get_order(group, n, ctx) ||
		!EC_GROUP_precompute_mult(group, ctx) ||
		!EC_POINT_mul(group, Q, n, NULL, NULL, ctx) ||
		!EC_POINT_is_at_infinity(group, Q))
	{
		ret = SM2_ERR_INIT_FAILED;
		goto cleanup;
	}
#ifdef _DEBUG
	fprintf(stdout, " ok\n");
#endif

cleanup:
	if (ctx) BN_CTX_free(ctx);
	if (p) BN_free(p);
	if (a) BN_free(a);
	if (b) BN_free(b);
	if (P) EC_POINT_free(P);
	if (Q) EC_POINT_free(Q);
	if (R) EC_POINT_free(R);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (n) BN_free(n);
	if (ret)
		EC_GROUP_free(group);
	else
		*ecgroup = group;
	return ret;
}


static int sm2_do_gen_keypair(int type, const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey)
{
	EC_KEY *eckey = NULL;
	BIGNUM *prikey = NULL, *x = NULL, *y = NULL;
	EC_POINT *pubkey = NULL;
	BN_CTX *ctx = NULL;
	int ret = SM2_ERR_NOERR;
	
	eckey = EC_KEY_new();
	ctx = BN_CTX_new();
	prikey = BN_new();
	pubkey = EC_POINT_new(ecgroup);
	x = BN_new();
	y = BN_new();
	if (!eckey || !ctx || !prikey || !pubkey)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}
	if (!EC_KEY_set_group(eckey, ecgroup))
	{
		EC_KEY_free(eckey);
		return SM2_ERR_BAD_PARAM;
	}

	if (0 == type)
	{
		if (!EC_KEY_generate_key(eckey))
		{
			ret = SM2_ERR_BAD_PARAM;
			goto cleanup;
		}
		if (!BN_copy(prikey, EC_KEY_get0_private_key(eckey)))
		{
			ret = SM2_ERR_BN_LIB;
			goto cleanup;
		}
		if (!EC_POINT_copy(pubkey, EC_KEY_get0_public_key(eckey)))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		}
	}
	else
	{			
		switch (type)
		{
		case 1:
			if (!BN_hex2bn(&prikey, "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263"))
			{
				ret = SM2_ERR_BN_LIB;
				goto cleanup;
			} break;
		case 2:
			if (!BN_hex2bn(&prikey, "6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE"))
			{
				ret = SM2_ERR_BN_LIB;
				goto cleanup;
			} break;
		case 3:
			if (!BN_hex2bn(&prikey, "5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53"))
			{
				ret = SM2_ERR_BN_LIB;
				goto cleanup;
			} break;
		case 4:
			if (!BN_hex2bn(&prikey, "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0"))
			{
				ret = SM2_ERR_BN_LIB;
				goto cleanup;
			} break;
		case 5:
			if (!BN_hex2bn(&prikey, "2995692C1EF25CD0285528CFB8080C13B1DAA224E1BDB1B00C5DFF6F988327DF"))
			{
				ret = SM2_ERR_BN_LIB;
				goto cleanup;
			} break;
		default:
			ret = SM2_ERR_BAD_PARAM;
			goto cleanup;
		}
		if (/*!EC_GROUP_precompute_mult(ecgroup, ctx) || */!EC_POINT_mul(ecgroup, pubkey, prikey, NULL, NULL, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		}
	}
	if (!EC_KEY_set_private_key(eckey, prikey))
	{
		ret = SM2_ERR_PRIVATEKEY;
		goto cleanup;
	}
	if (!EC_KEY_set_public_key(eckey, pubkey))
	{
		ret = SM2_ERR_PUBLICKEY;
		goto cleanup;
	}
	if (!EC_KEY_check_key(eckey))
	{
		ret = SM2_ERR_BAD_PARAM;
		goto cleanup;
	}
	privatekey->bits = 256;
	if (!EC_bn2bin(prikey, privatekey->d))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, pubkey, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	publickey->bits = 256;
	if (!EC_bn2bin(x, publickey->x) || !EC_bn2bin(y, publickey->y))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
#ifdef _DEBUG
    fprintf(stdout, "\n publickey:");
	fprintf(stdout, "\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n");
	fprintf(stdout, "\n     y = 0x");
	BNPrintf(y);
	fprintf(stdout, "\n");
	
	fprintf(stdout, "\n privatekey:");
	fprintf(stdout, "\n     d = 0x");
	BNPrintf(prikey);
	fprintf(stdout, "\n");
#endif
cleanup:
	if (eckey) EC_KEY_free(eckey);
	if (prikey) BN_free(prikey);
	if (pubkey) EC_POINT_free(pubkey);
	if (ctx) BN_CTX_free(ctx);
	if (x) BN_free(x);
	if (y) BN_free(y);
	return ret;
}


static int sm2_do_dh_gen_random(int type, const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE])
{
	int ret = SM2_ERR_NOERR;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL, *k = NULL, *x = NULL, *y = NULL;
	EC_POINT *P = NULL;
	
	ctx = BN_CTX_new();
	order = BN_new();
	k = BN_new();
	P = EC_POINT_new(ecgroup);
	x = BN_new();
	y = BN_new();
	if (!ctx || !order || !k || !P || !x || !y)
	{
		ret = SM2_ERR_NOERR;
		goto cleanup;
	}
	if (!EC_GROUP_get_order(ecgroup, order, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}	
	switch (type) {
	case 0:
		do 
		{
			if (!BN_rand_range(k, order))
			{
				ret = SM2_ERR_BN_LIB;
				goto cleanup;
			}
		} while (BN_is_zero(k));
		break;
	case 1:
		if (!BN_hex2bn(&k, "83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563"))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		} break;
	case 2:
		if (!BN_hex2bn(&k, "33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80"))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		} break;
	default:
		ret = SM2_ERR_BAD_PARAM;
		goto cleanup;
	}
	if (!EC_POINT_mul(ecgroup, P, k, NULL, NULL, ctx) ||
		!EC_POINT_get_affine_coordinates_GFp(ecgroup, P, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	R[0] = POINT_CONVERSION_UNCOMPRESSED;
	if (!EC_bn2bin(k, r) || !EC_bn2bin(x, R + 1) || !EC_bn2bin(y, R + 1 + SM2_BIGNUM_BUFSIZE))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
cleanup:
	if (ctx) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (k) BN_free(k);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (P) EC_POINT_free(P);
	return ret;
}


static int sm2_do_encrypt(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey, const unsigned char *input,
	unsigned int ilen, unsigned char *output, unsigned int *olen, BIGNUM *k_in)
{
	int xylen = 0, ret = SM2_ERR_NOERR;
	unsigned int i = 0;
	unsigned char *t = NULL, *temp = NULL;
	sm3_context sm3_ctx;

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *order = BN_new();
	EC_POINT *C1 = EC_POINT_new(ecgroup);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *h = BN_new();
	EC_POINT *S = EC_POINT_new(ecgroup);
	EC_POINT *pubkey = EC_POINT_new(ecgroup);
	BIGNUM *k = NULL;

	if (NULL == k_in)
		k = BN_new();
	else
		k = k_in;
	if (!ctx || !order || !C1 || !x || !y || !h || !S || !pubkey || !k)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}
	if (!EC_GROUP_get_order(ecgroup, order, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	xylen = EC_GROUP_get_degree(ecgroup) / 8;
	*olen = 1 + 2 * xylen + ilen + 32;
	if (NULL == output)	
		goto cleanup;
	RAND_seed(input, ilen);
	do {
		if (NULL == k_in)
		{
			do {
				if (!BN_rand_range(k, order))
				{
					ret = SM2_ERR_RANDOM_FAILED;
					goto cleanup;
				}
			} while (BN_is_zero(k));
		}
		if (!EC_POINT_mul(ecgroup, C1, k, NULL, NULL, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		}
		if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, C1, x, y, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		}	
		output[0] = POINT_CONVERSION_UNCOMPRESSED;
		if (!EC_bn2bin(x, output + 1))
		{
			ret = SM2_ERR_BN_LIB;
			goto cleanup;
		}
		if (!EC_bn2bin(y, output + 1 + xylen))
		{
			ret = SM2_ERR_BN_LIB;
			goto cleanup;
		}		
		if (!EC_GROUP_get_cofactor(ecgroup, h, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		}
		if (!EC_bin2bn(publickey->x, SM2_BIGNUM_BUFSIZE, x) || !EC_bin2bn((unsigned char *)publickey->y, SM2_BIGNUM_BUFSIZE, y))
		{
			ret = SM2_ERR_BN_LIB;
			goto cleanup;
		}
		if (!EC_POINT_set_affine_coordinates_GFp(ecgroup, pubkey, x, y, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		}
		if (!EC_POINT_mul(ecgroup, S, NULL, pubkey, h, ctx) ||
			EC_POINT_is_at_infinity(ecgroup, S))
		{
			ret = SM2_ERR_PUBLICKEY;
			goto cleanup;
		}
		if (!EC_POINT_mul(ecgroup, S, NULL, pubkey, k, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		}
		if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, S, x, y, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto cleanup;
		}
		if (!temp)
#ifdef __KERNEL__
			temp = (unsigned char *)kmalloc(2 * xylen, GFP_KERNEL);
#else
			temp = (unsigned char *)malloc(2 * xylen);
#endif
		if (!EC_bn2bin(x, temp))
		{
			ret = SM2_ERR_BN_LIB;
			goto cleanup;
		}
		if (!EC_bn2bin(y, temp + xylen))
		{
			ret = SM2_ERR_BN_LIB;
			goto cleanup;
		}
		if (!t)
#ifdef __KERNEL__
			t = (unsigned char *)kmalloc(ilen, GFP_KERNEL);
#else
			t = (unsigned char *)malloc(ilen);
#endif
		memset(t, 0, ilen);
		sm_kdf(temp, 2 * xylen, ilen, t);
		for(i = 0; i < ilen && t[i] == 0; ++i);
	} while(i == ilen);
	output = output + 1 + 2 * xylen;
	for (i = 0; i < ilen; ++i)
		output[i] = input[i] ^ t[i];
	output += ilen;

	sm3_starts(&sm3_ctx);
	sm3_update(&sm3_ctx, temp, xylen);
	sm3_update(&sm3_ctx, input, ilen);
	sm3_update(&sm3_ctx, temp + xylen, xylen);
	sm3_finish(&sm3_ctx, output);

cleanup:
	if (ctx) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (!k_in) BN_free(k);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (h) BN_free(h);
	if (C1) EC_POINT_free(C1);
	if (S) EC_POINT_free(S);
	if (pubkey) EC_POINT_free(pubkey);
#ifdef __KERNEL__
	if (temp) kfree(temp);
	if (t) kfree(t);
#else
	if (temp) free(temp);
	if (t) free(t);
#endif
	return ret;
}


int sm2_dh_key(const EC_GROUP *ecgroup, const unsigned char Za[SM3_DIGEST_SIZE], const unsigned char Zb[SM3_DIGEST_SIZE],
	const SM2_PRIVATE_KEY *a_pri_key, const SM2_PUBLIC_KEY *b_pub_key, const unsigned char a_r[SM2_BIGNUM_BUFSIZE],
	const unsigned char R_b[SM2_ECPOINT_BUFSIZE], unsigned int keylen, unsigned char *outkey)
{
	BN_CTX *ctx = NULL;
	EC_POINT *Ra = NULL, *Rb = NULL;
	BIGNUM *x = NULL, *y = NULL, *r = NULL, *d = NULL;
	int ret = SM2_ERR_NOERR;
	unsigned char *kdf_in = NULL;
	int inlen = 0;
	EC_POINT *dhpoint = NULL, *pubkey = NULL;

	if (POINT_CONVERSION_UNCOMPRESSED != R_b[0])
		return SM2_ERR_BAD_PARAM;

	dhpoint = EC_POINT_new(ecgroup);
	pubkey = EC_POINT_new(ecgroup);
	Ra = EC_POINT_new(ecgroup);
	Rb = EC_POINT_new(ecgroup);
	ctx = BN_CTX_new();
	x = BN_new();
	y = BN_new();
	r = BN_new();
	d = BN_new();
	if (!dhpoint || !pubkey || !Ra || !Rb || !ctx || !x || !y || !r || !d)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto err;
	}
	if (!EC_bin2bn((unsigned char *)a_pri_key->d, SM2_BIGNUM_BUFSIZE, d) ||
		!EC_bin2bn((unsigned char *)b_pub_key->x, SM2_BIGNUM_BUFSIZE, x) ||
		!EC_bin2bn((unsigned char *)b_pub_key->y, SM2_BIGNUM_BUFSIZE, y))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(ecgroup, pubkey, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
	if (!EC_bin2bn((unsigned char *)a_r, SM2_BIGNUM_BUFSIZE, r))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}
	if (!EC_POINT_mul(ecgroup, Ra, r, NULL, NULL, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, Ra, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}
	if (!EC_bin2bn((unsigned char *)R_b + 1, SM2_BIGNUM_BUFSIZE, x))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}
	if (!EC_bin2bn((unsigned char *)R_b + 1 + SM2_BIGNUM_BUFSIZE, SM2_BIGNUM_BUFSIZE, y))
	{
		ret = SM2_ERR_BN_LIB;
		goto err;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(ecgroup, Rb, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto err;
	}

	ret = sm2_compute_key(dhpoint, ecgroup, d, r, pubkey, Ra, Rb);

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ecgroup)) == NID_X9_62_prime_field) 
	{
		if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, dhpoint, x, y, ctx))
		{
			ret = SM2_ERR_EC_LIB;
			goto err;
		}
	}
	else
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(ecgroup,dhpoint, x, y, ctx)) 
		{
			ret = SM2_ERR_EC_LIB;
			goto err;
		}
	}

#ifdef _DEBUG
	fprintf(stdout, "\nTesting DH Point\n     Xv = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     Yv = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
#endif
	
	inlen = EC_GROUP_get_degree(ecgroup) / 8;
#ifdef __KERNEL__
	kdf_in = (unsigned char *)kmalloc(2 * (inlen + SM3_DIGEST_SIZE), GFP_KERNEL);
#else
	kdf_in = (unsigned char *)malloc(2 * (inlen + SM3_DIGEST_SIZE));
#endif
	EC_bn2bin(x, kdf_in);
	EC_bn2bin(y, kdf_in + inlen);
	memcpy(kdf_in + 2 * inlen, Za, SM3_DIGEST_SIZE);
	memcpy(kdf_in + 2 * inlen + SM3_DIGEST_SIZE, Zb, SM3_DIGEST_SIZE);

	sm_kdf(kdf_in, 2 * (inlen + SM3_DIGEST_SIZE), keylen, outkey);

err:
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (r) BN_free(r);
	if (Ra) EC_POINT_free(Ra);
	if (Rb) EC_POINT_free(Rb);
	if (pubkey) EC_POINT_free(pubkey);
	if (dhpoint) EC_POINT_free(dhpoint);
	if (ctx) BN_CTX_free(ctx);

	return ret;
}


int sm2_init(EC_GROUP **ecgroup)
{
	return sm2_do_init(0, ecgroup);
}


int sm2_init_standard(EC_GROUP **ecgroup)
{
	return sm2_do_init(1, ecgroup);
}


int sm2_gen_keypair(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey)
{
	return sm2_do_gen_keypair(0, ecgroup, privatekey, publickey);
}


int sm2_gen_keypair_standard1(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey)
{
	return sm2_do_gen_keypair(1, ecgroup, privatekey, publickey);
}


int sm2_gen_keypair_standard2_a(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey)
{
	return sm2_do_gen_keypair(2, ecgroup, privatekey, publickey);
}


int sm2_gen_keypair_standard2_b(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey)
{
	return sm2_do_gen_keypair(3, ecgroup, privatekey, publickey);
}


int sm2_gen_keypair_standard3(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey)
{
	return sm2_do_gen_keypair(4, ecgroup, privatekey, publickey);
}

int sm2_gen_keypair_standard5(const EC_GROUP *ecgroup, SM2_PRIVATE_KEY *privatekey, SM2_PUBLIC_KEY *publickey)
{
	return sm2_do_gen_keypair(5, ecgroup, privatekey, publickey);
}

void sm2_cleanup(EC_GROUP *ecgroup)
{
	if (ecgroup) EC_GROUP_free(ecgroup);
	ecgroup=NULL;
}


int sm2_encrypt(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey,
	const unsigned char *input, unsigned int ilen, unsigned char *output, unsigned int *olen)
{
	return sm2_do_encrypt(ecgroup, publickey, input, ilen, output, olen, NULL);
}


int sm2_encrypt_standard(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey,
	const unsigned char *input, unsigned int ilen, unsigned char *output, unsigned int *olen)
{
	int ret = SM2_ERR_NOERR;
	BIGNUM *k = BN_new();
	if (!k)
		return SM2_ERR_MALLOC_FAILED;
	if (!BN_hex2bn(&k, "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"))
	{
		BN_free(k);
		return SM2_ERR_BN_LIB;
	}
	ret = sm2_do_encrypt(ecgroup, publickey, input, ilen, output, olen, k);
	BN_free(k);
	return ret;
}


int sm2_decrypt(const EC_GROUP *ecgroup, const SM2_PRIVATE_KEY *privatekey,
	const unsigned char *input, unsigned int ilen, unsigned char *output, unsigned int *olen)
{
	int xylen = 0, ret = SM2_ERR_NOERR;
	unsigned int i = 0;
	unsigned char *t = NULL, *temp = NULL;
	sm3_context sm3_ctx;
	unsigned char u[SM3_DIGEST_SIZE] = {0};

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *order = BN_new();
	BIGNUM *k = BN_new();
	EC_POINT *C1 = EC_POINT_new(ecgroup);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *h = BN_new();
	BIGNUM *d = BN_new();
	EC_POINT *S = EC_POINT_new(ecgroup);

	if (POINT_CONVERSION_UNCOMPRESSED != input[0]) // 只处理非压缩数据
	{
		ret = SM2_ERR_BAD_PARAM;
		printf("decrypt uncomp error. \n");
		goto cleanup;
	}
	if (!ctx || !order || !k || !C1 || !x || !y || !h || !S || !d)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}	
	xylen = EC_GROUP_get_degree(ecgroup) / 8;
	*olen = ilen - 1 - 2 * xylen - 32;
	if (NULL == output)	
		goto cleanup;

	if (!EC_bin2bn((unsigned char *)input + 1, xylen, x))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_bin2bn((unsigned char *)input + 1 + xylen, xylen, y))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	
	if (!EC_POINT_set_affine_coordinates_GFp(ecgroup, C1, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	if (!EC_POINT_is_on_curve(ecgroup, C1, ctx))
	{
		ret = SM2_ERR_DECRYPT;
		goto cleanup;
	}
	if (!EC_GROUP_get_cofactor(ecgroup, h, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	if (!EC_POINT_mul(ecgroup, S, NULL, C1, h, ctx) ||
		EC_POINT_is_at_infinity(ecgroup, S))
	{
		ret = SM2_ERR_DECRYPT;
		goto cleanup;
	}
	if (!EC_bin2bn((unsigned char *)privatekey->d, SM2_BIGNUM_BUFSIZE, d))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_POINT_mul(ecgroup, S, NULL, C1, d, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, S, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	if (!temp)
#ifdef __KERNEL__
		temp = (unsigned char *)kmalloc(2 * xylen, GFP_KERNEL);
#else
		temp = (unsigned char *)malloc(2 * xylen);
#endif
	if (!EC_bn2bin(x, temp))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_bn2bin(y, temp + xylen))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!t)
#ifdef __KERNEL__
		t = (unsigned char *)kmalloc(*olen, GFP_KERNEL);
#else
		t = (unsigned char *)malloc(*olen);
#endif
	memset(t, 0, *olen);
	sm_kdf(temp, 2 * xylen, *olen, t);
	for(i = 0; i < ilen && t[i] == 0; ++i);
	if (i == ilen)
	{
		ret = SM2_ERR_DECRYPT;
		goto cleanup;
	}
	input = input + 1 + 2 * xylen;
	for (i = 0; i < *olen; ++i)
		output[i] = input[i] ^ t[i];
	input += *olen;
	sm3_starts(&sm3_ctx);
	sm3_update(&sm3_ctx, temp, xylen);
	sm3_update(&sm3_ctx, output, *olen);
	sm3_update(&sm3_ctx, temp + xylen, xylen);
	sm3_finish(&sm3_ctx, u);
	if (memcmp(u, input, 32))
		ret = SM2_ERR_DECRYPT;
cleanup:
	if (ctx) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (k) BN_free(k);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (h) BN_free(h);
	if (C1) EC_POINT_free(C1);
	if (S) EC_POINT_free(S);
	if (d) BN_free(d);
#ifdef __KERNEL__
	if (temp) kfree(temp);
	if (t) kfree(t);
#else
	if (temp) free(temp);
	if (t) free(t);
#endif
	return ret;
}


/** sm2_sign
 * computes ECDSA signature of a given hash value using the supplied
 * private key (note: sig must point to ECDSA_size(eckey) bytes of memory).
 * \param type this parameter is ignored
 * \param input pointer to the message to sign
 * \param ilen length of the message
 * \param output buffer to hold the DER encoded signature
 * \param olen pointer to the length of the returned signature
 * \param k optional pointer to a pre-computed inverse k
 * \param rp optional pointer to the pre-computed rp value (see 
 *        ECDSA_sign_setup
 * \param eckey pointer to the EC_KEY object containing a private EC key
 */
int sm2_sign(const EC_GROUP *ecgroup, const SM2_PRIVATE_KEY *privatekey, const unsigned char Z[SM3_DIGEST_SIZE],
	const unsigned char *input, unsigned int ilen, SM2_SIGNATURE *output)
{
	int ret = SM2_ERR_NOERR;
	ECDSA_SIG *signature = NULL;
	BIGNUM *d = BN_new();

	if (!d)
		return SM2_ERR_MALLOC_FAILED;
	if (!EC_bin2bn((unsigned char *)privatekey->d, SM2_BIGNUM_BUFSIZE, d))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	signature = ECDSA_SIG_new();
	if (!signature)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}

	RAND_seed(input, ilen);
	ret = sm2_do_sign(ecgroup, d, Z, input, ilen, signature, NULL, NULL);
	if (SM2_ERR_NOERR == ret)
	{
		//printf ("ECSign OK\n     r = 0x");
		//BNPrintf(signature->r);
		//printf("\n     s = 0x");
		//BNPrintf(signature->s);
		//printf("\n");
		if (!EC_bn2bin(signature->r, output->r) || !EC_bn2bin(signature->s, output->s))
			ret = SM2_ERR_BN_LIB;
	}

cleanup:
	if (d) BN_free(d);
	if (signature) ECDSA_SIG_free(signature);	
	return ret;
}

int sm2_sign_standard(const EC_GROUP *ecgroup, const SM2_PRIVATE_KEY *privatekey, const unsigned char Z[SM3_DIGEST_SIZE],
	const unsigned char *input, unsigned int ilen, SM2_SIGNATURE *output)
{
	int ret = SM2_ERR_NOERR;
	ECDSA_SIG *signature = NULL;
	BIGNUM *rp = NULL, *kinv = NULL, *order = NULL, *x = NULL, *y = NULL, *d = NULL;
	EC_POINT *Q = NULL;
	BN_CTX *ctx = NULL;
//	int degree = 0;
//	unsigned char *str = NULL;
//	const EC_POINT *pPoint = NULL;

	if ((d = BN_new()) == NULL)
		return SM2_ERR_MALLOC_FAILED;
	if (!EC_bin2bn((unsigned char *)privatekey->d, SM2_BIGNUM_BUFSIZE, d))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	signature = ECDSA_SIG_new();
	if (!signature)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}

	ctx = BN_CTX_new();
	rp    = BN_new();
	kinv  = BN_new();
	order = BN_new();
	x = BN_new();
	y = BN_new();
	Q = EC_POINT_new(ecgroup);

	if (!ctx || !rp || !kinv || !Q)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}	

	if (!BN_hex2bn(&kinv, "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_POINT_mul(ecgroup, Q, kinv, NULL, NULL, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, Q, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
#ifdef _DEBUG
	fprintf(stdout, "\nTesting K Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
#endif	

	EC_GROUP_get_order(ecgroup, order, ctx);
	if (!BN_nnmod(rp, x, order, ctx))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}

	ret = sm2_do_sign(ecgroup, d, Z, input, ilen, signature, kinv, rp);
	if (SM2_ERR_NOERR == ret)
	{
		printf ("ECSign OK\n     r = 0x");
		BNPrintf(signature->r);
		printf("\n     s = 0x");
		BNPrintf(signature->s);
		printf("\n");
		if (!EC_bn2bin(signature->r, output->r) || !EC_bn2bin(signature->s, output->s))
			ret = SM2_ERR_BN_LIB;
	}

cleanup:
	if (d) BN_free(d);
	if (signature) ECDSA_SIG_free(signature);	
	if (rp) BN_free(rp);
	if (kinv) BN_free(kinv);
	if (order) BN_free(order);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (Q) EC_POINT_free(Q);
	if (ctx) BN_CTX_free(ctx);
	return ret;
}


int sm2_verify(const EC_GROUP *ecgroup, const SM2_PUBLIC_KEY *publickey, const unsigned char Z[SM2_BIGNUM_BUFSIZE],
	const unsigned char *input, unsigned int ilen, const SM2_SIGNATURE *signature)
{
	int ret = SM2_ERR_NOERR;
	ECDSA_SIG *sig = ECDSA_SIG_new();
	EC_POINT *pubkey = EC_POINT_new(ecgroup);
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

	if (!signature || !pubkey || !x || !y)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}
	if (!EC_bin2bn(signature->r, SM2_BIGNUM_BUFSIZE, sig->r) || !EC_bin2bn(signature->s, SM2_BIGNUM_BUFSIZE, sig->s))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_bin2bn(publickey->x, SM2_BIGNUM_BUFSIZE, x) || !EC_bin2bn(publickey->y, SM2_BIGNUM_BUFSIZE, y))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	if (!EC_POINT_set_affine_coordinates_GFp(ecgroup, pubkey, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	ret = sm2_do_verify(ecgroup, pubkey, Z, input, ilen, sig);

cleanup:
	if (sig) ECDSA_SIG_free(sig);
	if (pubkey) EC_POINT_free(pubkey);
	if (ctx) BN_CTX_free(ctx);
	if (x) BN_free(x);
	if (y) BN_free(y);
	return ret;
}

int sm_gen_random(unsigned int len, unsigned char *output)
{
	time_t tm = time(NULL);
	RAND_seed((const void *)&tm, sizeof(time_t));
	return RAND_bytes(output, len);
}


int sm2_dh_gen_random(const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE])
{
	return sm2_do_dh_gen_random(0, ecgroup, r, R);
}


int sm2_dh_gen_random_standard_a(const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE])
{
	return sm2_do_dh_gen_random(1, ecgroup, r, R);
}


int sm2_dh_gen_random_standard_b(const EC_GROUP *ecgroup, unsigned char r[SM2_BIGNUM_BUFSIZE], unsigned char R[SM2_ECPOINT_BUFSIZE])
{
	return sm2_do_dh_gen_random(2, ecgroup, r, R);
}


void sm_kdf(const unsigned char *share, unsigned int sharelen, unsigned int keylen, unsigned char *outkey)
{
	sm3_context ctx;
	unsigned char dgst[SM3_DIGEST_SIZE] = {0};
	int rlen = (int)keylen;
	unsigned int ct = 1;
	unsigned char *pp = outkey;
	unsigned char str_ct[4] = {0};

	while (rlen > 0)
	{
		sm3_starts(&ctx);
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


int sm2_Z(const EC_GROUP *ecgroup, const unsigned char *ID, unsigned short idlen,
	const SM2_PUBLIC_KEY *publickey, unsigned char dgst[SM3_DIGEST_SIZE])
{
	sm3_context sm3_ctx;
	BN_CTX *ctx = NULL;
	BIGNUM *x = NULL, *y = NULL;
	const EC_POINT *pPoint = NULL;
	unsigned char str_idlen[2] = {0};
	int ret = SM2_ERR_NOERR;
	int degree = 0;
	unsigned char *str = NULL;

	ctx = BN_CTX_new();
	x = BN_new();
	y = BN_new();

	if (!ctx || !x || !y)
	{
		ret = SM2_ERR_MALLOC_FAILED;
		goto cleanup;
	}

	sm3_starts(&sm3_ctx);
	str_idlen[0] = idlen >> 8;
	str_idlen[1] = idlen;
	sm3_update(&sm3_ctx, (const unsigned char *)str_idlen, 2);
	sm3_update(&sm3_ctx, (const unsigned char *)ID, idlen / 8);				

	if (!EC_GROUP_get_curve_GFp(ecgroup, NULL, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	degree = EC_GROUP_get_degree(ecgroup) / 8;
#ifdef __KERNEL__
	str = (unsigned char *)kmalloc(degree, GFP_KERNEL);
#else
	str = (unsigned char *)malloc(degree);
#endif
	if (!EC_bn2bin(x, str))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	sm3_update(&sm3_ctx, str, degree);
	if (!EC_bn2bin(y, str))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	sm3_update(&sm3_ctx, str, degree);
	pPoint = EC_GROUP_get0_generator(ecgroup);
	if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, pPoint, x, y, ctx))
	{
		ret = SM2_ERR_EC_LIB;
		goto cleanup;
	}
	if (!EC_bn2bin(x, str))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	sm3_update(&sm3_ctx, str, degree);
	if (!EC_bn2bin(y, str))
	{
		ret = SM2_ERR_BN_LIB;
		goto cleanup;
	}
	sm3_update(&sm3_ctx, str, degree);
	sm3_update(&sm3_ctx, publickey->x, degree);
	sm3_update(&sm3_ctx, publickey->y, degree);
	sm3_finish(&sm3_ctx, dgst);
	
#ifdef _DEBUG		
{
	BIGNUM *tmp=BN_new();
	fprintf(stdout, "\n     z = 0x");
	EC_bin2bn(dgst,SM3_DIGEST_SIZE, tmp );
	BNPrintf(tmp);
	fprintf(stdout, "\n");
	if (tmp) BN_free(tmp);
}
#endif

cleanup:
	if (ctx) BN_CTX_free(ctx);
	if (x) BN_free(x);
	if (y) BN_free(y);
#ifdef __KERNEL__
	if (str) kfree(str);
#else
	if (str) free(str);
#endif

	return ret;
}

void *sm2_malloc(size_t size,  const char *file, int line)
{
    return CRYPTO_malloc((int)size, file, line);
}

void sm2_free(void *ptr,  const char *file, int line)
{
    return CRYPTO_free(ptr);
}






