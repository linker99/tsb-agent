#ifndef _ECC_H_
#define _ECC_H_



#define ECC_WORDSIZE 8
#define ECC_NUMBITS 256
#define ECC_NUMWORD (ECC_NUMBITS/ECC_WORDSIZE) //3

#define SWAP(a,b) { u32 t = a; a = b; b = t;}

#define digit2str16(x, y)   {                               \
	        (y)[0] = (u8)((x >> 8 ) & 0x000000FF);      \
	        (y)[1] = (u8)((x >> 0 ) & 0x000000FF);      \
}

#define str2digit16(y, x)    {                                  \
	        x = ((((u16)(y)[0]) & 0x000000FF) << 8)  |  \
	            ((((u16)(y)[1]) & 0x000000FF) << 0 );   \
}

#define digit2str32(x, y)   {                               \
	        (y)[0] = (u8)((x >> 24) & 0x000000FF);      \
	        (y)[1] = (u8)((x >> 16) & 0x000000FF);      \
	        (y)[2] = (u8)((x >> 8 ) & 0x000000FF);      \
	        (y)[3] = (u8)((x >> 0 ) & 0x000000FF);      \
}

#define str2digit32(y, x)    {                                   \
	        x = ((((u32)(y)[0]) & 0x000000FF) << 24)  |  \
	            ((((u32)(y)[1]) & 0x000000FF) << 16)  |  \
	            ((((u32)(y)[2]) & 0x000000FF) << 8 )  |  \
	            ((((u32)(y)[3]) & 0x000000FF) << 0 );    \
}

typedef struct ecc_point
{
    u8 x[ECC_NUMWORD];
    u8 y[ECC_NUMWORD];
} ecc_point;

struct ecc_curve {
	struct ecc_point g;
	u8 p[ECC_NUMWORD];
	u8 n[ECC_NUMWORD];
	u8 h[ECC_NUMWORD];
	u8 a[ECC_NUMWORD];
	u8 b[ECC_NUMWORD];
};

void ecc_point_add(ecc_point *result, ecc_point *x, ecc_point *y);
void ecc_point_mult(ecc_point *result, ecc_point *point, u8 *scalar, u8 *initialZ);
void ecc_point_mult2(ecc_point *result, ecc_point *g, ecc_point *p, u8 *s, u8 *t);
int ecc_point_is_zero(ecc_point *point);


void vli_clear(u8 *vli);

int vli_is_zero(u8 *vli);

u8 vli_test_bit(u8 *vli, u32 bit);

u32 vli_num_digits(u8 *vli);

u32 vli_num_bits(u8 *vli);

void vli_set(u8 *dest, u8 *src);

int vli_cmp(u8 *left, u8 *right);

u8 vli_lshift(u8 *result, u8 *in, u32 shift);

void vli_rshift1(u8 *vli);

u8 vli_add(u8 *result, u8 *left, u8 *right);

u8 vli_sub(u8 *result, u8 *left, u8 *right);

void vli_mmod_fast(u8 *result, u8 *product, u8* mod);

void vli_mult(u8 *result, u8 *left, u8 *right);

void vli_square(u8 *result, u8 *left);

void vli_mod_add(u8 *result, u8 *left, u8 *right, u8 *mod);

void vli_mod_sub(u8 *result, u8 *left, u8 *right, u8 *mod);

void vli_mod_mult_fast(u8 *result, u8 *left, u8 *right, u8 *mod);

void vli_mod_square_fast(u8 *result, u8 *left, u8 *mod);

void vli_mod_mult(u8 *result, u8 *left, u8 *right, u8 *mod);

void vli_mod_inv(u8 *result, u8 *input, u8 *mod);


#endif
