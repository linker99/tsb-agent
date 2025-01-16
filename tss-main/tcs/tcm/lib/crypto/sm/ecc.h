#ifndef _ECC_H_
#define _ECC_H_

#include <stdint.h>

#define ECC_WORDSIZE 8
#define ECC_NUMBITS 256
#define ECC_NUMWORD (ECC_NUMBITS/ECC_WORDSIZE) //3

#define SWAP(a,b) { uint32_t t = a; a = b; b = t;}

#define digit2str16(x, y)   {                               \
	        (y)[0] = (uint8_t)((x >> 8 ) & 0x000000FF);      \
	        (y)[1] = (uint8_t)((x >> 0 ) & 0x000000FF);      \
}

#define str2digit16(y, x)    {                                  \
	        x = ((((u16)(y)[0]) & 0x000000FF) << 8)  |  \
	            ((((u16)(y)[1]) & 0x000000FF) << 0 );   \
}

#define digit2str32(x, y)   {                               \
	        (y)[0] = (uint8_t)((x >> 24) & 0x000000FF);      \
	        (y)[1] = (uint8_t)((x >> 16) & 0x000000FF);      \
	        (y)[2] = (uint8_t)((x >> 8 ) & 0x000000FF);      \
	        (y)[3] = (uint8_t)((x >> 0 ) & 0x000000FF);      \
}

#define str2digit32(y, x)    {                                   \
	        x = ((((uint32_t)(y)[0]) & 0x000000FF) << 24)  |  \
	            ((((uint32_t)(y)[1]) & 0x000000FF) << 16)  |  \
	            ((((uint32_t)(y)[2]) & 0x000000FF) << 8 )  |  \
	            ((((uint32_t)(y)[3]) & 0x000000FF) << 0 );    \
}

typedef struct ecc_point
{
    uint8_t x[ECC_NUMWORD];
    uint8_t y[ECC_NUMWORD];
} ecc_point;

struct ecc_curve {
	struct ecc_point g;
	uint8_t p[ECC_NUMWORD];
	uint8_t n[ECC_NUMWORD];
	uint8_t h[ECC_NUMWORD];
	uint8_t a[ECC_NUMWORD];
	uint8_t b[ECC_NUMWORD];
};

void ecc_point_add(ecc_point *result, ecc_point *x, ecc_point *y);
void ecc_point_mult(ecc_point *result, ecc_point *point, uint8_t *scalar, uint8_t *initialZ);
void ecc_point_mult2(ecc_point *result, ecc_point *g, ecc_point *p, uint8_t *s, uint8_t *t);
int ecc_point_is_zero(ecc_point *point);


void vli_clear(uint8_t *vli);

int vli_is_zero(uint8_t *vli);

uint8_t vli_test_bit(uint8_t *vli, uint32_t bit);

uint32_t vli_num_digits(uint8_t *vli);

uint32_t vli_num_bits(uint8_t *vli);

void vli_set(uint8_t *dest, uint8_t *src);

int vli_cmp(uint8_t *left, uint8_t *right);

uint8_t vli_lshift(uint8_t *result, uint8_t *in, uint32_t shift);

void vli_rshift1(uint8_t *vli);

uint8_t vli_add(uint8_t *result, uint8_t *left, uint8_t *right);

uint8_t vli_sub(uint8_t *result, uint8_t *left, uint8_t *right);

void vli_mmod_fast(uint8_t *result, uint8_t *product, uint8_t* mod);

void vli_mult(uint8_t *result, uint8_t *left, uint8_t *right);

void vli_square(uint8_t *result, uint8_t *left);

void vli_mod_add(uint8_t *result, uint8_t *left, uint8_t *right, uint8_t *mod);

void vli_mod_sub(uint8_t *result, uint8_t *left, uint8_t *right, uint8_t *mod);

void vli_mod_mult_fast(uint8_t *result, uint8_t *left, uint8_t *right, uint8_t *mod);

void vli_mod_square_fast(uint8_t *result, uint8_t *left, uint8_t *mod);

void vli_mod_mult(uint8_t *result, uint8_t *left, uint8_t *right, uint8_t *mod);

void vli_mod_inv(uint8_t *result, uint8_t *input, uint8_t *mod);


#endif
