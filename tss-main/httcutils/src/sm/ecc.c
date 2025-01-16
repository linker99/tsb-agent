#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ecc.h"

extern struct ecc_curve ecc_curve;


void vli_clear(uint8_t *vli)
{
	int i;

	for (i = 0; i < ECC_NUMWORD; ++i) {
		vli[i] = 0;
	}
}

int vli_is_zero(uint8_t *vli)
{
	int i;

	for (i = 0; i < ECC_NUMWORD; ++i) {
		if (vli[i])
			return 0;
	}

	return 1;
}

uint8_t vli_test_bit(uint8_t *vli, uint32_t bit)
{
	return (vli[bit/8] & ((uint8_t)1 << (bit % 8)));
}

uint32_t vli_num_digits(uint8_t *vli)
{
	int i;
	for (i = ECC_NUMWORD - 1; i >= 0 && vli[i] == 0; --i);

	return (i + 1);
}

uint32_t vli_num_bits(uint8_t *vli)
{
	uint32_t i, num_digits;
	uint8_t digit;

	num_digits = vli_num_digits(vli);
	if (num_digits == 0)
		return 0;

	digit = vli[num_digits - 1];
	for (i = 0; digit; ++i)
		digit >>= 1;

	return ((num_digits - 1) * 8 + i);
}

void vli_set(uint8_t *dest, uint8_t *src)
{
	uint32_t i;

	for (i = 0; i < ECC_NUMWORD; ++i)
		dest[i] = src[i];
}

int vli_cmp(uint8_t *left, uint8_t *right)
{
	int i;

	for (i = ECC_NUMWORD - 1; i >= 0; --i) {
		if (left[i] > right[i])
			return 1;
		else if (left[i] < right[i])
			return -1;
	}
	return 0;
}

uint8_t vli_lshift(uint8_t *result, uint8_t *in, uint32_t shift)
{
	uint8_t carry = 0;
	int i;

	for (i = 0; i < ECC_NUMWORD; ++i) {
		uint8_t temp = in[i];
		result[i] = (temp << shift) | carry;
		carry = temp >> (8 - shift);
	}

	return carry;
}

void vli_rshift1(uint8_t *vli)
{
	uint8_t *end = vli;
	uint8_t carry = 0;

	vli += ECC_NUMWORD;
	while (vli-- > end)
	{
		uint8_t temp = *vli;
		*vli = (temp >> 1) | carry;
		carry = temp << 7;
	}
}

uint8_t vli_add(uint8_t *result, uint8_t *left, uint8_t *right)
{
	uint8_t carry = 0;
	uint32_t i;

	for(i=0; i<ECC_NUMWORD; ++i){
		uint8_t sum;

		sum = left[i] + right[i] + carry;
		if (sum != left[i]) {
			carry = (sum < left[i]);
		}
		result[i] = sum;
	}

	return carry;
}

uint8_t vli_sub(uint8_t *result, uint8_t *left, uint8_t *right)
{
	uint8_t borrow = 0;
	int i;

	for (i = 0; i < ECC_NUMWORD; ++i) {
		uint8_t diff;

		diff = left[i] - right[i] - borrow;
		if (diff != left[i])
			borrow = (diff > left[i]);

		result[i] = diff;
	}

	return borrow;
}

void vli_mult(uint8_t *result, uint8_t *left, uint8_t *right)
{
	uint16_t r01 = 0;
	uint8_t r2 = 0;
	int i, k;

	for (k = 0; k < ECC_NUMWORD*2 - 1; ++k) {
		int min = (k < ECC_NUMWORD ? 0 : (k + 1) - ECC_NUMWORD);
		for (i = min; i <= k && i < ECC_NUMWORD; ++i) {
			uint16_t product = (uint16_t)left[i] * right[k-i];
			r01 = r01 + product;
			r2 += (r01 < product);
		}
		result[k] = (uint8_t)r01;
		r01 = (r01 >> 8) | (((uint16_t)r2) << 8);
		r2 = 0;
	}

	result[ECC_NUMWORD*2 - 1] = (uint8_t)r01;
}

void vli_square(uint8_t *result, uint8_t *left)
{
	uint16_t r01 = 0;
	uint8_t r2 = 0;
	int i, k;

	for (k = 0; k < ECC_NUMWORD*2 - 1; ++k) {
		uint32_t min = (k < ECC_NUMWORD ? 0 : (k + 1) - ECC_NUMWORD);
		for (i = min; i <= k && i <= k - i; ++i) {
			uint16_t product = (uint16_t)left[i] * left[k-i];
			if (i < k - i) {
				r2 += product >> 15;
				product *= 2;
			}
			r01 += product;
			r2 += (r01 < product);
		}
		result[k] = (uint8_t)r01;
		r01 = (r01 >> 8) | (((uint16_t)r2) << 8);
		r2 = 0;
	}

	result[ECC_NUMWORD*2 - 1] = (uint8_t)r01;
}

void vli_mod_add(uint8_t *result, uint8_t *left, uint8_t *right, uint8_t *mod)
{
	uint8_t carry;

	carry = vli_add(result, left, right);

	if(carry || vli_cmp(result, mod) >= 0) {
		vli_sub(result, result, mod);
	}
}

void vli_mod_sub(uint8_t *result, uint8_t *left, uint8_t *right, uint8_t *mod)
{
	uint8_t borrow;

	borrow = vli_sub(result, left, right);
	if(borrow)
		vli_add(result, result, mod);
}

void vli_mmod_fast(uint8_t *result, uint8_t *product, uint8_t* mod)
{
	uint8_t tmp1[ECC_NUMWORD];
	uint8_t tmp2[ECC_NUMWORD];
	uint8_t tmp3[ECC_NUMWORD];
	int carry = 0;

	vli_set(result, product);
	vli_clear(tmp1);
	vli_clear(tmp2);
	vli_clear(tmp3);

	tmp1[0] = tmp1[12] = tmp1[28] = product[32];
	tmp1[1] = tmp1[13] = tmp1[29] = product[33];
	tmp1[2] = tmp1[14] = tmp1[30] = product[34];
	tmp1[3] = tmp1[15] = tmp1[31] = product[35];
	tmp2[8] = product[32];
	tmp2[9] = product[33];
	tmp2[10] = product[34];
	tmp2[11] = product[35];
	carry += vli_add(result, result, tmp1);
	carry -= vli_sub(result, result, tmp2);

	tmp1[0] = tmp1[4] = tmp1[16] = tmp1[28] = product[36];
	tmp1[1] = tmp1[5] = tmp1[17] = tmp1[29] = product[37];
	tmp1[2] = tmp1[6] = tmp1[18] = tmp1[30] = product[38];
	tmp1[3] = tmp1[7] = tmp1[19] = tmp1[31] = product[39];
	tmp1[12] = tmp1[13] = tmp1[14] = tmp1[15] = 0;
	tmp2[8] = product[36];
	tmp2[9] = product[37];
	tmp2[10] = product[38];
	tmp2[11] = product[39];
	carry += vli_add(result, result, tmp1);
	carry -= vli_sub(result, result, tmp2);

	tmp1[0] = tmp1[4] = tmp1[20] = tmp1[28] = product[40];
	tmp1[1] = tmp1[5] = tmp1[21] = tmp1[29] = product[41];
	tmp1[2] = tmp1[6] = tmp1[22] = tmp1[30] = product[42];
	tmp1[3] = tmp1[7] = tmp1[23] = tmp1[31] = product[43];
	tmp1[16] = tmp1[17] = tmp1[18] = tmp1[19] = 0;
	carry += vli_add(result, result, tmp1);

	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[24] = tmp1[28] = product[44];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[25] = tmp1[29] = product[45];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[26] = tmp1[30] = product[46];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[27] = tmp1[31] = product[47];
	tmp1[20] = tmp1[21] = tmp1[22] = tmp1[23] = 0;
	carry += vli_add(result, result, tmp1);

	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[16] = tmp1[28] = tmp3[28] = product[48];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[17] = tmp1[29] = tmp3[29] = product[49];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[18] = tmp1[30] = tmp3[30] = product[50];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[19] = tmp1[31] = tmp3[31] = product[51];
	tmp1[24] = tmp1[25] = tmp1[26] = tmp1[27] = 0;
	carry += vli_add(result, result, tmp1);
	carry += vli_add(result, result, tmp3);

	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[16] = tmp1[20] = tmp1[28] = product[52];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[17] = tmp1[21] = tmp1[29] = product[53];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[18] = tmp1[22] = tmp1[30] = product[54];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[19] = tmp1[23] = tmp1[31] = product[55];
	tmp2[8] = product[52];
	tmp2[9] = product[53];
	tmp2[10] = product[54];
	tmp2[11] = product[55];
	tmp3[0] = tmp3[12] = tmp3[28] = product[52];
	tmp3[1] = tmp3[13] = tmp3[29] = product[53];
	tmp3[2] = tmp3[14] = tmp3[30] = product[54];
	tmp3[3] = tmp3[15] = tmp3[31] = product[55];
	carry += vli_add(result, result, tmp1);
	carry += vli_add(result, result, tmp3);
	carry -= vli_sub(result, result, tmp2);

	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[16] = tmp1[20] = tmp1[24] = tmp1[28] = product[56];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[17] = tmp1[21] = tmp1[25] = tmp1[29] = product[57];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[18] = tmp1[22] = tmp1[26] = tmp1[30] = product[58];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[19] = tmp1[23] = tmp1[27] = tmp1[31] = product[59];
	tmp2[8] = product[56];
	tmp2[9] = product[57];
	tmp2[10] = product[58];
	tmp2[11] = product[59];
	tmp3[0] = tmp3[4] = tmp3[16] = tmp3[28] = product[56];
	tmp3[1] = tmp3[5] = tmp3[17] = tmp3[29] = product[57];
	tmp3[2] = tmp3[6] = tmp3[18] = tmp3[30] = product[58];
	tmp3[3] = tmp3[7] = tmp3[19] = tmp3[31] = product[59];
	tmp3[12] = tmp3[13] = tmp3[14] = tmp3[15] = 0;
	carry += vli_add(result, result, tmp1);
	carry += vli_add(result, result, tmp3);
	carry -= vli_sub(result, result, tmp2);

	tmp1[0] = tmp1[4] = tmp1[12] = tmp1[16] = tmp1[20] = tmp1[24] = tmp1[28] = product[60];
	tmp1[1] = tmp1[5] = tmp1[13] = tmp1[17] = tmp1[21] = tmp1[25] = tmp1[29] = product[61];
	tmp1[2] = tmp1[6] = tmp1[14] = tmp1[18] = tmp1[22] = tmp1[26] = tmp1[30] = product[62];
	tmp1[3] = tmp1[7] = tmp1[15] = tmp1[19] = tmp1[23] = tmp1[27] = tmp1[31] = product[63];
	tmp3[0] = tmp3[4] = tmp3[20]  = product[60];
	tmp3[1] = tmp3[5] = tmp3[21]  = product[61];
	tmp3[2] = tmp3[6] = tmp3[22]  = product[62];
	tmp3[3] = tmp3[7] = tmp3[23]  = product[63];
	tmp3[16] = tmp3[17] = tmp3[18] = tmp3[19] = tmp3[28] = tmp3[29] = tmp3[30] = tmp3[31] = 0;
	tmp2[28] = product[60];
	tmp2[29] = product[61];
	tmp2[30] = product[62];
	tmp2[31] = product[63];
	tmp2[8] = tmp2[9] = tmp2[10] = tmp2[11] = 0;
	carry += vli_lshift(tmp2, tmp2, 1);
	carry += vli_add(result, result, tmp1);
	carry += vli_add(result, result, tmp3);
	carry += vli_add(result, result, tmp2);

	if (carry < 0) {
		do {
			carry += vli_add(result, result, mod);
		} while(carry < 0);
	} else {
		while (carry || vli_cmp(mod, result) != 1)
		{
			carry -= vli_sub(result, result, mod);
		}
	}
}

void vli_mod_mult_fast(uint8_t *result, uint8_t *left, uint8_t *right, uint8_t *mod)
{
	uint8_t product[2 * ECC_NUMWORD];

	vli_mult(product, left, right);
	vli_mmod_fast(result, product, mod);
}

void vli_mod_square_fast(uint8_t *result, uint8_t *left, uint8_t *mod)
{
	uint8_t product[2 * ECC_NUMWORD];

	vli_square(product, left);
	vli_mmod_fast(result, product, mod);
}


void vli_mod_mult(uint8_t *result, uint8_t *left, uint8_t *right, uint8_t *mod)
{
	uint8_t product[2 * ECC_NUMWORD];
	uint8_t modMultiple[2 * ECC_NUMWORD];
	uint32_t digitShift, bitShift;
	uint32_t productBits;
	uint8_t carry;
	uint32_t modBits = vli_num_bits(mod);

	vli_mult(product, left, right);
	productBits = vli_num_bits(product + ECC_NUMWORD);
	if (productBits) {
		productBits += ECC_NUMWORD * 8;
	} else {
		productBits = vli_num_bits(product);
	}

	if (productBits < modBits) {
		vli_set(result, product);
		return;
	}

	vli_clear(modMultiple);
	vli_clear(modMultiple + ECC_NUMWORD);
	digitShift = (productBits - modBits) / 8;
	bitShift = (productBits - modBits) % 8;
	if (bitShift) {
		modMultiple[digitShift + ECC_NUMWORD] = vli_lshift(modMultiple + digitShift, mod, bitShift);
	} else {
		vli_set(modMultiple + digitShift, mod);
	}

	vli_clear(result);
	result[0] = 1; 
	while (productBits > ECC_NUMWORD * 8 || vli_cmp(modMultiple, mod) >= 0)
	{
		int cmp = vli_cmp(modMultiple + ECC_NUMWORD, product + ECC_NUMWORD);
		if (cmp < 0 || (cmp == 0 && vli_cmp(modMultiple, product) <= 0)) {
			if (vli_sub(product, product, modMultiple))
			{
				vli_sub(product + ECC_NUMWORD, product + ECC_NUMWORD, result);
			}
			vli_sub(product + ECC_NUMWORD, product + ECC_NUMWORD, modMultiple + ECC_NUMWORD);
		}
		carry = (modMultiple[ECC_NUMWORD] & 0x01) << 7;
		vli_rshift1(modMultiple + ECC_NUMWORD);
		vli_rshift1(modMultiple);
		modMultiple[ECC_NUMWORD-1] |= carry;

		--productBits;
	}
	vli_set(result, product);
}

#define EVEN(vli) (!(vli[0] & 1))

void vli_mod_inv(uint8_t *result, uint8_t *input, uint8_t *mod)
{
	uint8_t a[ECC_NUMWORD], b[ECC_NUMWORD], u[ECC_NUMWORD], v[ECC_NUMWORD];
	uint8_t carry;
	int cmpResult;

	if (vli_is_zero(input)) {
		vli_clear(result);
		return;
	}

	vli_set(a, input);
	vli_set(b, mod);
	vli_clear(u);
	u[0] = 1;
	vli_clear(v);

	while ((cmpResult = vli_cmp(a, b)) != 0) {
		carry = 0;
		if (EVEN(a)) {
			vli_rshift1(a);
			if (!EVEN(u)) {
				carry = vli_add(u, u, mod);
			}
			vli_rshift1(u);
			if (carry) {
				u[ECC_NUMWORD-1] |= 0x80;
			}
		} else if (EVEN(b)) {
			vli_rshift1(b);
			if (!EVEN(v)) {
				carry = vli_add(v, v, mod);
			}
			vli_rshift1(v);
			if (carry) {
				v[ECC_NUMWORD-1] |= 0x80;
			}
		} else if (cmpResult > 0) {
			vli_sub(a, a, b);
			vli_rshift1(a);
			if (vli_cmp(u, v) < 0) {
				vli_add(u, u, mod);
			}
			vli_sub(u, u, v);
			if (!EVEN(u)) {
				carry = vli_add(u, u, mod);
			}
			vli_rshift1(u);
			if (carry) {
				u[ECC_NUMWORD-1] |= 0x80;
			}
		} else {
			vli_sub(b, b, a);
			vli_rshift1(b);
			if (vli_cmp(v, u) < 0) {
				vli_add(v, v, mod);
			}
			vli_sub(v, v, u);
			if (!EVEN(v)) {
				carry = vli_add(v, v, mod);
			}
			vli_rshift1(v);
			if (carry) {
				v[ECC_NUMWORD-1] |= 0x80;
			}
		}
	}

	vli_set(result, u);
}

int ecc_point_is_zero(ecc_point *point)
{
	return (vli_is_zero(point->x) && vli_is_zero(point->y));
}

static void ecc_point_double_jacobian(uint8_t *X1, uint8_t *Y1, uint8_t *Z1)
{
	uint8_t t4[ECC_NUMWORD];
	uint8_t t5[ECC_NUMWORD];

	if(vli_is_zero(Z1))
		return;

	vli_mod_square_fast(t4, Y1, ecc_curve.p);   
	vli_mod_mult_fast(t5, X1, t4, ecc_curve.p); 
	vli_mod_square_fast(t4, t4, ecc_curve.p);   
	vli_mod_mult_fast(Y1, Y1, Z1, ecc_curve.p); 
	vli_mod_square_fast(Z1, Z1, ecc_curve.p);   

	vli_mod_add(X1, X1, Z1, ecc_curve.p); 
	vli_mod_add(Z1, Z1, Z1, ecc_curve.p); 
	vli_mod_sub(Z1, X1, Z1, ecc_curve.p); 
	vli_mod_mult_fast(X1, X1, Z1, ecc_curve.p);   

	vli_mod_add(Z1, X1, X1, ecc_curve.p);
	vli_mod_add(X1, X1, Z1, ecc_curve.p); 
	if (vli_test_bit(X1, 0)) {
		uint8_t carry = vli_add(X1, X1, ecc_curve.p);
		vli_rshift1(X1);
		X1[ECC_NUMWORD-1] |= carry << 7;
	} else {
		vli_rshift1(X1);
	}

	vli_mod_square_fast(Z1, X1, ecc_curve.p);     
	vli_mod_sub(Z1, Z1, t5, ecc_curve.p); 
	vli_mod_sub(Z1, Z1, t5, ecc_curve.p); 
	vli_mod_sub(t5, t5, Z1, ecc_curve.p); 
	vli_mod_mult_fast(X1, X1, t5, ecc_curve.p);  
	vli_mod_sub(t4, X1, t4, ecc_curve.p); 

	vli_set(X1, Z1);
	vli_set(Z1, Y1);
	vli_set(Y1, t4);
}

static void apply_z(uint8_t *X1, uint8_t *Y1, uint8_t *Z)
{
	uint8_t t1[ECC_NUMWORD];

	vli_mod_square_fast(t1, Z, ecc_curve.p);    
	vli_mod_mult_fast(X1, X1, t1, ecc_curve.p); 
	vli_mod_mult_fast(t1, t1, Z, ecc_curve.p); 
	vli_mod_mult_fast(Y1, Y1, t1, ecc_curve.p);
}

static void XYcZ_initial_double(uint8_t *X1, uint8_t *Y1, uint8_t *X2, uint8_t *Y2, uint8_t *initialZ)
{
	uint8_t z[ECC_NUMWORD];

	vli_set(X2, X1);
	vli_set(Y2, Y1);

	if(initialZ)
	{
		vli_set(z, initialZ);
	}else{
		vli_clear(z);
		z[0] = 1;
	}
	apply_z(X1, Y1, z);

	ecc_point_double_jacobian(X1, Y1, z);

	apply_z(X2, Y2, z);
}

static void XYcZ_add(uint8_t *X1, uint8_t *Y1, uint8_t *X2, uint8_t *Y2)
{
	uint8_t t5[ECC_NUMWORD];

	vli_mod_sub(t5, X2, X1, ecc_curve.p); 
	vli_mod_square_fast(t5, t5, ecc_curve.p);      
	vli_mod_mult_fast(X1, X1, t5, ecc_curve.p);   
	vli_mod_mult_fast(X2, X2, t5, ecc_curve.p);  
	vli_mod_sub(Y2, Y2, Y1, ecc_curve.p); 
	vli_mod_square_fast(t5, Y2, ecc_curve.p);   

	vli_mod_sub(t5, t5, X1, ecc_curve.p); 
	vli_mod_sub(t5, t5, X2, ecc_curve.p); 
	vli_mod_sub(X2, X2, X1, ecc_curve.p); 
	vli_mod_mult_fast(Y1, Y1, X2, ecc_curve.p);    
	vli_mod_sub(X2, X1, t5, ecc_curve.p); 
	vli_mod_mult_fast(Y2, Y2, X2, ecc_curve.p);   
	vli_mod_sub(Y2, Y2, Y1, ecc_curve.p); 

	vli_set(X2, t5);
}

static void XYcZ_addC(uint8_t *X1, uint8_t *Y1, uint8_t *X2, uint8_t *Y2)
{
	uint8_t t5[ECC_NUMWORD];
	uint8_t t6[ECC_NUMWORD];
	uint8_t t7[ECC_NUMWORD];

	vli_mod_sub(t5, X2, X1, ecc_curve.p);
	vli_mod_square_fast(t5, t5, ecc_curve.p);      
	vli_mod_mult_fast(X1, X1, t5, ecc_curve.p);    
	vli_mod_mult_fast(X2, X2, t5, ecc_curve.p);   
	vli_mod_add(t5, Y2, Y1, ecc_curve.p); 
	vli_mod_sub(Y2, Y2, Y1, ecc_curve.p);

	vli_mod_sub(t6, X2, X1, ecc_curve.p);
	vli_mod_mult_fast(Y1, Y1, t6, ecc_curve.p);   
	vli_mod_add(t6, X1, X2, ecc_curve.p);
	vli_mod_square_fast(X2, Y2, ecc_curve.p);    
	vli_mod_sub(X2, X2, t6, ecc_curve.p); 

	vli_mod_sub(t7, X1, X2, ecc_curve.p); 
	vli_mod_mult_fast(Y2, Y2, t7, ecc_curve.p);    
	vli_mod_sub(Y2, Y2, Y1, ecc_curve.p); 

	vli_mod_square_fast(t7, t5, ecc_curve.p);   
	vli_mod_sub(t7, t7, t6, ecc_curve.p); 
	vli_mod_sub(t6, t7, X1, ecc_curve.p); 
	vli_mod_mult_fast(t6, t6, t5, ecc_curve.p);    
	vli_mod_sub(Y1, t6, Y1, ecc_curve.p); 
	vli_set(X1, t7);
}

void ecc_point_mult(ecc_point *result, ecc_point *point, uint8_t *scalar, uint8_t *initialZ)
{
	uint8_t Rx[2][ECC_NUMWORD];
	uint8_t Ry[2][ECC_NUMWORD];
	uint8_t z[ECC_NUMWORD];
	int i, nb;

	vli_set(Rx[1], point->x);
	vli_set(Ry[1], point->y);

	XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initialZ);

	for (i = vli_num_bits(scalar) - 2; i > 0; --i) {
		nb = !vli_test_bit(scalar, i);
		XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
		XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
	}

	nb = !vli_test_bit(scalar, 0);
	XYcZ_addC(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);

	vli_mod_sub(z, Rx[1], Rx[0], ecc_curve.p);
	vli_mod_mult_fast(z, z, Ry[1-nb], ecc_curve.p);    
	vli_mod_mult_fast(z, z, point->x, ecc_curve.p);   
	vli_mod_inv(z, z, ecc_curve.p);            
	vli_mod_mult_fast(z, z, point->y, ecc_curve.p);   
	vli_mod_mult_fast(z, z, Rx[1-nb], ecc_curve.p);     

	XYcZ_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);

	apply_z(Rx[0], Ry[0], z);

	vli_set(result->x, Rx[0]);
	vli_set(result->y, Ry[0]);
}

static uint32_t max(uint32_t a, uint32_t b)
{
	return (a > b ? a : b);
}

void ecc_point_mult2(ecc_point *result, ecc_point *g, ecc_point *p, uint8_t *s, uint8_t *t)
{
	uint8_t tx[ECC_NUMWORD];
	uint8_t ty[ECC_NUMWORD];
	uint8_t tz[ECC_NUMWORD];
	uint8_t z[ECC_NUMWORD];
	ecc_point sum;
	ecc_point *point = NULL;
	ecc_point *pointpart = NULL;
	int index;
	uint32_t numBits;
	uint8_t *rx;
	uint8_t *ry;
	int i;
	ecc_point *points[4] = {NULL, g, p, &sum};

	rx = result->x;
	ry = result->y;

	vli_set(sum.x, p->x);
	vli_set(sum.y, p->y);
	vli_set(tx, g->x);
	vli_set(ty, g->y);

	vli_mod_sub(z, sum.x, tx, ecc_curve.p); 
	XYcZ_add(tx, ty, sum.x, sum.y);
	vli_mod_inv(z, z, ecc_curve.p); 
	apply_z(sum.x, sum.y, z);

	numBits = max(vli_num_bits(s), vli_num_bits(t));

	point = points[(!!vli_test_bit(s, numBits-1)) | ((!!vli_test_bit(t, numBits-1)) << 1)];
	vli_set(rx, point->x);
	vli_set(ry, point->y);
	vli_clear(z);
	z[0] = 1;

	for (i = numBits - 2; i >= 0; --i) {
		ecc_point_double_jacobian(rx, ry, z);

		index = (!!vli_test_bit(s, i)) | ((!!vli_test_bit(t, i)) << 1);
		pointpart = points[index];
		if(pointpart) {
			vli_set(tx, pointpart->x);
			vli_set(ty, pointpart->y);
			apply_z(tx, ty, z);
			vli_mod_sub(tz, rx, tx, ecc_curve.p); /* Z = x2 - x1 */
			XYcZ_add(tx, ty, rx, ry);
			vli_mod_mult_fast(z, z, tz, ecc_curve.p);
		}
	}

	vli_mod_inv(z, z, ecc_curve.p); 
	apply_z(rx, ry, z);
}

void ecc_point_add(ecc_point *result, ecc_point *left, ecc_point *right)
{
	uint8_t x1[ECC_NUMWORD];
	uint8_t y1[ECC_NUMWORD];
	uint8_t x2[ECC_NUMWORD];
	uint8_t y2[ECC_NUMWORD];
	uint8_t z[ECC_NUMWORD];

	vli_set(x1, left->x);
	vli_set(y1, left->y);
	vli_set(x2, right->x);
	vli_set(y2, right->y);

	vli_mod_sub(z, x2, x1, ecc_curve.p); 

	XYcZ_add(x1, y1, x2, y2);
	vli_mod_inv(z, z, ecc_curve.p); 
	apply_z(x2,y2, z);

	vli_set(result->x, x2);
	vli_set(result->y, y2);
}
