#include "sm3.h"

#define rol(x,n) (((uint32_t)x << (n & 0x1F)) | ((uint32_t)(x & 0xFFFFFFFF) >> ((32 - n) & 0x1F)))
//#define rol(x,n) (((uint32_t)x << n) | ((uint32_t)(x & 0xFFFFFFFF) >> (32 - n)))
/*
   inline int rol(uint32_t operand, uint8_t width){
   asm volatile("rol %%cl, %%eax"
   : "=a" (operand)
   : "a" (operand), "c" (width)
   );
   }
 */
#define P0(x) ((x^(rol(x,9))^(rol(x,17))))
#define P1(x) ((x^(rol(x,15))^(rol(x,23))))

#define CONCAT_4_BYTES( w32, w8, w8_i)            \
{                                                 \
	(w32) = ( (uint32_t) (w8)[(w8_i)    ] << 24 ) |  \
	( (uint32_t) (w8)[(w8_i) + 1] << 16 ) |  \
	( (uint32_t) (w8)[(w8_i) + 2] <<  8 ) |  \
	( (uint32_t) (w8)[(w8_i) + 3]       );   \
}

#define SPLIT_INTO_4_BYTES( w32, w8, w8_i)        \
{                                                 \
	(w8)[(w8_i)] = (uint8_t) ( (w32) >> 24 );    \
	(w8)[(w8_i) + 1] = (uint8_t) ( (w32) >> 16 );    \
	(w8)[(w8_i) + 2] = (uint8_t) ( (w32) >>  8 );    \
	(w8)[(w8_i) + 3] = (uint8_t) ( (w32)       );    \
}

#define _GNU_SOURCE

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
	(b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
	(b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
	(b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
	(b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

static uint8_t SM3_padding[64] =
{
	(uint8_t) 0x80, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0,
	(uint8_t)    0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0,
	(uint8_t)    0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0,
	(uint8_t)    0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0, (uint8_t) 0
};

int sm3_starts(sm3_context *index)
{
	if (index == NULL) {
		return -1;
	}

	index->total_bytes_High = 0;
	index->total_bytes_Low = 0;
	index->vector[0] = 0x7380166f;
	index->vector[1] = 0x4914b2b9;
	index->vector[2] = 0x172442d7;
	index->vector[3] = 0xda8a0600;
	index->vector[4] = 0xa96f30bc;
	index->vector[5] = 0x163138aa;
	index->vector[6] = 0xe38dee4d;
	index->vector[7] = 0xb0fb0e4e;

	//memset(index->ipad, 0, 64);
	//memset(index->opad, 0, 64);

	return 0;
}

int sm3_init(sm3_context *index)
{
	if (index == NULL) {
		return -1;
	}

	index->total_bytes_High = 0;
	index->total_bytes_Low = 0;
	index->vector[0] = 0x7380166f;
	index->vector[1] = 0x4914b2b9;
	index->vector[2] = 0x172442d7;
	index->vector[3] = 0xda8a0600;
	index->vector[4] = 0xa96f30bc;
	index->vector[5] = 0x163138aa;
	index->vector[6] = 0xe38dee4d;
	index->vector[7] = 0xb0fb0e4e;

	//memset(index->ipad, 0, 64);
	//memset(index->opad, 0, 64);

	return 0;
}

sm3_context* sm3_alloc_init(void)
{
	sm3_context	*context = malloc(sizeof(sm3_context));
	if (context == 0) {
		return 0;
	}
	sm3_init(context);
	return context;
}

static void SM3_CF(sm3_context *index, const unsigned char *byte_64_block )
{
	uint32_t j,W[68];

	uint32_t A,B,C,D,E,F,G,H,SS1,SS2,TT1,TT2;
#ifdef DEBUG_PRINT
	for (j = 0; j < 64; j++)
		printk("%d:%8x\n", j, byte_64_block[j]);
	printk("\n--------------------\n");
#endif

	CONCAT_4_BYTES( W[0],  byte_64_block,  0 );
	CONCAT_4_BYTES( W[1],  byte_64_block,  4 );
	CONCAT_4_BYTES( W[2],  byte_64_block,  8 );
	CONCAT_4_BYTES( W[3],  byte_64_block, 12 );
	CONCAT_4_BYTES( W[4],  byte_64_block, 16 );
	CONCAT_4_BYTES( W[5],  byte_64_block, 20 );
	CONCAT_4_BYTES( W[6],  byte_64_block, 24 );
	CONCAT_4_BYTES( W[7],  byte_64_block, 28 );
	CONCAT_4_BYTES( W[8],  byte_64_block, 32 );
	CONCAT_4_BYTES( W[9],  byte_64_block, 36 );
	CONCAT_4_BYTES( W[10], byte_64_block, 40 );
	CONCAT_4_BYTES( W[11], byte_64_block, 44 );
	CONCAT_4_BYTES( W[12], byte_64_block, 48 );
	CONCAT_4_BYTES( W[13], byte_64_block, 52 );
	CONCAT_4_BYTES( W[14], byte_64_block, 56 );
	CONCAT_4_BYTES( W[15], byte_64_block, 60 );
#ifdef DEBUG_PRINT
	for (j = 0; j < 16; j++) {
		printk("%d:%8x\n", j, W[j]);
	}
#endif
	for (j = 16; j < 68; j++){
		// waitting to modified 
		// there is something strange here,"P1(W[j-16]^W[j-9]^rol(W[j-3],15))" will get a error result
		uint32_t temp = W[j-16]^W[j-9]^rol(W[j-3],15);
		W[j] = P1(temp)^rol(W[j-13],7)^(W[j-6]);
		// W[j] = P1((W[j-16]^W[j-9]^rol(W[j-3],15)))^rol(W[j-13],7)^(W[j-6]);

#ifdef DEBUG_PRINT

		printk("%d::(*)=%8x :temp=%8x :P1((*))=%8x :P1(*)=%8x :p1(temp)=%8x\n",
				j,(W[j-16]^W[j-9]^rol(W[j-3],15)),P1((W[j-16]^W[j-9]^rol(W[j-3],15))),temp,P1(W[j-16]^W[j-9]^rol(W[j-3],15)),P1(temp));

#endif
	}
	A = index->vector[0];
	B = index->vector[1];
	C = index->vector[2];
	D = index->vector[3];
	E = index->vector[4];
	F = index->vector[5];
	G = index->vector[6];
	H = index->vector[7];
#ifdef DEBUG_PRINT
	printk(" :A:%08x,B:%08x,C:%08x,D:%08x,E:%08x,F:%08x,G:%08x,H:%08x\n",A,B,C,D,E,F,G,H);
#endif

#define T 0x79cc4519
#define FF(X,Y,Z) (X^Y^Z)
#define GG(X,Y,Z) (X^Y^Z)

	for (j = 0; j < 16; j++) {
		SS1 = rol((rol(A,12) + E + rol(T,j)),7);
		SS2 = SS1^(rol(A,12));
		TT1 = FF(A,B,C) + D + SS2 + (W[j]^W[j+4]);
		TT2 = GG(E,F,G) + H + SS1 + W[j];
		D = C;
		C = rol(B,9);
		B = A;
		A = TT1;
		H = G;
		G = rol(F,19);
		F = E;
		E = P0(TT2);
#ifdef DEBUG_PRINT
		printk("%d: A:%08x,B:%08x,C:%08x,D:%08x,E:%08x,F:%08x,G:%08x,H:%08x\n",j,A,B,C,D,E,F,G,H);
#endif
	}

#undef T
#undef FF 
#undef GG


#define T 0x7a879d8a 
#define FF(X,Y,Z) ((X&Y)|(X&Z)|(Y&Z))
#define GG(X,Y,Z) ((X&Y)|(~X&Z))


	for (j = 16; j < 64; j++) {
		SS1 = (uint32_t)rol((rol(A,12) + E + (uint32_t)rol(T,j)),7);
		SS2 = SS1^(rol(A,12));
		TT1 = FF(A,B,C) + D + SS2 + (W[j]^W[j+4]);
		TT2 = GG(E,F,G) + H + SS1 + W[j];
		D = C;
		C = rol(B,9);
		B = A;
		A = TT1;
		H = G;
		G = rol(F,19);
		F = E;
		E = P0(TT2);
#ifdef DEBUG_PRINT
		printk("%d: A:%08x,B:%08x,C:%08x,D:%08x,E:%08x,F:%08x,G:%08x,H:%08x\n",j,A,B,C,D,E,F,G,H);
#endif
	}
#undef T
#undef FF 
#undef GG

	index->vector[0] ^= A;
	index->vector[1] ^= B;
	index->vector[2] ^= C;
	index->vector[3] ^= D;
	index->vector[4] ^= E;
	index->vector[5] ^= F;
	index->vector[6] ^= G;
	index->vector[7] ^= H;

}

int sm3_update(sm3_context *index, const unsigned char *chunk_data, unsigned int chunk_length)
{
	uint32_t left, fill;
	uint32_t i;

	if ((index == NULL) || (chunk_data == NULL) || (chunk_length < 1)) {
		return -1;
	}

	left = index->total_bytes_Low & 0x3F;
	fill = 64 - left;
	index->total_bytes_Low += chunk_length;
	index->total_bytes_Low &= 0xFFFFFFFF;

	if (index->total_bytes_Low < chunk_length) {
		index->total_bytes_High++;
	}

	if ((left > 0) && (chunk_length >= fill)) {
		for (i = 0; i < fill; i++) {
			index->buffer[left + i] = chunk_data[i];
		}
		SM3_CF(index, index->buffer);
		chunk_length -= fill;
		chunk_data  += fill;
		left = 0;
	}

	while (chunk_length >= 64) {
		SM3_CF(index, chunk_data);
		chunk_length -= 64;
		chunk_data  += 64;
	}

	if (chunk_length > 0) {
		for (i = 0; i < chunk_length; i++) {
			index->buffer[left + i] = chunk_data[i];
		}
	}
	return 0;
}

int sm3_finish(sm3_context *index, unsigned char output[SM3_DIGEST_SIZE])
{
	uint32_t last, padn;
	uint32_t high, low;
	uint8_t  msglen[8];
	int   ret;

	if ((index == NULL) || (output == NULL)) {
		*output = 0;
		return -1;
	}
	high = (index->total_bytes_Low >> 29) | (index->total_bytes_High << 3);
	low  = (index->total_bytes_Low << 3);
	SPLIT_INTO_4_BYTES(high, msglen, 0);
	SPLIT_INTO_4_BYTES(low, msglen, 4);

	last = index->total_bytes_Low & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);
	ret = sm3_update(index, SM3_padding, padn);
	if (ret != 0)
		return ret;

	ret = sm3_update(index, msglen, 8);
	if (ret != 0)
		return ret;

	PUT_ULONG_BE( index->vector[0], output,  0 );
	PUT_ULONG_BE( index->vector[1], output,  4 );
	PUT_ULONG_BE( index->vector[2], output,  8 );
	PUT_ULONG_BE( index->vector[3], output, 12 );
	PUT_ULONG_BE( index->vector[4], output, 16 );
	PUT_ULONG_BE( index->vector[5], output, 20 );
	PUT_ULONG_BE( index->vector[6], output, 24 );
	PUT_ULONG_BE( index->vector[7], output, 28 );
	return 0;
}

/*
 * output = SM3( input buffer )
 */
void sm3(const unsigned char *input, int ilen, unsigned char output[SM3_DIGEST_SIZE])
{
	sm3_context ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, input, ilen);
	sm3_finish(&ctx, output);

	memset(&ctx, 0, sizeof(sm3_context));
}

/*
 * output = SM3( file contents )
 */
int sm3_file( const char *path, unsigned char *output)
{
	FILE *f;
	size_t n;
	sm3_context ctx;
	unsigned char buf[1024];
	unsigned char hash[SM3_DIGEST_SIZE] = {0};

	if( ( f = fopen( path, "rb" ) ) == NULL )
		return( 1 );

	sm3_init( &ctx );

	while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 ){
    	sm3_update( &ctx, buf, (int) n );
    }

	sm3_finish( &ctx, hash);
	//for (i=0; i<SM3_DIGEST_SIZE; i++)
	//	sprintf((char *)(output + i*2), "%02X", hash[i]);
	memcpy(output, hash, SM3_DIGEST_SIZE);

	memset( &ctx, 0, sizeof( sm3_context ) );

	if( ferror( f ) != 0 )
	{
		fclose( f );
		return( 2 );
	}

	fclose( f );
	return( 0 );
}

