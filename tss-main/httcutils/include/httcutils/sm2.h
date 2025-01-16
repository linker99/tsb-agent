/*
 * @Description: 
 * @Author: huatai
 * @Date: 2021-06-30 15:27:52
 * @LastEditTime: 2021-07-19 15:50:24
 * @LastEditors: huatai
 */
#ifndef _SM2_H_
#define _SM2_H_


#define SM2_USER_ID (unsigned char *)"1234567812345678"
#define SM2_USER_ID_LENGTH 16

int ht_sm2_generate_keypair(unsigned char * prikey, unsigned int * pulPriLen,
					 unsigned char pubkey_XY[64]);
int ht_sm2_encrypt(unsigned char *C, unsigned int *Clen,
				  const unsigned char *M, 	int Mlen,
				  unsigned char *szPubkey_XY, int ul_PubkXY_len);
int ht_sm2_decrypt(unsigned char *M, unsigned int *Mlen,
				const unsigned char *C, int Clen,
				const unsigned char *prikey, int ulPri_dALen);

//Compression calculation
int ht_sm2_sign(unsigned char * signedData, unsigned int * pulSigLen,
				const unsigned char * message, int ilen,
					const unsigned char * UserID, int lenUID,
					const unsigned char * prikey, int ulPrikeyLen,
					unsigned char pubkey_XY[64]);
int ht_sm2_verify(const unsigned char * sign, int sign_len,
				const unsigned char * msg, int msg_len,
				const unsigned char * user_id, int id_len,
				const unsigned char * pub_key, int pubkey_len);

//No Compression calculation --- sm2 sign and verify process costing

//step 1 --- calculation Z
int ht_sm3_z(const unsigned char *Userid, unsigned int idlen, unsigned char *pubkey/*64B*/, unsigned char *Zdata);

//step 2 ---- calculation E
int ht_sm3_e(const unsigned char *Userid, unsigned int idlen, unsigned char *pubkey/*64B*/, 
			   const unsigned char *msg, unsigned int msg_len, unsigned char *Ehash/*32B*/);


int ht_sm2_sign_digest(
					unsigned char* signedData, unsigned int * pulSigLen,
					const unsigned char* digest, int digest_len,
					const unsigned char* prikey, unsigned long ulPrikeyLen);

int ht_sm2_verify_digest(const unsigned char * sign, int sign_len,//64 byte
				const unsigned char * digest, int digest_len,//32 byte
				const unsigned char * pub_key, int pubkey_len);//64_byte

int ht_sm3_kdf(const unsigned char *seed ,int send_len, unsigned char *mask, int mask_len);



int ht_sm2_dh_key(unsigned char* outkey,
                       unsigned char* dgst_S1, unsigned int* lenDgst_S1,
                       unsigned char* dgst_SA, unsigned int* lenDgst_SA,
                       int keylen,
                       const unsigned char* uid_a,  int uid_len_a,
                       const unsigned char* uid_b,  int uid_len_b,
                       const unsigned char* prikey_a,  int prikey_len_a,
                       const unsigned char* prikey_temp_a,  int rndKeyLen_A,
                       const unsigned char* pubkey_a,const unsigned char* pubkey_b,
                       const unsigned char* pubkey_temp_a,      const unsigned char* pubkey_temp_b,
                       int role);
#endif /* _SM2_H_ */
