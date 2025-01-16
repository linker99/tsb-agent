#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "uutils.h"
#include "convert.h"
#include "tcs_attest.h"

int httc_insert_uid_align4 (const char *uid, void *ptr)
{
	int uid_size = 0;
	struct tpcm_data *uid_st = (struct tpcm_data *)ptr;
	if(uid){
		uid_size = strlen (uid) + 1;		
		memcpy (uid_st->value, uid, uid_size);
	}
	uid_st->be_size = htonl (uid_size);
	return sizeof (struct tpcm_data) + HTTC_ALIGN_SIZE (uid_size, 4);
}

int httc_extract_uid_align4_size (void *ptr)
{
	struct tpcm_data *uid_st = (struct tpcm_data *)ptr;
	int uid_size = ntohl (uid_st->be_size);
	return sizeof (struct tpcm_data) + HTTC_ALIGN_SIZE (uid_size, 4);
}

int httc_insert_auth_align4 (int auth_type, int auth_length,unsigned char *auth, void *ptr)
{
	struct tpcm_auth *auth_st = (struct tpcm_auth *)ptr;
	auth_st->be_type = htonl (auth_type);
	auth_st->be_size = htonl (auth_length);
	if(auth_length) memcpy (auth_st->value, auth, auth_length);
	return sizeof (struct tpcm_auth) + HTTC_ALIGN_SIZE (auth_length, 4);
}

int httc_extract_auth_align4_size (void *ptr)
{
	struct tpcm_auth *auth_st = (struct tpcm_auth *)ptr;
	int auth_length = ntohl (auth_st->be_size);
	return sizeof (struct tpcm_auth) + HTTC_ALIGN_SIZE (auth_length, 4);
}

int httc_insert_data_align4 (const char *data, int size, void *ptr)
{
	struct tpcm_data *data_st = (struct tpcm_data *)ptr;	
	data_st->be_size = htonl (size);
    if (size) memcpy (data_st->value, data, size);
	return sizeof (struct tpcm_data) + HTTC_ALIGN_SIZE (size, 4);
}

int httc_insert_data (const char *data, int size, void *ptr)
{
	struct tpcm_data *data_st = (struct tpcm_data *)ptr;	
	data_st->be_size = htonl (size);
    memcpy (data_st->value, data, size);
	return sizeof (struct tpcm_data) + size;
}

/** 签名转换: 基于BC的SM3withSM2签名(64字节) ---> ASN.1编码的签名(70-72字节) */
int encodeDER_4signout(unsigned char *srcsignbuf, unsigned char *outbuf)
{
	unsigned char sigoutbuf[80] = {0};
	unsigned char sigoutbuflen = 0;
	unsigned int i = 0, ss = 0;

	sigoutbuf[0] = 0x30;
	sigoutbuf[1] = 0x00;
	sigoutbuf[2] = 0x02;
	if(srcsignbuf[0]&0x80){
		i++;
		sigoutbuf[3] = 0x21;
		sigoutbuf[3+i] = 0x00;
	}else
		sigoutbuf[3] = 0x20;
	memcpy(&(sigoutbuf[4+i]), srcsignbuf, 0x20);
	ss = 0x24+i;
	i = 0;
	sigoutbuf[ss] = 0x02;
	if(srcsignbuf[32]&0x80){
		i++;
		sigoutbuf[ss+1] = 0x21;
		sigoutbuf[ss+1+i] = 0x00;
	}else
		sigoutbuf[ss+1] = 0x20;
	memcpy(&(sigoutbuf[ss+2+i]), srcsignbuf+0x20, 0x20);
	sigoutbuflen = ss+2+i+0x20;
	sigoutbuf[1] = sigoutbuflen-2;
	memcpy(outbuf, sigoutbuf, sigoutbuflen);

	return sigoutbuflen;
}

int httc_get_replay_counter(uint64_t *replay_counter)
{
	int ret = 0;	
	ret =  tcs_get_replay_counter (replay_counter);
	if(ret) return ret;
	*replay_counter += 1;
	return ret;
}

int is_tpcm_id_valid (const char *id)
{
	int i = 0;
	if (!id || (strlen (id) != MAX_TPCM_ID_SIZE))	return 0;
	for (i = 0; i < MAX_TPCM_ID_SIZE; i++){
		if (!(((id[i] >= 'A') && (id[i] <= 'Z'))
			|| ((id[i] >= '0') && (id[i] <= '9'))))
		return 0;
	}
	return 1;
}

