#include <stdio.h>
#include <stdlib.h>
#include "sm_if.h"
#include "sm2.h"
#include "ssl.h"
#include "hash_key.h"
#include "libcrypt.h"

//#ifdef arm64
#include "ctype.h"
//#endif

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

void dump_hex(const unsigned char *str, int len)
{
        int i;

        for (i = 0; i < len; i++) {
                printf("%02X", str[i]);
        }
        printf("\n");
}


void Hex2Str(const unsigned char *src, int src_len, unsigned char *dest)
{
        int  i;
        char temp[3];

        for(i = 0; i < src_len; i++) {
                sprintf(temp, "%02X", (unsigned char)src[i]);
                memcpy(&dest[i * 2], temp, 2);
        }
        return;
}

void Str2Hex(const unsigned char *src, int src_len, unsigned char *dest)
{
        int i;
        unsigned char Hbyte, Lbyte;

        for (i = 0; i < src_len; i += 2) {
                Hbyte = toupper(src[i]);
                Lbyte = toupper(src[i + 1]);

                if (Hbyte >= 'A')
                        Hbyte = Hbyte - 0x37;

                if (Lbyte >= 'A')
                        Lbyte = Lbyte - 0x37;
                else
                        Lbyte = Lbyte & 0x0F;

                dest[i / 2] = Hbyte << 4 | Lbyte;
        }

        return;
}

int sm2_sign_digest(const char *digest, int digest_len, char *sign, int *sign_len)
{
        unsigned char *signature = NULL;
        int sig_len = 0;

        if (os_sm2_sign(digest, digest_len, privkey, sizeof(privkey),
                        pubkey, sizeof(pubkey), &signature, &sig_len)) {
                //printf("signed failed\n");
                return -1;
        }

        *sign_len = sig_len;
        memcpy(sign, signature, sig_len);

        if (signature)
                SM2_FREE(signature);

        return 0;
}

int sm2_verify_digest(const char *digest, int digest_len, const char *signature, int sig_len)
{
        if (os_sm2_verify(digest, digest_len, pubkey, sizeof(pubkey), signature, sig_len)) {
                //printf("signature verify failed\n");
                return -1;
        }

        return 0;
}

int py_sm2_verify(const char *digest, int digest_len, const char *sign, int sign_len)
{
        int ret = 0;
        unsigned char sign_buf[1024] = {0};
        unsigned char digest_buf[1024] = {0};
        int digest_buf_len, sign_buf_len = 0;

        Str2Hex(digest, digest_len, digest_buf);
        digest_buf_len = digest_len / 2;

        Str2Hex(sign, sign_len, sign_buf);
        sign_buf_len = sign_len / 2;

        ret = sm2_verify_digest(digest_buf, digest_buf_len, sign_buf, sign_buf_len);
        return ret;

}

int py_sm2_sign(const char *digest, int digest_len, char *sign)
{
        int ret = 0;
        unsigned char sign_buf[1024] = {0};
        unsigned char digest_buf[1024] = {0};
        int digest_buf_len, sign_buf_len = 0;

        Str2Hex(digest, digest_len, digest_buf);
        digest_buf_len = digest_len / 2;
        ret = sm2_sign_digest(digest_buf, digest_buf_len, sign_buf, &sign_buf_len);
        if (!ret) {
                Hex2Str(sign_buf, sign_buf_len, sign);
                /* *sign_len = sign_buf_len * 2; */
        }

        return ret;
}

int py_sm3_hash(const char *data, int data_len, char *hash)
{
        sm3_context ctx;
        char digest[32] = {0};

        sm3_init(&ctx);
        sm3_update(&ctx, data, data_len);
        sm3_finish(&ctx, digest);

        Hex2Str(digest, sizeof(digest), hash);

        return 0;
}

int set_key(const unsigned char *pub, int pub_len, const unsigned char *priv, int priv_len)
{
        if (pub_len != sizeof(pubkey) || priv_len != sizeof(privkey))
                return -1;

        memcpy(pubkey, pub, pub_len);
        memcpy(privkey, priv, priv_len);

        return 0;
}
