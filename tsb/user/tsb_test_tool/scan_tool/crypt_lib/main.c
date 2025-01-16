#include <stdio.h>
#include <stdlib.h>
#include "sm_if.h"
#include "sm2.h"
#include "ssl.h"
#include "hash_key.h"

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

#if 1
        if (signature)
                SM2_FREE(signature);
        return 0;
#else
        if (os_sm2_verify(digest, digest_len, pubkey, sizeof(pubkey),
                          signature, sig_len)) {
                //printf("signature verify failed\n");
                return -1;
        }
        //printf("verfication ok\n");
        if (signature)
                SM2_FREE(signature);
        return 0;
#endif
}

int sm3_hash_by_file(const char *name, char *digest)
{
        FILE * fp = NULL;
        int size = 0;
        char *rbuf = NULL;
        int rbuf_len = 0;
        int offset = 0;
        sm3_context ctx;

        fp = fopen(name, "rb");
        if (fp == NULL) {
                perror("fopen");
                return -1;
        }

        fseek(fp, 0L, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);

        rbuf = malloc(size);
        if (!rbuf) {
                printf("malloc error!\n");
                return -1;
        }

        rbuf_len = fread(rbuf, 1, size, fp);
        if (rbuf_len != size) {
                printf("read error !\n");
                fclose(fp);
                return -1;
        }

        fclose(fp);

        sm3_init(&ctx);
        sm3_update(&ctx, rbuf, rbuf_len);
        sm3_finish(&ctx, digest);

        return 0;
}

int main(int argc, char **argv)
{
        char *filename = NULL;
        char digest[32] = {0};
        char sign[64] = {0};
        int sig_len = 0;

        if (argc != 2) {
                printf("%s filename\n", argv[0]);
                exit(0);
        }

        filename = argv[1];
        if (0 != sm3_hash_by_file(filename, digest)) {
                printf("calc hash fail !\n");
                return -1;
        }
        //dump_hex(digest, 32);

        if (0 != sm2_sign_digest(digest, 32, sign, &sig_len)) {
                printf("calc sign fail !\n");
                return -1;
        }
        printf("%s ", filename);
        dump_hex(sign, sig_len);
        return 0;
}

