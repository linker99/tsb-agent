#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include "../tcsapi/tcs_file_integrity.h"
//#include "tpcm_def.h"

#define LEN_HASH_SM3		32

int str_split(char *instring, char *delimiter, char *out_name, char *out_hash)
{
	int ret = 0;
	char *s = NULL;
	int vect = 0;
	char str_array[5][1024];

	if (instring == NULL || delimiter == NULL) {
		printf("input string or delimiter is error!");
		ret = -1;
		return ret;
	}

	if (delimiter[0] == '\0') {
		printf("input delimiter is error!");
		ret = -1;
		return ret;
	}

	s = strtok(instring, delimiter);

	while (s != NULL) {
		if (vect > 4) {
			printf("the string delimiter is too long !\n");
			ret = -1;
			return ret;
		}

		int len = strlen(s)+1;

		memcpy(str_array[vect], s, len);
		str_array[vect][len] = '\0';
		s = strtok(NULL, delimiter);
		vect++;
	}

	memset(out_name, 0, 1024);
	memset(out_hash, 0, 256);
	memcpy(out_name, str_array[0], strlen(str_array[0]));
	memcpy(out_hash, str_array[1], strlen(str_array[1]));

	return ret;
}

#define BYTE4_ALIGNMENT(len) if((len%4) != 0) len += 4-len%4
int config_whitelist_from_file(char *proc_file)
{
        int ret = 0;
		int i;
		unsigned int k;
		__u8 digest[LEN_HASH_SM3];
        FILE * fp = NULL;
        char buf[4096] = {0};
        char name[1024] = {0};
        char hash[256] = {0};

		FILE* fp_w = fopen("integrity.data", "wb");

        fp = fopen(proc_file, "r");
        if (fp == NULL) {
                perror("fopen");
                return -1;
        }

        while (fgets(buf, 1024, fp) != NULL) {

            str_split(buf, " ", name, hash);
            //printf("%s %s\n", name, hash);

			for (i=0; i<LEN_HASH_SM3; i++) {
				sscanf(&hash[i*2], "%2x", &k);
				digest[i] = (unsigned char)k;
			}

			int data_len = LEN_HASH_SM3+strlen(name)+1;
			BYTE4_ALIGNMENT(data_len);
			int len = sizeof(struct file_integrity_item)+data_len;
			struct file_integrity_item *p_item=malloc(len);
			p_item->extend_size = 0;
			p_item->be_path_length = strlen(name)+1;
			//printf("111:%d\n", p_item->be_path_length);
			p_item->be_path_length = htons(p_item->be_path_length);
			//printf("222:%d\n", p_item->be_path_length);
			memcpy(p_item->data, digest, LEN_HASH_SM3);
			memcpy(p_item->data+LEN_HASH_SM3, name, strlen(name)+1);

			//printf("%d   %s\n", p_item->be_path_length, p_item->data+LEN_HASH_SM3);
			fwrite(p_item, 1, len, fp_w);

			free(p_item);
			
        }

        fclose(fp);
		fclose(fp_w);

        return ret;
}

int main(int argc, char **argv)
{
        //char sign[256] = {0};
        //if (argc != 2) {
        //        printf("./load whitelist\n");
        //        exit(0);
        //}

        //char *config_file = argv[1];

        config_whitelist_from_file("whitelist_str");
        exit(0);
}
