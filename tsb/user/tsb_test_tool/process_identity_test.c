#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <elf.h>
#include "sm3.h"

#include "../tsbapi/tsb_admin.h"
#include "../tcsapi/tcs_process_def.h"

#define PAGE_SIZE       4096
#define ALIGN           (PAGE_SIZE - 1)
#define ROUND_PG(x)     (((x) + (ALIGN)) & ~(ALIGN))

#define Elf_Ehdr	Elf64_Ehdr
#define Elf_Phdr	Elf64_Phdr

#define HASH_LEN 32
#define BYTE4_ALIGNMENT(len) if((len%4) != 0) len += 4-len%4

//#define EXE_LEN 4096
//#define LIBC_LEN 1802240
//#define LIBTSBADMIN_LEN 8192
//#define LD_LEN 135168


//static int dump_elf2file(const char *name)    // elf 文件路径
//{
//	int elf_fd = -1;
//	char *exe_buf = NULL;
//
//	elf_fd = open(name, O_RDONLY);
//	if(elf_fd < 0) {
//		perror("open");
//		return -1;
//	}
//
//	Elf_Ehdr ehdr;
//	Elf_Phdr *phdr = NULL;
//	ssize_t sz;
//
//	if (read(elf_fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
//		close(elf_fd);
//		return -1;
//	}
//
//	/* TODO check elf ehdr */
//
//	sz = ehdr.e_phnum * sizeof(Elf_Phdr);
//	phdr = malloc(sz);
//	if (lseek(elf_fd, ehdr.e_phoff, SEEK_SET) < 0) {
//		close(elf_fd);
//		return -1;
//	}
//
//	if (read(elf_fd, phdr, sz) != sz) {
//		free(phdr);
//		close(elf_fd);
//		return -1;
//	}
//
//	Elf_Phdr *iter;
//	for (iter = phdr; iter < &phdr[ehdr.e_phnum]; iter++) {
//		if (iter->p_type != PT_LOAD)
//			continue;
//
//		if (!(iter->p_flags & PF_X))
//			continue;
//
//		sz = ROUND_PG(iter->p_memsz);
//		break;
//	}
//
//	printf("filename[%s] text_section len[%d]\n", name, sz);
//	//read(elf_fd,  exe_buf, sz);
//
//	close(elf_fd);
//
//	return sz;
//}
//
//int calc_file_hash(char *file_nanme, int file_len, unsigned char *hash)
//{
//	char *buf = (char *)malloc(file_len);
//	memset(buf, 0, file_len);
//	FILE *fp = fopen(file_nanme, "rb");
//	if (!fp)
//	{
//		printf("fopen errror!\n");
//		return -1;
//	}
//	fread(buf, 1, file_len, fp);
//	sm3(buf, file_len, hash);
//	print_hex("hash", hash, HASH_LEN);
//	fclose(fp);
//	free(buf);
//}




void print_hex(const char *name, unsigned char *p, int len)
{
	int i = 0;

	//printf("name[%s] p[%x] len[%d]\n", name, p, len);
	for (i = 0; i < len; i++) {
		printf("%02X", p[i]);
		//printf("%02X", (int)p[i] & 0x000000ff);
	}
	printf("\n");
}

//过滤换行符
int filterLF(char* buf)
{
	if(!buf)
		return -1;

	char *tmp = NULL;
	if ((tmp = strstr(buf, "\n")))
	{
		*tmp = '\0';
	}

	return 0;
}

char fullpath[128][256] = {0};
int file_num=0;
int calc_hash(int i, unsigned char *hash)
{
	sm3_file(fullpath[i], hash);

	return 0;
}

int collect_file()
{
	char buf[4096] = {0};
	int i=0;
	FILE *fp = NULL;

	fp = fopen("process_identity_hash_file.txt", "r");
	if (fp == NULL) 
	{
		printf("fopen process_identity_hash_file.txt error!\n");
		return -1;
	}

	while (fgets(buf, 1024, fp) != NULL) 
	{
		filterLF(buf);
		strcpy(fullpath[i], buf);
		printf("---%s---\n", buf);
		memset(buf, 0, sizeof(buf));
		file_num++;
		i++;
	}
	fclose(fp);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("param error!\n");
		return 0;
	}

	unsigned char hash[HASH_LEN] = {0};
	char buf[4096] = {0};
	int text_section_len = 0;
	int i=0;

	collect_file(fullpath);
	
	struct process_identity *p_process_identity_policy = (struct process_identity *)buf;
	p_process_identity_policy->name_length = 7;
	p_process_identity_policy->specific_libs = 0;
	p_process_identity_policy->be_hash_length = htons(HASH_LEN);


	for (i=0; i<file_num; i++)
	{
		calc_hash(i, hash);
		print_hex("hash", hash, HASH_LEN);
		memcpy(p_process_identity_policy->data+HASH_LEN*i, hash, HASH_LEN);
	}

	p_process_identity_policy->be_lib_number = htons(file_num-1);  //fix
	memcpy(p_process_identity_policy->data+HASH_LEN*file_num, "helloa", 7);  //fix

	int policy_len = sizeof(struct process_identity) + HASH_LEN*file_num + 7;  //fix
	printf("111 policy_len:%d\n", policy_len);
	BYTE4_ALIGNMENT(policy_len);
	printf("222 policy_len:%d\n", policy_len);

	if (strcmp(argv[1], "1") == 0)
		tsb_set_process_ids((unsigned char *)p_process_identity_policy, policy_len);
	else if (strcmp(argv[1], "3") == 0)
		tsb_reload_process_ids();
	else
		printf("param argv error!\n");

	return 0;
}