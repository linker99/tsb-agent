#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
/* #include <linux/hdreg.h> */
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include "sm3.h"

#define DISK_NUM_MAX  0x20

typedef struct disks_info_s {
	unsigned long major;
	unsigned long minor;
	char name[128];
	char path[128];
	char serialnumber[128];
	char sm3digest[32];
	int flag;
} disks_info_t;

disks_info_t disk_info[DISK_NUM_MAX] = { 0 };
char disk_comm[200] = {'\0'};
char serial_number[200] = {'\0'};

int gethdid(char *device, char *hdid)
{
	FILE *stream;
	/* snprintf(disk_comm, 200,"udevadm info --query=all --name=/dev/sda | grep ID_SERIAL_SHORT | cut -d \"=\" -f 2"); */
	sprintf(disk_comm,"lsblk --nodeps -no serial %s", device );
	stream =popen(disk_comm, "r" );
	fread( hdid, sizeof(char),60, stream); 
	hdid[strlen(hdid)-1] = 0;
	/* printf("%s\n",hdid); */
	/* printf("%s\n",disk_comm); */
	pclose( stream );
}

/*
int gethdid(char *device, char *hdid)
{
	int fd;
	struct hd_driveid hid;
	int count;
	fd = open(device, O_RDONLY);
	if (fd < 0)
	{
		printf("open device[%s] failed\n", device);
		return -1;
	}

	if (ioctl(fd, HDIO_GET_IDENTITY, &hid) < 0)
	{
		printf("get device[%s] ID failed\n", device );
		return -1;
	}
	close(fd);
	sprintf(hdid, "%s", hid.serial_no);
	return 0;
}
*/
int is_exist_inlist(char *dname)
{
	int count;
	disks_info_t *pos = NULL;

	if (dname == NULL)
		return 0;

	for(count = 0; count < DISK_NUM_MAX ; count++)
	{
		pos = &disk_info[count];

		if(strlen(pos->name) == 0 )
			return 0;

		if(strstr(dname, pos->name) != NULL)
		{
			return 1;
		}
	}

	return 0;
}

void calc_sm3_hash(void)
{
	int count;
	disks_info_t *pos = NULL;
	sm3_context ctx;

	sm3_init(&ctx);
	for(count = 0; count < DISK_NUM_MAX ; count++)
	{
		pos = &disk_info[count];

		if(strlen(pos->name) == 0 )
			break;

		/* printf("len %ld\n", strlen(pos->serialnumber)); */
		sm3_update(&ctx, pos->serialnumber, strlen(pos->serialnumber));
		sm3_finish(&ctx, pos->sm3digest);
	}
}
int tcs_simple_boot_measure (uint32_t stage, uint8_t* digest, uint8_t *obj, uint32_t objLen);
void update_hash_tpcm(void)
{
	int count;
	disks_info_t *pos = NULL;
	int loop;
	unsigned int stage;
	

	stage = 3000;
	for(count = 0; count < DISK_NUM_MAX ; count++)
	{
		int ret;
		pos = &disk_info[count];
		if(strlen(pos->name) == 0 )
			break;
		/* printf("name[%s] disksn[%s] major[%lu] hash: ",pos->name, pos->serialnumber, pos->major); */
		for(loop =0 ; loop <32; loop++)
			printf(" %02x",(unsigned char)pos->sm3digest[loop]);
		printf("\n");
#if 1 
		ret = tcs_simple_boot_measure (stage, pos->sm3digest, pos->name, strlen(pos->name)+1);
		if(ret != 0)
		{
			printf("disk[%s] boot measure failed\n",pos->name);
			continue;
		}
		stage++;
#endif
	}
}


void diskstat()
{
	FILE *fp;
	int nread = 0;
	ssize_t len = 0;
	char *buffer = NULL;
	char buf[20][32];
	char *file = "/proc/diskstats";
	disks_info_t *pinfo = NULL;
	int count = 0;
	unsigned long major;
	unsigned long minor;

	fp = fopen(file, "rb");
	if (fp == NULL)
	{
		printf("error to open: %s\n", file);
		exit(EXIT_FAILURE);
	}

	while ((nread = getline(&buffer, &len, fp)) != -1)
	{
		int ret;
		char* p;
		pinfo = &disk_info[count]; 
		sscanf(buffer, "%04s%08s%32s %32s %32s %32s %32s %32s %32s %32s %32s %32s %32s %32s",
		       (char *)&buf[0], (char *)&buf[1], (char *)&buf[2], (char *)&buf[3], (char *)&buf[4], (char *)&buf[5], (char *)&buf[6],
		       (char *)&buf[7], (char *)&buf[8], (char *)&buf[9], (char *)&buf[10], (char *)&buf[11], (char *)&buf[12], (char *)&buf[13]);

		if ((0 != strncmp(buf[2], "sd", strlen("sd")))
		    && (0 != strncmp(buf[2], "hd", strlen("hd"))))
		{
			continue;
		}

		if ((p = strstr(buf[2], "loop")) != NULL)
		{
			continue;
		}
		
		if(is_exist_inlist(buf[2]))
		{
			continue;
		}

		strcpy(pinfo->name, buf[2]);
		sprintf(pinfo->path, "/dev/%s", buf[2]);
		ret = gethdid(pinfo->path, pinfo->serialnumber);
		pinfo->major = atoi(buf[0]);
		pinfo->minor = atoi(buf[1]);
		pinfo->flag = 1;
		count++;
		if(count >= DISK_NUM_MAX)
		{
			printf("The disk number should be less than %d\n",DISK_NUM_MAX);
			break;
		}
	}
	fclose(fp);
}

int main()
{
	diskstat();
	calc_sm3_hash();
	update_hash_tpcm();
}
