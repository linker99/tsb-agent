#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <httcutils/sys.h>
#include <httcutils/mem.h>
#include <httcutils/debug.h>
#include <httcutils/file.h>
int httc_util_file_size(const char* filename,unsigned long *psize)
{
    FILE *fp=fopen(filename,"r");
    if(!fp) return -1;
    fseek(fp,0L,SEEK_END);
    long size=ftell(fp);
    fclose(fp);
    *psize = size;
    return 0;
}
int httc_util_file_write(const char* filename,const char *buffer,unsigned int size)
{
	int r = 0;
	FILE *pf = fopen(filename,"w");
	if(!pf) return -1;
	if(size)r = fwrite(buffer,sizeof(char),size,pf);
//close_file:
	fclose(pf);
	return r;
}


int httc_util_file_write_offset(const char* filename,const char *buffer,unsigned long offset,unsigned int size)
{
	int r = 0;
	FILE *pf = fopen(filename,"r+");
	if(!pf) return 0;
	fseek(pf,offset,SEEK_SET);
	r = fwrite(buffer,sizeof(char),size,pf);
//close_file:
	fclose(pf);
	return r;
}

int httc_util_file_write_offset_array(const char* filename,struct file_section *p,int n)
{
	int r ;
	int i;
	FILE *pf = fopen(filename,"r+");
	if(!pf) return 0;
	for(i=0;i<n;i++){
		fseek(pf,p[i].offset,SEEK_SET);
		r = fwrite(p[i].buffer,sizeof(char),p[i].length,pf);
		if(r != p[i].length){
			r = -1;
			goto close_file;
		}
	}
	r = 0;
close_file:
	fclose(pf);
	return r;
}


int httc_util_file_append(const char* filename,const char *buffer,unsigned int size)
{
	int r = 0;
	FILE *pf = fopen(filename,"ab");
	if(!pf) return 0;
	r = fwrite(buffer,sizeof(char),size,pf);
//close_file:
	fclose(pf);
	return r;
}

void* httc_util_file_read_full(const char* filename,unsigned long *psize)
{
	void* data = 0;
	FILE *pf = fopen(filename,"r");
	if(!pf) return 0;

	fseek(pf,0,SEEK_END);
	long fsize = ftell(pf);
	if(fsize<0 || fsize > 1024 * 1024 * 100){
		goto close_file;
	}
	if(psize) *psize = (unsigned long)fsize;
	else goto close_file;
	if(!(*psize)) goto close_file; 
	data=(char*)httc_malloc(fsize);
	if(!data)goto close_file;
	rewind(pf);
	if(fread(data,sizeof(char),fsize,pf) != fsize){
		httc_free(data);
		data = NULL;
	}

close_file:

	fclose(pf);
	return data;
}

void *httc_util_file_read_offset(const char* filename,unsigned long offset,unsigned long *size)
{
	void* data = 0;
	FILE *pf = fopen(filename,"r");
	if(!pf) return 0;

	fseek(pf,0,SEEK_END);
	long fsize = ftell(pf);
	if(fsize<0 ||(fsize - offset) > 1024 * 1024 * 100){
		goto close_file;
	}
	if(size) *size = (unsigned long)fsize - offset;
	else goto close_file;
	if(!(*size)) goto close_file;
	data=(char*)httc_malloc(*size);	
	if(!data)goto close_file;
	fseek(pf,offset,SEEK_SET);
	if(fread(data,sizeof(char),*size,pf) != (*size)){
		httc_free(data);
		data=NULL;
	}

close_file:
	fclose(pf);
	return data;
}

#define BUFFER_SIZE 4096
int httc_util_file_copy_file(const char* source,const char* target){
	char buffer[BUFFER_SIZE];
	FILE *fin,*fout;
	int rszie;
	int result = 0;
	if ((fin=fopen(source,"rb")) ==NULL)  {
		return -1;
	}
	if ((fout=fopen(target,"wb")) ==NULL)  {
		fclose(fin);
		return -1;
	}
	while( (rszie = fread (buffer,1,BUFFER_SIZE,fin)) > 0){
		if(fwrite(buffer,1,rszie,fout) != rszie)break;
	}
	if(ferror(fin) || ferror(fout))result = -1;

	fclose(fin);
	fclose(fout);
	return result;

}

int httc_util_create_path (const char *path)
{
	if (access (path, F_OK))
		return httc_util_system_args ("mkdir -p %s", path);
	return 0;
}

int httc_util_create_path_of_fullpath (const char *fullpath)
{
	char *file = NULL;
	char path[4096] = {0};
	file = strrchr (fullpath, '/');
	memcpy (path, fullpath, file - fullpath);
	return httc_util_create_path (path);
}



