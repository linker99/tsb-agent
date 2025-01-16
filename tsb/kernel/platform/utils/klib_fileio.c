#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/mm.h>
#include "klib_fileio.h"
#include "../hook/hook.h"
#include "../utils/vfs.h"
#include "../utils/debug.h"
// 
// Library Functions 
// 
// Context : User 
// Parameter : 
// filename : filename to open 
// flags : 
// O_RDONLY, O_WRONLY, O_RDWR 
// O_CREAT, O_EXCL, O_TRUNC, O_APPEND, O_NONBLOCK, O_SYNC, ... 
// mode : file creation permission. 
// S_IRxxx S_IWxxx S_IXxxx (xxx = USR, GRP, OTH), S_IRWXx (x = U, G, O) 
// Return : 
// file pointer. if error, return NULL 


//struct file *klib_fopen(const char *filename, int flags, int mode)
//{
//	struct file *filp = filp_open(filename, flags, mode);
//
//	return (IS_ERR(filp)) ? NULL : filp;
//}
//
//
//
//// Context : User
//// Parameter :
//// filp : file pointer
//// Return :
//
//void klib_fclose(struct file *filp)
//{
//	if (filp)
//    {
//		filp_close(filp,0);
//        filp = NULL;
//    }
//}



// Context : User 
// Parameter : 
// filp : file pointer 
// offset : 
// whence : SEEK_SET, SEEK_CUR 
// Comment : 
// do not support SEEK_END 
// no boundary check (file position may exceed file size) 


int klib_fseek(struct file *filp, int offset, int whence) 
{ 
	if (filp)
      {
		int pos = filp->f_pos;
		if (whence == SEEK_SET) 
			pos = offset; 
		else if (whence == SEEK_CUR) 
			pos += offset; 

		if (pos < 0) 
			pos = 0; 

		return (filp->f_pos = pos); 
	} else 
		return -ENOENT; 
}
EXPORT_SYMBOL(klib_fseek);

// Context : User 
// Parameter : 
// buf : buffer to read into 
// len : number of bytes to read 
// filp : file pointer 
// Return : 
// actually read number. 0 = EOF, negative = error 




int klib_fread(char *buf, int len, struct file *filp) 
{ 
	int readlen; 
#ifdef set_fs
	mm_segment_t oldfs; 
#endif
	if (filp == NULL) 
		return -ENOENT; 

	if (filp->f_op->read == NULL) 
		return -ENOSYS; 

	if (((filp->f_flags & O_ACCMODE) & O_RDONLY) != 0) 
		return -EACCES; 

#ifdef set_fs
	oldfs = get_fs(); 
	set_fs(KERNEL_DS); 
#endif

	readlen = filp->f_op->read(filp, buf, len, &filp->f_pos); 

#ifdef set_fs
	set_fs(oldfs); 
#endif

	return readlen; 
}
EXPORT_SYMBOL(klib_fread);




int klib_fcopy(char *src, char *dst, int mode)
{
	int ret = -1, data_len;
	struct file *src_fp, *dst_fp = NULL;
	struct kstat stat;
	char *buffer = NULL;
#ifdef set_fs
	mm_segment_t oldfs; 
#endif

	src_fp = filp_open(src, O_RDONLY, 0);
	if(IS_ERR(src_fp)){
		DEBUG_MSG(HTTC_TSB_INFO,"Fail open src file[%s] by %ld\n", src, (long)IS_ERR(src_fp));
		return ret;
	}

	if(vfs_path_stat(src, &stat)){
		DEBUG_MSG(HTTC_TSB_INFO,"Fail stat src file[%s]\n", src);
		return ret;
	}

	dst_fp = filp_open(dst, O_WRONLY|O_CREAT|O_EXCL, 0777);
	if(IS_ERR(dst_fp)){
		filp_close(src_fp,0);
		DEBUG_MSG(HTTC_TSB_INFO,"Fail open dst file[%s] by %ld\n", dst, (long)IS_ERR(dst_fp));
		return ret;
	}

	buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if(!buffer){
		DEBUG_MSG(HTTC_TSB_INFO,"Fail kzalloc buffer\n");
		goto out;
	}

#ifdef set_fs
	oldfs = get_fs(); 
	set_fs(KERNEL_DS); 
#endif

	while((data_len = src_fp->f_op->read(src_fp, buffer, PAGE_SIZE, &src_fp->f_pos))>0){
		dst_fp->f_op->write(dst_fp, buffer, data_len, &dst_fp->f_pos); 
	}
	
#ifdef set_fs
	set_fs(oldfs); 
#endif
	
	ret = 0;

out:
	if(buffer)kfree(buffer);
	filp_close(dst_fp,0);
	filp_close(src_fp,0);

	return ret;
}
EXPORT_SYMBOL(klib_fcopy);

 




char *klib_fgets(char *str, int size, struct file *filp) 
{ 

	if (filp) 
	{
		char *cp;
		int len,readlen;
		for (cp = str, len = -1, readlen = 0; readlen < size - 1; ++cp, ++readlen) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
			if ((len = kernel_read(filp, cp, 1, &filp->f_pos)) <= 0) 
				break;
#else
			if ((len = kernel_read(filp, filp->f_pos, cp, 1)) <= 0) 
				break;
			filp->f_pos += len;
#endif		

			if (*cp == '\n') { 
				++cp; 
				++readlen; 
				break; 
			} 
		} 

		*cp = 0; 

		return (len < 0 || readlen == 0) ? NULL : str; 
	}
	else {
		return NULL; 
	}
} 
EXPORT_SYMBOL(klib_fgets);

// Context : User 
// Parameter : 
// buf : buffer containing data to write 
// len : number of bytes to write 
// filp : file pointer 
// Return : 
// actually written number. 0 = retry, negative = error 



int klib_fwrite(const char *buf, int len, struct file *filp)
{ 
	int writelen; 
#ifdef set_fs
	mm_segment_t oldfs; 
#endif

	if (filp == NULL) 
		return -ENOENT; 

	if (filp->f_op->write == NULL) 
		return -ENOSYS; 

	if (((filp->f_flags & O_ACCMODE) & (O_WRONLY | O_RDWR)) == 0) 
		return -EACCES; 

#ifdef set_fs
	oldfs = get_fs(); 
	set_fs(KERNEL_DS); 
#endif
	writelen = filp->f_op->write(filp, buf, len, &filp->f_pos); 
#ifdef set_fs
	set_fs(oldfs); 
#endif
	return writelen; 
} 

// Context : User 
// Parameter : 
// filp : file pointer 
// Return : 
// written character, EOF if error 




// Context : User 
// Parameter : 
// str : string 
// filp : file pointer 
// Return : 
// count of written characters. 0 = retry, negative = error 


 


// Context : User 
// Parameter : 
// filp : file pointer 
// fmt : printf() style formatting string 
// Return : 
// same as klib_fputs() 






// 
// Test Functions 
// 
#define MAXLINELEN 1024 





/*use sys_mkdirat to create directory in kernel space*/
static long (*origin_sys_mkdirat)(int dfd, const char __user *pathname, int mode) = NULL;
static int get_sys_mkdirat(void)
{
	if(hook_search_ksym("sys_mkdirat", (unsigned long *)&origin_sys_mkdirat) || !origin_sys_mkdirat)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"sys_call [sys_mkdir] not found \n");
		return -1;
	}
	return 0;
}

int klib_mkdir(char *pathname, int mode){
	char *ptr = pathname;
	
#ifdef set_fs
	mm_segment_t old_fs;
#endif
	
	if(!origin_sys_mkdirat && get_sys_mkdirat())
		return -1;
	
#ifdef set_fs
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	while(ptr && *ptr)
	{
		char save;
		while(*ptr == '/')ptr++; //skip all preceding '/'
		while(*ptr && *ptr != '/')ptr++; //find next '/' or null
		save = *ptr;
		*ptr = 0;
		origin_sys_mkdirat(AT_FDCWD, pathname, mode);
		*ptr = save;
	}
#ifdef set_fs
	set_fs(old_fs);
#endif
	return 0;
}

EXPORT_SYMBOL(klib_mkdir);


/* the head of passwd_info list */
struct passwd_info *passwd_info = NULL;

void parse_password_info(char *buffer, int len)
{
    char *p;
    struct passwd_info *info;
   
    info = (struct passwd_info *)dkzalloc(sizeof(struct passwd_info), GFP_KERNEL);
    if(info == NULL || IS_ERR(info))
        return;
    /*user name*/
	p = strsep(&buffer, SEPARATOR_COLOMN);
	if (!p || !*p)
		return;
    strncpy(info->user, p, MAX_USER_LEN);
    /*password*/
	p = strsep(&buffer, SEPARATOR_COLOMN);
	if (!p || !*p)
		return;
    /*uid*/
	p = strsep(&buffer, SEPARATOR_COLOMN);
	if (!p || !*p)
		return;
    info->uid = simple_strtoul(p, NULL, 10);
	if (info->uid < 0)
		return;    
    /*guid*/
	p = strsep(&buffer, SEPARATOR_COLOMN);
	if (!p || !*p)
		return;
    info->guid = simple_strtoul(p, NULL, 10);
	if (info->guid < 0)
		return;  

    if(passwd_info == NULL)
        passwd_info = info;
    else
    {
        struct passwd_info *tmp = passwd_info;
        while(tmp->next)
        {
            tmp = tmp->next;
        }
        tmp->next = info;
    }
}
EXPORT_SYMBOL(parse_password_info);

int get_password_info(void)
{
    int ret = -1;
#define MAX_LINE_LEN    256
    char buff[MAX_LINE_LEN];
    struct file *file;
    
    file = filp_open(ETC_PASSWORD, O_RDONLY, 0);
    if (!file)
    {
        goto out;
    }
    if (!file->f_op->read)
    {
        goto out;
    }
    while(klib_fgets(buff, MAX_LINE_LEN, file))
    {
        parse_password_info(buff, MAX_LINE_LEN);
    }

    ret = 0;
out:
    if(file != NULL)
        filp_close(file, NULL);
    return ret;
}
EXPORT_SYMBOL(get_password_info);

int put_password_info(void)
{
    struct passwd_info *next = get_passwd_info_head();
    struct passwd_info *tmp = NULL;
    
    while(next)
    {
        tmp = next->next;
        dkfree(next);
        next = tmp;
    }

    return 0;
}
EXPORT_SYMBOL(put_password_info);

struct passwd_info * get_passwd_info_head(void)
{
    return passwd_info;
}
EXPORT_SYMBOL(get_passwd_info_head);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
static struct vm_area_struct*  httcsec_futil_get_exemap(struct mm_struct *mm)
{
	if (mm) {
		struct vm_area_struct *vma = mm->mmap;
		while (vma) {
			if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
				return vma;
			}
			vma = vma->vm_next;
		}
	}
	return 0;
}


char *httcsec_get_exe_path(struct mm_struct *mm,char *buffer,int maxlen)
{
	struct vm_area_struct *vma = httcsec_futil_get_exemap(mm);
	if (vma && vma->vm_file)
	{
		return d_path(vma->vm_file->f_dentry,vma->vm_file->f_vfsmnt, buffer, maxlen);

	}
	return 0;
}

#else
char *httcsec_get_exe_path(struct mm_struct *mm,char *buffer,int maxlen)
{
	if (mm && mm->exe_file)
	{
		return d_path(&mm->exe_file->f_path, buffer, maxlen);
	}
	return 0;
}
#endif
EXPORT_SYMBOL(httcsec_get_exe_path);
