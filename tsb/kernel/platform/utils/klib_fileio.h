/*
 * klib_fileio.h
 *
 */

#ifndef KLIB_FILEIO_H_
#define KLIB_FILEIO_H_



#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <asm/processor.h>
//#include <asm/uaccess.h>
#include <linux/stat.h>
#include <linux/slab.h>



#define EOF (-1)
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define ETC_PASSWORD        "/etc/passwd"
#define SEPARATOR_COLOMN    ":"
#define MAX_USER_LEN        32

struct passwd_info
{
    int  uid;
    int  guid;
    char user[MAX_USER_LEN];
    struct passwd_info *next;
};

// Function Prototypes

int klib_fseek(struct file *filp, int offset, int whence);

int klib_fread(char *buf, int len, struct file *filp);

int klib_fgetc(struct file *filp);

char *klib_fgets(char *str, int size, struct file *filp);

int klib_fwrite(const char *buf, int len, struct file *filp);

int klib_fputc(int ch, struct file *filp);

int klib_fputs(char *str, struct file *filp);

int klib_fprintf(struct file *filp, const char *fmt, ...);

int klib_stat(const char *filename, struct kstat *stat) ;

char *klib_fgetpath(struct file *filp, char *buf, int buflen);

int httcsec_futil_read_from(char *buf, int offset,int len, struct file *filp);
//int httcsec_futil_read_from_mem(char *buf, int offset,int len, char *policy_buffer);

int klib_mkdir(char *pathname, int mode);

int klib_fcopy(char *src, char *dst, int mode);

/* read /etc/passwd file and save */
int get_password_info(void);
/* free malloced memory */
int put_password_info(void);
/* get passwd_info list */
struct passwd_info * get_passwd_info_head(void);

char *httcsec_get_exe_path(struct mm_struct *mm,char *buffer,int maxlen);

#endif /* KLIB_FILEIO_H_ */
