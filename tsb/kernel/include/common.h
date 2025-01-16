#ifndef __HTTC_COMMON_H__
#define __HTTC_COMMON_H__


#define LEN_HASH  32

#define BASE_PATH "/usr/local/httcsec/"

#define BYTE4_ALIGNMENT(len)		\
	if((len%4) != 0)		\
		len += 4-len%4

struct tsb_general_policy
{
	int length;
	const char *data;
};

struct tsb_user_interface_parameter
{
	int type;
	int length;
	const char *data;
};

struct tsb_user_read_memory_log_parameter
{
	int  *hasmore;
	int  *length;
	char *data;
};

/* whitelist user interface type */
enum{
	TYPE_WHITELIST_MEASURE_FILE  = 1,
	TYPE_WHITELIST_MEASURE_FILE_PATH,
	TYPE_WHITELIST_MATCH_FILE,
	TYPE_WHITELIST_MATCH_FILE_PATH,
};

/* dmesure user interface type */
enum{
	TYPE_DMEASURE_KERNEL_MEMORY  = 1,
	TYPE_DMEASURE_KERNEL_MEMORY_ALL,
	TYPE_DMEASURE_PROCESS,
};

/* process identity user interface type */
enum{
	TYPE_PROCESS_IDENTITY_VERIFY  = 1,
	TYPE_PROCESS_IDENTITY_GET,
	TYPE_PROCESS_IDENTITY_ROLE,
};

#endif	/* __HTTC_COMMON_H__ */
