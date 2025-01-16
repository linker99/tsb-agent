

#ifndef TSBAPI_TSB_MEASURE_KERNEL_H_
#define TSBAPI_TSB_MEASURE_KERNEL_H_

enum{
	TSB_MEASURE_FAILE = 1,
	TSB_ERROR_CALC_HASH,
	TSB_ERROR_SYSTEM,
};

/** whitelist error */
enum{
	TSB_ERROR_FILE = 100,
};

/** dmeasure error */
enum{
	TSB_ERROR_DMEASURE_POLICY_NOT_FOUND = 200,
	TSB_ERROR_DMEASURE_NAME,
};

/** process identity error */
enum{
	TSB_ERROR_PROCESS_IDENTITY_POLICY = 300,
};


/*
 * 	度量文件完整性，只匹配HASH
 * 	导出到用户空间
 */
int tsb_measure_file(const char *path);

/*
 *
 * 	度量文件完整性，只匹配HASH,传文件指针
 * 	不导出到用户空间
 */

int tsb_measure_file_filp(struct file *filp);

/*
 *	度量文件完整性，匹配路径和HASH
 *	导出到用户空间
 */
int tsb_measure_file_path(const char *path);

/*
 *	度量文件完整性，匹配路径和HASH，传文件指针
 *	不导出到用户空间
 */
int tsb_measure_file_path_filp(struct file *filp);

/*
 *
 *	度量文件完整性，匹配指定路径和HASH，传文件指针
 *	不导出到用户空间
 */
int tsb_measure_file_specific_path_filp(const char *path,struct file *filp);


/*
 * 	基准库匹配
 */
int tsb_match_file_integrity(const unsigned char *hash, int hash_length);
/*
 * 	基准库按路径名匹配
 */
int tsb_match_file_integrity_by_path(
		const unsigned char *hash, int hash_length,
		const unsigned char *path, int path_length);

/*
 * 	进程动态度量和进程身份认证接口
 */


/*
 * 	进程动态度量，传进程ID
 * 	pid=0度量当前进程
 *	导出到用户空间
 */
int tsb_measure_process(unsigned pid);
/*
 * 	进程动态度量，传进程指针
 * 	不导出到用户空间
 */
int tsb_measure_process_taskp(struct task_struct *task);



/*
 * 度量指定内核段
 */
int tsb_measure_kernel_memory(const char *name);

/*
 * 度量所有内核段
 * (代码，系统调用表，中断表)
 */
int tsb_measure_kernel_memory_all(void);


/*
 * 	进程身份认证，传进程ID
 * 	pid=0认证当前进程
 * 	导出到用户空间
 */
int tsb_verify_process(int pid,const char *name);



/*
 * 	进程身份认证，传进程指针
 * 	不导出到用户空间
 */
int tsb_verify_process_taskp(struct task_struct *task,const char *name);


/*
  * 获取当前进程身份
 */
int tsb_get_process_identity(unsigned char *process_name,int *process_name_length);

/*
  *  获取当前用户角色
 */
int tsb_is_role_member(const unsigned char *role_name);
#endif /* TSBAPI_TSB_MEASURE_KERNEL_H_ */
