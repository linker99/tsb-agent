#include "tsbapi/tsb_admin.h"
/*
 * 	设置日志配置
 */
int tsb_set_log_config(const struct log_config *config){
	return 0;
}
/*
 * 	读取日志配置
 */
int tsb_get_log_config(struct log_config *config){
	return 0;
}

/*
 * 	轮转日志输出文件。
 */

int tsb_rotate_log_file(){
	return 0;
}
/*
 * 	读取内存日志。
 */
int tsb_read_inmem_log(unsigned char *buffer,int *length_inout,int *hashmore){
	return 0;
}

/*
 * 	非阻塞方式读取内存日志。
 */
int tsb_read_inmem_log_nonblock(unsigned char *buffer,int *length_inout,int *hashmore){
	return 0;
}

/*
 * 设置通知缓存条数
 */
int tsb_set_notice_cache_number(int num)
{
	return 0;
}

/*
 * 创建通知读取队列
 */
int tsb_create_notice_read_queue ()
{
	return 0;
}

/*
 *  close notify read queue
 */
void tsb_close_notice_read_queue(int fd)
{
	return ;
}

/*
 * 	写入内存通知。
 */
int tsb_write_notice(unsigned char *buffer, int length, int type)
{
	return 0;
}

/*
 * 	阻塞方式读取内存通知。
 */
int tsb_read_notice(int fd, struct notify **ppnode, int *num/*, unsigned int timeout*/)
{
	return 0;
}

/*
 * 	非阻塞方式读取内存通知。
 */
int tsb_read_notice_noblock(int fd, struct notify **ppnode, int *num)
{
	return 0;
}

/*
 * 	重新加载动态度量策略
 */
int tsb_reload_dmeasure_policy(){
	return 0;
}

/*
 * 	重新加载动态度量策略
 */
int tsb_set_dmeasure_policy(const char *buffer, int len){
	return 0;
}

/*
 * 增加进程度量策略
 */
int tsb_add_process_dmeasure_policy(const char *data ,int length){
	return 0;
}

/*
 * 删除进程度量策略
 */
int tsb_remove_process_dmeasure_policy(const char *data ,int length){
	return 0;
}

/*
 * 重新加载进程度量策略
 */
int tsb_reload_process_dmeasure_policy(){
	return 0;
}

/*
 * 	重置进程追踪防护策略
 */
int tsb_set_ptrace_process_policy(const char *data ,int length){
	return 0;
}

/*
 * 	重新加载进程追踪防护策略
 */
int tsb_reload_ptrace_process_policy(void){
	return 0;
}

/*
 * 	重新加载全局控制策略
 */
int tsb_reload_global_control_policy(){
	return 0;
}

/*
 * 	重新加载动态度量策略
 */
int tsb_set_global_control_policy(const char *buffer, int len){
	return 0;
}


int tsb_add_file_integrity(const char *data ,int length){
	return 0;
}
int tsb_remove_file_integrity(const char *data ,int length){
	return 0;
}
int tsb_reload_file_integrity(){
	return 0;
}

int tsb_reload_critical_confile_integrity(){
	return 0;
}

int tsb_set_process_ids(const char *data ,int length){
	return 0;
}
int tsb_set_process_roles(const char *data ,int length){
	return 0;
}
int tsb_reload_process_roles(){
	return 0;
}
int tsb_reload_process_ids(){
	return 0;
}

int tsb_set_tnc_policy(const char *data){
	return 0;
}

int write_user_log(const char *data ,int length){
	return 0;
}
/*
 * 重新加载文件访问控制策略
 */
int tsb_reload_file_protect_policy(){
	return 0;
}

/*
 * 重新加载特权进程策略
 */
/*int tsb_reload_privilege_process_policy(){
	return 0;
} */

/*
 * 重新加载cdrom策略
 */
int tsb_reload_cdrom_config()
{
	return 0;
}
/*
 * 重新加载udisk策略
 */
int tsb_reload_udisk_config(void)
{
	return 0;
}

/*
 * 重新加载network策略
 */
int tsb_reload_network(void)
{
	return 0;
}