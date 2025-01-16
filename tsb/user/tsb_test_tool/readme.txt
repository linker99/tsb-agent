白名单测试工具：
scan_tool目录  作用：扫描全盘文件生成白名单策略文件whitelist
whitelist_product.c   作用：将文件whitelist中的白名单策略，转换格式，生成tsb可以加载的白名单策略文件integrity.data
whitelist_test.c   作用：调用tsb应用层接口，添加、删除、重新加载白名单策略

动态度量测试工具：
dmesure_test.c  功能：修改动态度量开关以及度量间隔时间
dmesure_process_test.c   功能：下发进程动态度量策略

文件访问控制测试工具：
fac_test.c   功能：调用tsb应用层接口，通知tsb重新加载文件访问控制策略文件
fac_write.c  功能：生成文件访问控制策略文件file_protect.data

配置全局策略测试工具：
global_test.c

审计策略测试工具（写什么样的日志到文件中，成功、失败或者全审计）
log_config_test.c   功能：调用tsb应用层接口，通知tsb重新加载审计策略文件
log_config_write.c  功能：生成审计策略文件log_config

读日志测试工具：
log_mem_block_test.c  功能：调用tsb应用层接口，以阻塞方式从内存中读取日志（奔图项目使用）
log_mem_nonblock_recv.c  功能：调用tsb应用层接口，以非阻塞方式从内存中读取日志，并写到固定文件中（奔图项目使用）
log_mem_nonblock_test.c  功能：调用tsb应用层接口，以非阻塞方式从内存中读取日志（奔图项目使用）
log_test.c  功能：从日志文件tsb.log中，读取日志

进程身份测试工具：
process_identity_hash_file.sh   功能：将指定进程以及所用库的全路径写到文件process_identity_hash_file.txt中
process_identity_test.c  功能：从process_identity_hash_file.txt中，读取路径，计算文件hash，调用tsb应用层接口，将进程身份策略下发给tsb
process_roles_test.c  功能：调用tsb应用层接口，将进程角色策略下发给tsb

ptrace测试工具：
ptrace_test.c  功能：调用tsb应用层接口，将ptrace策略下发给tsb

应用层接口测试工具（文件tsbapi/tsb_measure_user.h中，提供的应用层接口）
tsb_user_interface_test.c  

测试工具，通过调用用户态接口write_user_log写日志
write_user_log_test.c