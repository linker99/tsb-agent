#ifndef UTIL_H_
#define UTIL_H_

//后台运行
void daemonize();

//守护进程
int	KeepAlive();

//通过进程名称获取进程ID
int getPidByName(char* task_name);

//执行linux系统命令，并返回结果
int RunCmdGetResult(char* cmd, char* buf, int len);

//过滤"\n"换行符
int filterLF(char* buf);

//得到当前进程的全路径名称
int GetLinuxModuleFileName(char* szFileName, int iLen);

#endif //UTIL_H_
