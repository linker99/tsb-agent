#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <sys/utsname.h>  
#include <stdio_ext.h>  
  
int main() {  
    FILE *fp;
    char cmd[256];
    char cmdOutput[1024];
  
    // 获取设备型号
    memset(cmd, 0, sizeof(cmd));
    memset(cmdOutput, 0, sizeof(cmdOutput));
    sprintf(cmd, "dmidecode | grep -m 1 'Product Name'  |uniq | cut -d: -f2");
    fp = popen(cmd, "r");  
    if (fp != NULL) {  
        fgets(cmdOutput, sizeof(cmdOutput), fp);  
        printf("设备型号: %s", cmdOutput);  
        pclose(fp);  
    } else {  
        printf("没有获取到设备型号\n");  
    }
  
    // 获取系统架构  
    memset(cmd, 0, sizeof(cmd));
    memset(cmdOutput, 0, sizeof(cmdOutput));
    sprintf(cmd, "uname -p");
    fp = popen(cmd, "r");  
    if (fp != NULL) {  
        fgets(cmdOutput, sizeof(cmdOutput), fp);  
        printf("系统架构: %s", cmdOutput);  
        pclose(fp);  
    } else {  
        printf("没有获取到系统架构\n");  
    }
  
    // 获取CPU型号  
    memset(cmd, 0, sizeof(cmd));
    memset(cmdOutput, 0, sizeof(cmdOutput));
    sprintf(cmd, "lscpu |grep 'Model name' | uniq | cut -d: -f2");
    fp = popen(cmd, "r");  
    if (fp != NULL) {  
        fgets(cmdOutput, sizeof(cmdOutput), fp);  
        printf("CPU 型号: %s", cmdOutput);  
        pclose(fp);  
    } else {  
        memset(cmd, 0, sizeof(cmd));
        memset(cmdOutput, 0, sizeof(cmdOutput));
        sprintf(cmd, "lscpu |grep '型号名称' uniq | cut -d： -f2");
        fp = popen(cmd, "r");
        if (fp != NULL) {
            fgets(cmdOutput, sizeof(cmdOutput), fp);  
            printf("CPU 型号: %s", cmdOutput);  
            pclose(fp);
        } else {
            printf("没有获取到CPU型号\n");  
        }
    }  
  
    // 获取主板信息  
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "dmidecode -t baseboard");
    fp = popen(cmd, "r");  
    if (fp != NULL) {
        printf("主板信息: \n"); 
        while(!feof(fp)){
			memset(cmdOutput,0,sizeof(cmdOutput));

			if(fgets(cmdOutput, sizeof(cmdOutput), fp) == NULL){
				break;
			}	

			printf("%s", cmdOutput);	
		}    
        pclose(fp);  
    } else {  
        printf("没有获取到主板信息\n");  
    }
  
    // 获取BIOS固件版本  
    memset(cmd, 0, sizeof(cmd));
    memset(cmdOutput, 0, sizeof(cmdOutput));
    sprintf(cmd, "dmidecode -s bios-version");
    fp = popen(cmd, "r");  
    if (fp != NULL) {  
        fgets(cmdOutput, sizeof(cmdOutput), fp);  
        printf("BIOS 固件版本: %s", cmdOutput);  
        pclose(fp);  
    } else {  
        printf("没有获取到BIOS固件版本\n");  
    }  
  
    // 获取系统版本
    memset(cmd, 0, sizeof(cmd));
    memset(cmdOutput, 0, sizeof(cmdOutput));
    sprintf(cmd, "cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2-");
    fp = popen(cmd, "r");  
    if (fp != NULL) {  
        fgets(cmdOutput, sizeof(cmdOutput), fp);  
        printf("系统版本: %s", cmdOutput);  
        pclose(fp);  
    } else {  
        printf("没有获取到系统版本\n");  
    }
  
    // 获取内核版本  
    memset(cmd, 0, sizeof(cmd));
    memset(cmdOutput, 0, sizeof(cmdOutput));
    sprintf(cmd, "uname -r");
    fp = popen(cmd, "r");  
    if (fp != NULL) {  
        fgets(cmdOutput, sizeof(cmdOutput), fp);  
        printf("内核版本: %s", cmdOutput);  
        pclose(fp);  
    } else {  
        printf("没有获取到内核版本\n");  
    }

    // 获取当前qt版本 
    memset(cmd, 0, sizeof(cmd));
    memset(cmdOutput, 0, sizeof(cmdOutput));
    sprintf(cmd, "rpm -qa|grep -i qt");
    fp = popen(cmd, "r");  
    if (fp != NULL) {  
        fgets(cmdOutput, sizeof(cmdOutput), fp);  
        if(strlen(cmdOutput) > 0){
            printf("QT版本: %s", cmdOutput);  
        }else{
            printf("没有获取到QT版本\n");
        }
        pclose(fp);  
    }else {  
        printf("没有获取到QT版本\n");  
    }

    return 0;
}
