#include <stdio.h>
#include <stdint.h>


static void usage ()
{
	printf ("\n"
			"Usage:  ./tpcm_switch -o 0\t关闭tpcm开关\n"
			"        ./tpcm_switch -o 1\t打开tpcm开关\n"
			"        ./tpcm_switch -o 2\t获取tpcm开关状态\n"
		);
}
extern int tcs_set_tpcm_switch(uint32_t value);
extern int tcs_get_tpcm_switch(uint32_t *value);

int main(int argc,char **argv){
	int ret = 0;

	if(argc < 3){
		usage();
		return -1;
	}
	int op = argv[2][0] - '0';
	if( 1 == op || 0 == op )
	{
		ret = tcs_set_tpcm_switch(op);	
		if(ret)
		{
			printf("set tpcm switch %d failed, return value %d(%x)\n",op,ret,ret);
		}else{
			printf("set tpcm switch %d sucess\n", op);

		}
	}else if( 2 == op )
	{
		int status = -1;
		ret = tcs_get_tpcm_switch(&status);
		if(ret)
		{
			printf("get tpcm switch %d failed, return value %d(%x)\n",op,ret,ret);
		}else{
			printf("tpcm switch status is %d\n",status);

		}
	}else{
		usage();
		return -1;
	}
out:
	return ret;

}

