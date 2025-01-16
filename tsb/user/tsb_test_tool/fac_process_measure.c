#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv)
{
	char buf[4096] = {0};

	while(1)
	{
		FILE *fp = fopen("/root/hyq/test/a.log", "r+");
		if (!fp)
		{
			printf("fopen errror!\n");
			sleep(3);
			continue;
		}
		fread(buf, 1, 100, fp);
		fclose(fp);
		printf("----buf[%s]-----\n", buf);

		sleep(3);
	}

	return 0;
}