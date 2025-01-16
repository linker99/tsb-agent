#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	int i = 100;
	int ret = 0;
	char *ptr;

	ptr = malloc(32);
	if (!ptr)
		goto out;

	while (i > 0) {
		printf("hello world!\n");
		sleep(1);
		i--;
	}
	free(ptr);

out:
	return ret;
}
