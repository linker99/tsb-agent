#include <linux/kernel.h>
int hook_search_ksym(const char * sym_name, unsigned long *sym_addr)
{
	return 0;
}

