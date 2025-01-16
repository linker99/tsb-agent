#include <linux/module.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include "utils/debug.h"



#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
int noop_pre(struct kprobe *p, struct pt_regs *regs) 
{ 
	return 0;
}

static struct kprobe kp = 
{
	.symbol_name = "__module_address",
};

struct module *(*find_module_address)(unsigned long addr) = NULL;

int find___module_address(void)
{
	int ret = -1;
         unsigned long *sym_address; 
	kp.pre_handler = noop_pre;
	ret = register_kprobe(&kp);
	if (ret < 0) 
	{
		DEBUG_MSG(HTTC_TSB_INFO, "register_kprobe failed, error:%d\n", ret);
		return ret;
        }

		DEBUG_MSG(HTTC_TSB_DEBUG, "__module_address addr: %p\n", kp.addr);
        sym_address = (void *)kp.addr;
		 DEBUG_MSG(HTTC_TSB_DEBUG, "sym_address %px\n", (void*)sym_address);
	//find_module_address = (void*)kp.addr;
	find_module_address = (void*)sym_address;
	unregister_kprobe(&kp);
	return ret;
}

int utils_init(void) 
{
	int ret = 0;
	ret = find___module_address();
	return ret;
}
#endif

struct module *get_module_from_addr(unsigned long addr)
{
	struct module *mod;

	//mutex_lock(&module_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	if(find_module_address == NULL)
		return NULL;

	mod = find_module_address(addr);
#else
	mutex_lock(&module_mutex);
	mod = __module_address(addr);
	mutex_unlock(&module_mutex);
#endif
	/* if (!mod) { */
	/*         mod = find_hidden_module_from_addr(addr); */
	/* } */
	//mutex_unlock(&module_mutex);

	return mod;
}

void print_hex(const char *name, unsigned char *p, int len)
{
	int i = 0;

	//printk("name[%s] len[%d]\n", name, len);
	printk("file_name[%s], hash[", name);
	for (i = 0; i < len; i++) {
		printk("%02X", p[i]);
	}
	printk("]\n");
}
