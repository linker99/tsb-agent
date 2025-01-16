#include <linux/module.h>
#include <net/sock.h>
#include <asm/desc.h>

static struct desc_struct *gd = NULL;
static struct desc_struct buffer;

#if defined(__x86_64__)
int set_kernel_wp(int writable, unsigned int val)
{
	unsigned int ret = 0;
	if (writable)
	{
		unsigned int cr0 = 0;
		asm volatile ("movq %%cr0, %%rax": "=a"(cr0));
		ret = cr0;
		cr0 &= 0xfffeffff;
		asm volatile ("movq %%rax, %%cr0"::"a"(cr0));
	}
	else
	{
		asm volatile ("movq %%rax, %%cr0": : "a"(val));
	}
	return ret;
}
#endif

void dump_hex(void *p, int bytes)
{
	int i = 0;
	char *data = p;
	int add_newline = 1;

	if (bytes != 0) {
		printk("0x%.2x.", (unsigned char)data[i]);
		i++;
	}
	while (i < bytes) {
		printk("0x%.2x.", (unsigned char)data[i]);
		i++;
		if (i % 16 == 0) {
			printk("\n");
			add_newline = 0;
		} else
			add_newline = 1;
	}
	if (add_newline)
		printk("\n");
}

static int dmeasure_test_modify_idt(void)
{
	int ret = 0;
	unsigned int cr0 = 0;
	unsigned char pad = 0x5a;
	struct desc_ptr idt;

	store_idt(&idt);
	printk("idt address:[%p], idt size:[%d]\n", (void *)idt.address, idt.size);
	gd = ((struct desc_struct *)idt.address) + 254;

	/* replace */
	//write_cr0(read_cr0() & ~X86_CR0_WP);
	cr0 = set_kernel_wp(1, cr0);
	printk("before change, value is ");
	dump_hex(gd, sizeof(struct desc_struct));
	memcpy(&buffer, gd, sizeof(struct desc_struct));

	memset(gd, pad, sizeof(struct desc_struct));
	printk("after change, value is ");
	dump_hex(gd, sizeof(struct desc_struct));
	set_kernel_wp(0, cr0);
	//write_cr0(read_cr0() | X86_CR0_WP);

	/* recovery */
	//msleep(60*1000);
	//write_cr0(read_cr0() & ~X86_CR0_WP);
	//memcpy(gd, &buffer, sizeof(struct desc_struct));
	//printk("change idt value back, and changing back value is ");
	//dump_hex(gd, sizeof(struct desc_struct));
	//write_cr0(read_cr0() | X86_CR0_WP);

	return ret;
}


static int test_idt_init(void)
{
	int ret = 0;

	ret = dmeasure_test_modify_idt();
	if (ret)
		printk("dmeasure idt error!\n");

	return ret;
}

static void test_idt_exit(void)
{
	unsigned int cr0 = 0;
	/* recovery */
	//msleep(60*1000);
	//write_cr0(read_cr0() & ~X86_CR0_WP);
	cr0 = set_kernel_wp(1, cr0);
	memcpy(gd, &buffer, sizeof(struct desc_struct));
	printk("change idt value back, and changing back value is ");
	dump_hex(gd, sizeof(struct desc_struct));
	set_kernel_wp(0, cr0);
	//write_cr0(read_cr0() | X86_CR0_WP);

	return;
}

module_init(test_idt_init);
module_exit(test_idt_exit);

MODULE_AUTHOR("HTTC");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("HTTCSEC NET TEST");

