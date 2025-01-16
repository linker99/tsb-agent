#include <linux/version.h>
#include <linux/init.h>     // module_{init,exit}()
#include <linux/module.h>   // THIS_MODULE, MODULE_VERSION, ...
#include <linux/kernel.h>   // printk(), pr_*()
#include <linux/kallsyms.h> // kallsyms_lookup_name()
//#include <asm/syscall.h>    // syscall_fn_t, __NR_*
#include <asm/ptrace.h>     // struct pt_regs
#include <linux/vmalloc.h>  // vm_unmap_aliases()
#include <linux/mm.h>       // struct mm_struct, apply_to_page_range()
//#include <linux/kconfig.h>  // IS_ENABLED()


static struct mm_struct *init_mm_ptr;

static unsigned long kgdb_notify_addr = 0xffffffff;
module_param(kgdb_notify_addr, ulong, 0644);
MODULE_PARM_DESC(kgdb_notify_addr, "ulong kgdb_notify saddress");

void *origin_kgdb_notify = NULL;


#if defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
#include <asm/tlbflush.h>   // flush_tlb_kernel_range()
#include <asm/pgtable.h>    // {clear,set}_pte_bit(), set_pte()
/********** HELPERS **********/
// From arch/arm64/mm/pageattr.c.
struct page_change_data {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

// From arch/arm64/mm/pageattr.c.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
#else
static int change_page_range(pte_t *ptep, pgtable_t token, unsigned long addr, void *data)
#endif
{
	struct page_change_data *cdata = data;
	pte_t pte = READ_ONCE(*ptep);

	pte = clear_pte_bit(pte, cdata->clear_mask);
	pte = set_pte_bit(pte, cdata->set_mask);

	set_pte(ptep, pte);
	return 0;
}

// From arch/arm64/mm/pageattr.c.
static int __change_memory_common(unsigned long start, unsigned long size,
				  pgprot_t set_mask, pgprot_t clear_mask)
{
	struct page_change_data data;
	int ret;

	data.set_mask = set_mask;
	data.clear_mask = clear_mask;

	ret = apply_to_page_range(init_mm_ptr, start, size, change_page_range, &data);

	flush_tlb_kernel_range(start, start + size);
	return ret;
}

// Simplified set_memory_rw() from arch/arm64/mm/pageattr.c.
static int set_page_rw(unsigned long addr)
{
	vm_unmap_aliases();
	return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_WRITE), __pgprot(PTE_RDONLY));
}

// Simplified set_memory_ro() from arch/arm64/mm/pageattr.c.
static int set_page_ro(unsigned long addr)
{
	vm_unmap_aliases();
	return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_RDONLY), __pgprot(PTE_WRITE));
}
#endif
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

static unsigned int inline set_kernel_writable(void)
{
#if defined(__x86_64__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 90)
	unsigned int cr0 = 0;
	unsigned int ret;
	asm volatile ("movq %%cr0, %%rax": "=a"(cr0));
	ret = cr0;
	cr0 &= 0xfffeffff;
	asm volatile ("movq %%rax, %%cr0"::"a"(cr0));
	return ret;
#else
	write_cr0(read_cr0() & ~X86_CR0_WP);
	return 0;
#endif
#endif
}

static void inline set_kernel_readonly(unsigned int cr0)
{
#if defined(__x86_64__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 90)
	asm volatile ("movq %%rax, %%cr0": : "a"(cr0));
#else
	write_cr0(read_cr0() | X86_CR0_WP);
#endif
#endif
}

static int kernel_args_addr_init(void)
{
	int ret = 0;

	if (kgdb_notify_addr == 0xffffffff || kgdb_notify_addr == 0) {
		printk("Insmod [kgdb_notify_addr] Argument Error!\n");
		return -EINVAL;
	} else {
		printk("kgdb_notify addr:[%0lx]!\n", kgdb_notify_addr);
	}

	origin_kgdb_notify = (void *)kgdb_notify_addr;

	return ret;
}

unsigned char data[1];
static int __init modinit(void)
{
	int res = 0;
	char *p = NULL;
	unsigned int cr0 = 0;

	printk("init\n");


	res = kernel_args_addr_init();
	if (res)
		goto out;
	p = (void *)origin_kgdb_notify;

#if defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name("init_mm");
	res = set_page_rw((kgdb_notify_addr + 100) & PAGE_MASK);
	if (res != 0) {
		pr_err("set_page_rw() failed: %d\n", res);
		return res;
	}
#endif
#endif
	cr0 = set_kernel_writable();

	
	printk("start replace!\n");
	dump_hex(origin_kgdb_notify, 5);
	data[0] = (unsigned char)p[1];
	p[1] = 0x2f;
	dump_hex(origin_kgdb_notify, 5);

#if defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	res = set_page_ro((kgdb_notify_addr + 100) & PAGE_MASK);
	if (res != 0) {
		pr_err("set_page_ro() failed: %d\n", res);
		return res;
	}
#endif
#endif
	set_kernel_readonly(cr0);

	printk("init done\n");

out:
	return res;
}

static void __exit modexit(void)
{
	int res = 0;
	char *p = NULL;
	unsigned int cr0 = 0;

	printk("exit\n");

#if defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	res = set_page_rw((kgdb_notify_addr + 100) & PAGE_MASK);
	if (res != 0) {
		pr_err("set_page_rw() failed: %d\n", res);
		return;
	}
#endif
#endif
	cr0 = set_kernel_writable();


	p = (void *)origin_kgdb_notify;
	dump_hex(origin_kgdb_notify, 5);
	p[1] = data[0];
	dump_hex(origin_kgdb_notify, 5);


#if defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	res = set_page_ro((kgdb_notify_addr + 100) & PAGE_MASK);
	if (res != 0)
		pr_err("set_page_ro() failed: %d\n", res);
#endif
#endif
	set_kernel_readonly(cr0);

	printk("goodbye\n");
}

module_init(modinit);
module_exit(modexit);
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("Syscall hijack on arm64.");
MODULE_AUTHOR("Marco Bonelli");
MODULE_LICENSE("GPL");
