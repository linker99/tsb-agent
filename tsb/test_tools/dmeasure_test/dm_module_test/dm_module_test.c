#include <linux/module.h>
#include <linux/version.h>
#include <net/sock.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>  

#define TEST_ITEM	"hellomodule"
#define HACK_SIZE 32 
static struct mm_struct *init_mm_ptr = NULL;

static unsigned long init_mm_address = 0xFFFFFFFFFFFFFFFF;
module_param(init_mm_address, ulong, 0644);
MODULE_PARM_DESC(init_mm_address, "ulong init_mm_address address");

struct module *item = NULL;
static char buff[32] = {0};

int original_writeable = 0;

/********** HELPERS **********/
#if defined(CONFIG_ARM64)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
static inline int pmd_huge(pmd_t pmd)
{
        return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}

int set_memory_page_wp(unsigned long addr, int writeable)
{
        pgd_t *pgd;
        pte_t *ptep = 0;
        pud_t *pud;
        pmd_t *pmd;
        pte_t pte;

        //struct mm_struct *pinit_mm = current->mm;
        struct mm_struct *pinit_mm = init_mm_ptr;
        pgd = pgd_offset(pinit_mm,addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)){
                goto out;
        }

        pud = pud_offset(pgd, addr);
        if (pud_none(*pud) || pud_bad(*pud)){
                goto out;
        }

        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) ){
                goto out;
        }
        if(pmd_huge(*pmd)){
                pte = pmd_pte(*pmd);
        }
        else if(pmd_bad(*pmd)){
                goto out;
        }
        else{
                ptep = pte_offset_map(pmd, addr);
                pte = *ptep;
                if (pte_none(pte)){
                        goto out;
                }
        }
        if(writeable)
        {
                original_writeable = pte_write(pte);
                if (original_writeable)
                {
                        return 0;
                }
                pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
                pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY));
        }
        else
        {
                if (original_writeable)
                {
                        return 0;
                }
                pte = clear_pte_bit(pte, __pgprot(PTE_WRITE));
                pte = set_pte_bit(pte, __pgprot(PTE_RDONLY));
        }

        if(ptep)
        {
                set_pte(ptep,pte);
        }
        else
        {
                set_pmd(pmd,pte_pmd(pte));
        }
        flush_tlb_all();

        return 0;

out:
        return -1;
}
#endif

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
#else
	return 0;
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

static int dmeasure_test_modify_module(void)
{
        int ret = 0;
        struct list_head *modules_head;
        struct module *mod = NULL;
	unsigned int cr0 = 0;
		
        modules_head = (&__this_module)->list.prev;
		
        /* replace */
        list_for_each_entry_rcu(mod, modules_head, list) {
                if (!strncmp(mod->name, TEST_ITEM, strlen(TEST_ITEM))) {
                        printk("changing module_core of module:[%s]\n", mod->name);
                        item = mod;

						cr0 = set_kernel_writable();
#if defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
						ret = set_memory_page_wp( ((unsigned long)mod->core_layout.base + 100) & PAGE_MASK, 1);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0) 
						ret = set_page_rw(((unsigned long)mod->core_layout.base + 100) & PAGE_MASK);
						if (ret != 0) {
							printk("set_page_rw() failed: %d\n", ret);
							return ret;
						}
#endif
#endif
						printk("before changing, %s module_core is \n", mod->name);
						dump_hex(mod->core_layout.base, HACK_SIZE);

						memcpy(buff, mod->core_layout.base, HACK_SIZE);
						memset(mod->core_layout.base, 0xFF, HACK_SIZE);
						printk("after changing, %s module_core is \n", mod->name);
						dump_hex(mod->core_layout.base, HACK_SIZE);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
#if defined(CONFIG_ARM64)
						ret = set_memory_page_wp( ((unsigned long)mod->core_layout.base + 100) & PAGE_MASK, 0);
#endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0) 
#if defined(CONFIG_ARM64)
						ret = set_page_ro(((unsigned long)mod->core_layout.base + 100) & PAGE_MASK);
						if (ret != 0) {
							printk("set_page_ro() failed: %d\n", ret);
							return ret;
						}
#endif
#else
#if defined(CONFIG_ARM64)
						ret = set_page_rw(((unsigned long)mod->module_core + 100) & PAGE_MASK);
						if (ret != 0) {
							printk("set_page_rw() failed: %d\n", ret);
							return ret;
						}
#endif
						printk("before changing, %s module_core is \n", mod->name);
						dump_hex(mod->module_core, HACK_SIZE);

						memcpy(buff, mod->module_core, HACK_SIZE);
						memset(mod->module_core, 0xFF, HACK_SIZE);
						printk("after changing, %s module_core is \n", mod->name);
						dump_hex(mod->module_core, HACK_SIZE);
#if defined(CONFIG_ARM64)
						ret = set_page_ro(((unsigned long)mod->module_core + 100) & PAGE_MASK);
						if (ret != 0) {
							printk("set_page_ro() failed: %d\n", ret);
							return ret;
						}
#endif
#endif
                        set_kernel_readonly(cr0);

                        break;
                }
        }

		if(!item) {
			printk("error! hellomodule.ko donot exist! attack is invalid!\n");
			ret = -1;
		}

        return ret;
}

static int test_module_init(void)
{
        int ret = 0;
		
		//init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name("init_mm");
		//if (!init_mm_ptr)
		//{
		//	printk("Do not find init_mm!\n");
		//	return -1;
		//}
		if ((init_mm_address == 0xFFFFFFFFFFFFFFFF || init_mm_address == 0)) {
			printk("Enter[%s] Insmod Argument Error!\n",__func__);
			return -EINVAL;
		}
		init_mm_ptr = (struct mm_struct *)init_mm_address;
		
        ret = dmeasure_test_modify_module();
        if (ret)
                printk("dmeasure module error!\n");

        return ret;
}

static void test_module_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
#if defined(CONFIG_ARM64)
	int ret = 0;
#endif
#endif
	unsigned int cr0 = 0;

	if(!item) {
		printk("test_module_exit failed\n");
		return;
	}
	/* recovery */
	printk("changing module_core of module '%s' back\n", item->name);
	cr0 = set_kernel_writable();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
#if defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	ret = set_memory_page_wp( ((unsigned long)item->core_layout.base + 100) & PAGE_MASK, 1);
#else
	ret = set_page_rw(((unsigned long)item->core_layout.base + 100) & PAGE_MASK);
	if (ret != 0) {
		printk("set_page_rw() failed: %d\n", ret);
		return;
	}
#endif
#endif
	dump_hex(item->core_layout.base, HACK_SIZE);
	memset(item->core_layout.base, 0, HACK_SIZE);
	memcpy(item->core_layout.base, buff ,HACK_SIZE);
	dump_hex(item->core_layout.base, HACK_SIZE);
#if defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	ret = set_memory_page_wp( ((unsigned long)item->core_layout.base + 100) & PAGE_MASK, 0);
#else
	ret = set_page_ro(((unsigned long)item->core_layout.base + 100) & PAGE_MASK);
	if (ret != 0) {
		printk("set_page_ro() failed: %d\n", ret);
		return;
	}
#endif
#endif
#else
#if defined(CONFIG_ARM64)
	ret = set_page_rw(((unsigned long)item->module_core + 100) & PAGE_MASK);
	if (ret != 0) {
		printk("set_page_rw() failed: %d\n", ret);
		return;
	}
#endif
	dump_hex(item->module_core, HACK_SIZE);
	memset(item->module_core, 0, HACK_SIZE);
	memcpy(item->module_core, buff ,HACK_SIZE);
	dump_hex(item->module_core, HACK_SIZE);
#if defined(CONFIG_ARM64)
	ret = set_page_ro(((unsigned long)item->module_core + 100) & PAGE_MASK);
	if (ret != 0) {
		printk("set_page_ro() failed: %d\n", ret);
		return;
	}
#endif
#endif
	set_kernel_readonly(cr0);
	printk("test_module_exit success!\n");
    	return;
}

module_init(test_module_init);
module_exit(test_module_exit);

MODULE_AUTHOR("HTTC");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("HTTCSEC MODULE TEST");

