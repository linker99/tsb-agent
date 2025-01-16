#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <asm/tlbflush.h>
//#include <linux/unistd.h>
//#include <asm/syscall.h>
//#include <asm-generic/unistd.h>
#if defined(CONFIG_SW)
#include <asm-generic/unistd.h>
#else
#include <linux/unistd.h>
#if defined(__i386__) || defined(__x86_64__)
#include <asm/syscall.h>
#endif
#endif

static unsigned long syscall_table = 0xffffffff;
module_param(syscall_table, ulong, 0644);
MODULE_PARM_DESC(syscall_table, "ulong syscall_table address");

static unsigned long init_mm_address = 0xFFFFFFFFFFFFFFFF;
module_param(init_mm_address, ulong, 0644);
MODULE_PARM_DESC(init_mm_address, "ulong init_mm_address address");

static DEFINE_SPINLOCK(syscall_hook_lock);
static unsigned long *writable_syscall_table;

#ifndef NR_syscalls
#define NR_syscalls __NR_syscalls
#endif

static int syscall_flag[NR_syscalls];
unsigned long *backup_syscall_table[NR_syscalls];


static void backup_syscall(void)
{
        int i = 0;
        unsigned long *sys_call = NULL;

        sys_call = (unsigned long *)syscall_table;
        for (i = 0; i < NR_syscalls; i++) {
                backup_syscall_table[i] = (unsigned long *)sys_call[i];
                //print_syscall_name(i);
        }

        printk("Enter:[%s], NR_syscalls:[%d]\n", __func__, NR_syscalls);
        return;
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

static struct mm_struct *init_mm_ptr;
#if defined(CONFIG_ARM64)
static inline int pmd_huge(pmd_t pmd)
{
	return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}

int original_writeable = 0;
static int httc_set_memory_page(unsigned long addr, int writeable)
{
	pgd_t *pgd;
	pte_t *ptep = 0;
	pud_t *pud;
	pmd_t *pmd;
	pte_t pte;

	//struct mm_struct *pinit_mm = current->mm;
	struct mm_struct *pinit_mm = init_mm_ptr;
	//printk("set_memory_page_wp 0x%lx,writeable=%d\n",addr,writeable);
	pgd = pgd_offset(pinit_mm,addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)){
		printk(KERN_NOTICE "Invalid Valid pgd 0x%lx = 0x%llx\n",(unsigned long)pgd, pgd_val(*pgd));
		goto out;
	}
	//printk(KERN_NOTICE "Valid pgd 0x%lx = 0x%llx\n",(unsigned long)pgd, pgd_val(*pgd));

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud) || pud_bad(*pud)){
		printk(KERN_NOTICE "Invalid pud 0x%lx = 0x%llx\n", (unsigned long )pud,pud_val(*pud));
		goto out;
	}
	//printk(KERN_NOTICE "Valid pud 0x%lx = 0x%llx\n", (unsigned long )pud,pud_val(*pud));


	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) ){
		printk(KERN_NOTICE "None pmd 0x%lx = 0x%llx\n", (unsigned long )pmd,pmd_val(*pmd));
		goto out;
	}
	if(pmd_huge(*pmd)){
		//printk(KERN_NOTICE "Huge pmd 0x%lx = 0x%llx\n", (unsigned long )pmd,pmd_val(*pmd));
		pte = pmd_pte(*pmd);
	}
	else if(pmd_bad(*pmd)){
		printk(KERN_NOTICE "Bad pmd 0x%lx = 0x%llx\n", (unsigned long )pmd,pmd_val(*pmd));
		goto out;
	}
	else{
		//printk(KERN_NOTICE "Normal Valid pmd 0x%lx = 0x%llx\n", (unsigned long )pmd,pmd_val(*pmd));
		ptep = pte_offset_map(pmd, addr);
		pte = *ptep;
		if (pte_none(pte)){
			printk(KERN_NOTICE "None pte 0x%lx = 0x%llx\n", (unsigned long )ptep,pte_val(pte));
			goto out;
		}
		//printk(KERN_NOTICE "Valid pte 0x%lx = 0x%llx\n", (unsigned long )ptep,pte_val(pte));

	}
	if(writeable)
	{
		original_writeable = pte_write(pte);
		if (original_writeable)
		{
			printk("writeable=%d, original_writeable=%d, donot need set PTE_WRITE, return 0\n",  writeable, original_writeable);
			return 0;
		}
		printk("11 PTE before set_pte_bit(PTE_WRITE) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
		pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
		printk("11 PTE after set_pte_bit(PTE_WRITE) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
		pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY));
		printk("11 PTE after clear_pte_bit(PTE_RDONLY) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
	}
	else
	{
		if (original_writeable)
		{
			printk("writeable=%d, original_writeable=%d, donot need clear PTE_WRITE, return 0\n",  writeable, original_writeable);
			return 0;
		}
		printk("00 PTE before clear_pte_bit(PTE_WRITE) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
		pte = clear_pte_bit(pte, __pgprot(PTE_WRITE));
		printk("00 PTE after set_pte_bit(PTE_WRITE) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
		pte = set_pte_bit(pte, __pgprot(PTE_RDONLY));
		printk("00 PTE after set_pte_bit(PTE_RDONLY) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
	}

	if(ptep)
	{
		set_pte(ptep,pte);
		//printk(KERN_INFO "PTE after set 0x%lx ,write=%d\n", (unsigned long)pte_val(*ptep),pte_write(*ptep));
	}
	else
	{
		set_pmd(pmd,pte_pmd(pte));
		//printk(KERN_INFO "PMD after set 0x%lx ,write=%d\n", (unsigned long)pmd_val(*pmd),pte_write(pmd_pte(*pmd)));
	}
	flush_tlb_all();

	return 0;

out:
	return -1;
}
#endif

static void wirte_syscall_enrty(int num, unsigned long *new_call, unsigned long *w_syscall_table, unsigned long *sys_call_table)
{
	unsigned int cr0 = 0;
        if (w_syscall_table == sys_call_table) {
#if defined(CONFIG_ARM64)
                httc_set_memory_page((unsigned long)sys_call_table + num, 1);
#else
			cr0 = set_kernel_writable();
#endif

                w_syscall_table[num] = (unsigned long)new_call;
                printk("Enter %s, do write protect!\n", __func__);
				
#if defined(CONFIG_ARM64)
				httc_set_memory_page((unsigned long)sys_call_table + num, 0);
#else
				set_kernel_readonly(cr0);
#endif           
        } else {
                printk("Enter %s, no write protect!\n", __func__);
                w_syscall_table[num] = (unsigned long)new_call;
        }
        return;
}

int hook_restore_system_call(int num, unsigned long *new_call, unsigned long **old_call)
{
        int ret = 0;

        spin_lock(&syscall_hook_lock);
        if (syscall_flag[num] == 0) {
                ret = -EINVAL;
                goto out;
        }

        wirte_syscall_enrty(num, *old_call, writable_syscall_table, (unsigned long *)syscall_table);
        syscall_flag[num] = 0;

out:
        spin_unlock(&syscall_hook_lock);
        return ret;
}

int hook_replace_system_call(int num, unsigned long *new_call, unsigned long **old_call)
{
        int ret = 0;

        spin_lock(&syscall_hook_lock);
        if (syscall_flag[num] == 1) {
                ret = -EINVAL;
                goto out;
        }

        *old_call = (unsigned long *)writable_syscall_table[num];
        wirte_syscall_enrty(num, new_call, writable_syscall_table, (unsigned long *)syscall_table);
        syscall_flag[num] = 1;

out:
        spin_unlock(&syscall_hook_lock);
        return ret;
}

static void *get_writable_syscall_table(void *sct_addr)
{

	return sct_addr;
}

int httc_syscall_init(void)
{
        int ret = 0;
        printk("Enter Func %s\n", __func__);
        if ((syscall_table == 0xffffffffffffffff || syscall_table == 0)
			|| (init_mm_address == 0xFFFFFFFFFFFFFFFF || init_mm_address == 0)) {
                printk("Insmod Argument Error!\n");
                ret = -EINVAL;
                goto out;
        } else {
				init_mm_ptr = (struct mm_struct *)init_mm_address;
                printk("syscall_table:[%0lx], NR_syscalls:[%d]!\n", syscall_table, NR_syscalls);
        }

	//init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name("init_mm");

        printk("running backup_syscall\n");
        backup_syscall();

        printk("running get_writable_syscall_table\n");
        writable_syscall_table = get_writable_syscall_table((void *)syscall_table);
        if (!writable_syscall_table) {
                ret = -EINVAL;
                goto out;
        }
        printk("writable syscall address:[%p]\n", writable_syscall_table);

out:
        return ret;
}

void httc_syscall_exit(void)
{
        if (writable_syscall_table && writable_syscall_table != (unsigned long *)syscall_table)
                vunmap((const void *)((unsigned long)writable_syscall_table & PAGE_MASK));
        return;
}
