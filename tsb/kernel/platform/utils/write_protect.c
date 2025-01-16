        #include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
//#include <asm/pgtable-prot.h>
#include "write_protect.h"
#include "debug.h"
//#ifdef HTTC_WRITE_PROTECT_SWITCH
static unsigned long init_mm_address = 0xFFFFFFFFFFFFFFFF;
module_param(init_mm_address, ulong, 0644);
MODULE_PARM_DESC(init_mm_address, "ulong init_mm_address address");
//#endif

#if defined(__x86_64__)
unsigned int set_kernel_wp(int writable, unsigned int val)
{
	unsigned int ret = 0;
	if (writable)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 90)
    		unsigned int cr0 = 0;
    		asm volatile ("movq %%cr0, %%rax": "=a"(cr0));
    		ret = cr0;
    		cr0 &= 0xfffeffff;
    		asm volatile ("movq %%rax, %%cr0"::"a"(cr0));
#else
		write_cr0(read_cr0() & ~X86_CR0_WP);
#endif
	}
	else
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 90)
		asm volatile ("movq %%rax, %%cr0": : "a"(val));
#else
		write_cr0(read_cr0() | X86_CR0_WP);
#endif
	}
    return ret;
}

#elif defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

static inline int pmd_huge(pmd_t pmd)
  {
          return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
  }
//#include <asm/syscall.h>
//#include <linux/pgtable.h>
struct mm_struct *init_mm_ptr = NULL;
int original_writeable = 0;
int set_memory_page_wp(unsigned long addr, int writeable)
{
	pgd_t *pgd;
	pte_t *ptep = 0;
	pud_t *pud;
	pmd_t *pmd;
	pte_t pte;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	p4d_t *p4dp;
	#endif

	//struct mm_struct *pinit_mm = current->mm;
	struct mm_struct *pinit_mm = init_mm_ptr;
	//printk("set_memory_page_wp 0x%lx,writeable=%d\n",addr,writeable);
	pgd = pgd_offset(pinit_mm,addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)){
		DEBUG_MSG(HTTC_TSB_INFO,"Invalid Valid pgd 0x%lx = 0x%llx\n",(unsigned long)pgd, pgd_val(*pgd));
		goto out;
	}
	//printk(KERN_NOTICE "Valid pgd 0x%lx = 0x%llx\n",(unsigned long)pgd, pgd_val(*pgd));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
  p4dp = p4d_offset(pgd,addr);
	pud = pud_offset(p4dp, addr);

#else
	pud = pud_offset(pgd, addr);
#endif
	if (pud_none(*pud) || pud_bad(*pud)){
		DEBUG_MSG(HTTC_TSB_INFO,"Invalid pud 0x%lx = 0x%llx\n", (unsigned long )pud,pud_val(*pud));
		goto out;
	}
	//printk(KERN_NOTICE "Valid pud 0x%lx = 0x%llx\n", (unsigned long )pud,pud_val(*pud));


	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) ){
		DEBUG_MSG(HTTC_TSB_INFO,"None pmd 0x%lx = 0x%llx\n", (unsigned long )pmd,pmd_val(*pmd));
		goto out;
	}
	if(pmd_huge(*pmd)){
		//printk(KERN_NOTICE "Huge pmd 0x%lx = 0x%llx\n", (unsigned long )pmd,pmd_val(*pmd));
		pte = pmd_pte(*pmd);
	}
	else if(pmd_bad(*pmd)){
		DEBUG_MSG(HTTC_TSB_INFO,"Bad pmd 0x%lx = 0x%llx\n", (unsigned long )pmd,pmd_val(*pmd));
		goto out;
	}
	else{
		//printk(KERN_NOTICE "Normal Valid pmd 0x%lx = 0x%llx\n", (unsigned long )pmd,pmd_val(*pmd));
		ptep = pte_offset_map(pmd, addr);
		pte = *ptep;
		if (pte_none(pte)){
			DEBUG_MSG(HTTC_TSB_INFO,"None pte 0x%lx = 0x%llx\n", (unsigned long )ptep,pte_val(pte));
			goto out;
		}
		//printk(KERN_NOTICE "Valid pte 0x%lx = 0x%llx\n", (unsigned long )ptep,pte_val(pte));

	}
	if(writeable)
	{
		original_writeable = pte_write(pte);
		if (original_writeable)
		{
			DEBUG_MSG(HTTC_TSB_INFO,"writeable=%d, original_writeable=%d, donot need set PTE_WRITE, return 0\n",  writeable, original_writeable);
			return 0;
		}
		DEBUG_MSG(HTTC_TSB_DEBUG,"11 PTE before set_pte_bit(PTE_WRITE) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
		pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
		DEBUG_MSG(HTTC_TSB_DEBUG,"11 PTE after set_pte_bit(PTE_WRITE) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
		pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY));
		DEBUG_MSG(HTTC_TSB_DEBUG,"11 PTE after clear_pte_bit(PTE_RDONLY) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
	}
	else
	{
		if (original_writeable)
		{
			DEBUG_MSG(HTTC_TSB_DEBUG,"writeable=%d, original_writeable=%d, donot need clear PTE_WRITE, return 0\n",  writeable, original_writeable);
			return 0;
		}
		DEBUG_MSG(HTTC_TSB_DEBUG,"00 PTE before clear_pte_bit(PTE_WRITE) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
		pte = clear_pte_bit(pte, __pgprot(PTE_WRITE));
		DEBUG_MSG(HTTC_TSB_DEBUG,"00 PTE after set_pte_bit(PTE_WRITE) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
		pte = set_pte_bit(pte, __pgprot(PTE_RDONLY));
		DEBUG_MSG(HTTC_TSB_DEBUG,"00 PTE after set_pte_bit(PTE_RDONLY) 0x%lx write=%d\n",  (unsigned long) pte_val(pte),pte_write(pte));
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


int lookup_init_mm()
{
//#ifdef HTTC_WRITE_PROTECT_SWITCH
	if ((init_mm_address == 0xFFFFFFFFFFFFFFFF || init_mm_address == 0)) 
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Enter[%s] Insmod Argument Error!\n",__func__);
		return -EINVAL;
	}

	init_mm_ptr = (struct mm_struct *)init_mm_address;
//#else
//	init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name("init_mm");
//#endif
	if (!init_mm_ptr) 
	{
		DEBUG_MSG(HTTC_TSB_INFO,"donot find init_mm!\n");
		return -1;
	}

	return 0;
}

#else
int set_memory_page_wp(unsigned long addr, int writeable)
{
	return 0;
}


#endif

#else
unsigned int set_kernel_wp(int writable, unsigned int val)
{
	return 0;
}
#endif	/* CONFIG_ARM64 */
