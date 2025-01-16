#include <linux/module.h>
#include <linux/net.h>
#include <linux/version.h>
//#include <linux/mutex.h>
#include <net/sock.h>
#include <asm/tlbflush.h>

#define NET_PROTO_COMMON 	"TCPv6"
#define NET_PROTO_NARI 	"PING"
#define NET_FAMILY_COMMON 	AF_NETLINK

static char* net_proto = NET_PROTO_COMMON;
static int net_family = NET_FAMILY_COMMON;

/*init net value*/
static unsigned long netfamilies = 0xffffffffffffffff;
static unsigned long netfamilieslock = 0xffffffffffffffff;
static unsigned long protolist = 0xffffffffffffffff;
static unsigned long protolistmutex = 0xffffffffffffffff;
module_param(netfamilies, ulong, 0644);
module_param(netfamilieslock, ulong, 0644);
module_param(protolist, ulong, 0644);
module_param(protolistmutex, ulong, 0644);
MODULE_PARM_DESC(netfamilies, "ulong netfamilies address");
MODULE_PARM_DESC(netfamilieslock, "ulong netfamilieslock address");
MODULE_PARM_DESC(protolist, "ulong protolist address");
MODULE_PARM_DESC(protolistmutex, "ulong protolistmutex address");
/*end*/
static unsigned long init_mm_address = 0xFFFFFFFFFFFFFFFF;
module_param(init_mm_address, ulong, 0644);
MODULE_PARM_DESC(init_mm_address, "ulong init_mm_address address");

static struct net_proto_family **net_families;
static spinlock_t *net_family_lock;
static struct list_head *proto_list;
static struct mutex *proto_list_mutex;
//static rwlock_t *proto_list_mutex;
static int reallen = 0;
static unsigned char *buff = NULL;
static struct net_proto_family *pf = NULL;
static unsigned long addr = 0;

/********** HELPERS **********/

static struct mm_struct *init_mm_ptr = NULL;


static int (*origin_pf_create)(struct net *net, struct socket *sock, int protocol, int kern) = NULL;

static int httc_pf_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	printk("enter %s\n", __func__);
       	return origin_pf_create(net, sock, protocol, kern);
}

static int kernel_args_addr_init(void)
{
        if (netfamilies == 0xffffffffffffffff || netfamilies == 0 ||
			netfamilieslock == 0xffffffffffffffff || netfamilieslock == 0 ||
            protolist == 0xffffffffffffffff || protolist == 0 ||
            protolistmutex == 0xffffffffffffffff || protolistmutex == 0) { 
                printk("Insmod [NET] Argument Error!\n");
                return -EINVAL;
        } else {
                printk("netfamilies:[%0lx]!\n", netfamilies);
				printk("netfamilieslock:[%0lx]!\n", netfamilieslock);
                printk("proto_list:[%0lx]!\n", protolist);
                printk("proto_list_mutex:[%0lx]!\n", protolistmutex);
        }

        net_families = (struct net_proto_family **)netfamilies;
		net_family_lock = (spinlock_t *)netfamilieslock;
        proto_list = (struct list_head *)protolist;
        proto_list_mutex = (struct mutex *)protolistmutex;

        return 0;
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
void (*origin_close)(struct sock *sk, long timeout) = NULL;
int (*origin_get_port)(struct sock *sk, unsigned short snum) = NULL;

void fake_close(struct sock *sk, long timeout) 
{
	printk("enter %s\n", __func__);
	origin_close(sk, timeout);
}

int fake_get_port(struct sock *sk, unsigned short snum)
{
	printk("enter %s\n", __func__);
	return origin_get_port(sk, snum);
}
#endif

int dmeasure_test_modify_net_proto(void)
{
        int ret = 0;
        int length = 0;
	unsigned int cr0;
        //int reallen = 0;
        //unsigned char *buff = NULL;
        struct proto *p = NULL;

        /* replace */
        //rcu_read_lock();
        cr0 = set_kernel_writable();
        //write_lock(proto_list_mutex);
         mutex_lock(proto_list_mutex); 

        list_for_each_entry(p, proto_list, node) {
                if (!strncmp(p->name, net_proto, strlen(net_proto))) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
			origin_get_port = p->get_port;
			origin_close = p->close;

			p->get_port = &fake_get_port;
			p->close = &fake_close;
#else
                        length = (unsigned long)&p->get_port - (unsigned long)&p->close + sizeof(unsigned long);
                        buff = kzalloc(length + 1, GFP_ATOMIC);
                        if (!buff) {
                                ret = -ENOMEM;
                                goto out;
                        }

                        memcpy(buff, p, length);
                        reallen = length;
                        printk("net proto buff: length is min than length:[%d]\n", length);
                        memset(p, 0xff, length);
#endif
                }
        }

         mutex_unlock(proto_list_mutex); 
        //write_unlock(proto_list_mutex);
        set_kernel_readonly(cr0);
        //rcu_read_unlock();

        /* recovery */
        //msleep(10*1000);
        //printk("changing net info back\n");

        ////rcu_read_lock();
        // set_kernel_writable();
        // mutex_lock(proto_list_mutex); 
        ////write_lock(proto_list_mutex);
        //list_for_each_entry(p, proto_list, node) {
        //        if (!strncmp(p->name, "TCPv6", 5)) {
        //                if (reallen > 0) {
        //                        memcpy(p, buff, reallen);
        //                }
        //        }
        //}
        // mutex_unlock(proto_list_mutex); 
        ////write_unlock(proto_list_mutex);
        //set_kernel_readonly();
        ////rcu_read_unlock();

out:
        //if (buff)
        //        kfree(buff);
        return ret;
}

#if defined(CONFIG_ARM64)
static inline int pmd_huge(pmd_t pmd)
{
	return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}

//static struct mm_struct *init_mm_ptr;
int original_writeable = 0;
int httc_set_memory_page(unsigned long addr, int writeable)
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

int dmeasure_test_modify_net_family_create(void)
{
        int ret = 0;
        int i = 0;
	unsigned int cr0 = 0;
        //struct net_proto_family *pf = NULL;
        struct net_proto_family *last = NULL;
	//unsigned long addr = 0;
        /* replace */
        //rcu_read_lock();
        cr0 = set_kernel_writable();
	//spin_lock(net_family_lock);

	for(i = 0 ; i < NPROTO ; i++){
                pf = rcu_dereference(net_families[i]);
                if (!pf) {
                        continue;
                } else {
                        last = pf;
                        if (pf->family == net_family) {
                                break;
                        } else {
                                pf = NULL;
                        }
                }
        }

        if (!pf)
                pf = last;


        if (pf) {
#if defined(CONFIG_ARM64)
				addr = (unsigned long)&pf->create;
				ret = httc_set_memory_page(addr, 1);
				if (ret != 0) {
					pr_err("set_page_rw() failed: %d\n", ret);
					return ret;
				}

				printk("net_family family:[%d] create:[%p]->[%p]\n", pf->family, pf->create, httc_pf_create);
				origin_pf_create = pf->create;
				pf->create = httc_pf_create;

				ret = httc_set_memory_page(addr, 0);
				if (ret != 0) {
					pr_err("set_page_ro() failed: %d\n", ret);
					return ret;
				}
#else
				printk("net_family family:[%d] create:[%p]->[%p]\n", pf->family, pf->create, httc_pf_create);
				origin_pf_create = pf->create;
				pf->create = &httc_pf_create;
#endif
        } else {
                printk("net_families item's family = [%d] is null, can not test . Now return\n", pf->family);
                ret = -1;
                //goto out;
        }

        set_kernel_readonly(cr0);
        //rcu_read_unlock();
	//spin_unlock(net_family_lock);

          /* recovery */
//        msleep(10*1000);
//        printk("changing net info back\n");
//
//        //rcu_read_lock();
//        set_kernel_writable();
//		//spin_lock(net_family_lock);
//
//        printk("after changing back, net_family family:%d create: %p -> %p\n", pf->family, pf->create, origin_pf_create);
//#if defined(__x86_64__)
//		pf->create = origin_pf_create;
//#else
//		ret = httc_set_memory_page(addr, 1);
//		if (ret != 0) {
//			pr_err("set_page_rw() failed: %d\n", ret);
//			return ret;
//		}
//        pf->create = origin_pf_create;
//
//		ret = httc_set_memory_page(addr, 0);
//		if (ret != 0) {
//			pr_err("set_page_ro() failed: %d\n", ret);
//			return ret;
//		}
//#endif
//        set_kernel_readonly();
//        //rcu_read_unlock();
//		//spin_unlock(net_family_lock);
//
//out:
        return ret;
}

void check_special_kernel_version(void)
{

	if (strcmp(CONFIG_DEFAULT_HOSTNAME, "NARI")==0) {
		net_proto = NET_PROTO_NARI;
		//net_family = NET_FAMILY_COMMON;
	}

	printk("attack net proto type:%s, net family:%d\n", net_proto, net_family);
}

static int test_net_init(void)
{
        int ret = 0;

		if ((init_mm_address == 0xFFFFFFFFFFFFFFFF || init_mm_address == 0)) {
			printk("Enter[%s] Insmod Argument Error!\n",__func__);
			return -EINVAL;
		}
		init_mm_ptr = (struct mm_struct *)init_mm_address;

        ret = kernel_args_addr_init();
        if (ret)
                goto out;

		check_special_kernel_version();
        ret = dmeasure_test_modify_net_proto();
        if (ret)
                printk("dmeasure net proto error!\n");
        ret = dmeasure_test_modify_net_family_create();
        if (ret)
                printk("dmeasure net family error!\n");
out:
        return ret;
}

static void test_net_exit(void)
{
#if defined(CONFIG_ARM64)
	int ret = 0;
#endif
	struct proto *p = NULL;
	unsigned int cr0 = 0;

	/* net proto recovery */
	printk("changing net proto info back\n");

	//rcu_read_lock();
	cr0 = set_kernel_writable();
	mutex_lock(proto_list_mutex); 
	//write_lock(proto_list_mutex);
	list_for_each_entry(p, proto_list, node) {
		if (!strncmp(p->name, net_proto, strlen(net_proto))) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
				p->get_port = origin_get_port;
				p->close = origin_close;
#else
			if (reallen > 0) {
				memcpy(p, buff, reallen);
			}
#endif
		}
	}

	mutex_unlock(proto_list_mutex); 
	//write_unlock(proto_list_mutex);
	set_kernel_readonly(cr0);
	//rcu_read_unlock();

	if (buff)
		kfree(buff);

	/* net family recovery */
	if (!pf)
		return;
	printk("changing net family info back\n");
	//rcu_read_lock();
	cr0 = set_kernel_writable();
	//spin_lock(net_family_lock);

	printk("after changing back, net_family family:%d create: %p -> %p\n", pf->family, pf->create, origin_pf_create);
#if defined(CONFIG_ARM64)
	ret = httc_set_memory_page(addr, 1);
	if (ret != 0) {
		pr_err("set_page_rw() failed: %d\n", ret);
		return ret;
	}
	pf->create = origin_pf_create;

	ret = httc_set_memory_page(addr, 0);
	if (ret != 0) {
		pr_err("set_page_ro() failed: %d\n", ret);
		return ret;
	}
#else
	pf->create = origin_pf_create;
#endif
	set_kernel_readonly(cr0);
	//rcu_read_unlock();
	//spin_unlock(net_family_lock);
    return;
}

module_init(test_net_init);
module_exit(test_net_exit);

MODULE_AUTHOR("HTTC");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("HTTCSEC NET TEST");

