#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/mm.h>
//#include <asm/uaccess.h>
#include <linux/utsname.h>

#include "../version.h"
#include "../utils/debug.h"
#include "hook.h"



#define BOOT_SYSMAP    "/boot/System.map-"
#define PROC_PATH    "/proc/kallsyms"

#define READ_BUF_LEN		1024

int hook_search_ksym(const char * sym_name, unsigned long *sym_addr)
{
#ifdef set_fs
	mm_segment_t old_fs;
#endif
	ssize_t bytes;
	struct file *file;
	char *p;
	char *read_buf;
	char* bufferpos;
	int rc = 0;
	int leftlen = 0;
	int symlen;
	char sympath[128];

#ifdef USESYSMAP
	snprintf(sympath, 128, BOOT_SYSMAP"%s", utsname()->release);
#else
	snprintf(sympath, 128, "%s",PROC_PATH);
#endif

	pr_dev("Using symbol path %s\n",sympath);

	file = filp_open(sympath, O_RDONLY, 0);
	if (!file){
		return -1;
	}

	if (!file->f_op->read)
	{
		rc = -1;
		goto out;
	}
	read_buf = dkmalloc(READ_BUF_LEN, GFP_KERNEL);
	bufferpos = read_buf;
	if (!read_buf)
	{
		rc = -ENOMEM;
		goto out;
	}

	symlen = strlen(sym_name);

#ifdef set_fs
	old_fs = get_fs();
	set_fs(get_ds());
#endif
	while ((bytes = file->f_op->read(file, bufferpos,
			READ_BUF_LEN - 1 - leftlen, &file->f_pos)) > 0)
	{
		char *left;
		read_buf[leftlen + bytes] = 0;
		left = strrchr(read_buf, '\n');
		if (left > 0)
			*left++ = 0;
		else
			left = read_buf + leftlen + bytes;
		bufferpos = read_buf;
		for (; (p = strstr(bufferpos, sym_name)) != NULL;
				bufferpos = p + symlen)
		{
			if (*(p - 1) != ' ')
				continue;
			if (*(p + symlen) != 0 && *(p + symlen) != '\n'
					&& *(p + symlen) != '\t')
				continue;

			p -= sizeof(void *) * 2 + 3;
			p[sizeof(void *) * 2] = '\0';
			*sym_addr = simple_strtoul(p, NULL, 16);
			goto outok;
		}
		leftlen = strlen(left);
		memcpy(read_buf, left, leftlen);
		bufferpos = read_buf + leftlen;
		//printk("diff = %d\n",leftlen);
		//memset (bufferpos, 0, bytes);
	}
	//not found
	rc = -1;
outok: 
#ifdef set_fs
	set_fs(old_fs);
#endif
	dkfree(read_buf);
out:
	filp_close(file, NULL);

	return rc;
}
EXPORT_SYMBOL(hook_search_ksym);


unsigned long hook_replace_pointer(void **pp_addr, void *pointer){
	struct page *p[1];
	char *mapped;
	unsigned long addr = (unsigned long)pp_addr & PAGE_MASK;
	pr_dev("pp_addr  = %p\n" ,pp_addr);
	if (pointer == NULL)
		return -1;
#ifdef DONT_REMAP_ON
	*pp_addr = pointer;
#else
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) && defined(__x86_64__)
	    p[0] = pfn_to_page(__pa_symbol(addr) >> PAGE_SHIFT);
	#else
	    p[0] = virt_to_page(addr);
	#endif
	mapped = vmap(p, 1, VM_MAP, PAGE_KERNEL);
	if (mapped == NULL)
		return -1;
	pr_dev("mapped writeable  adress = %p\n" ,mapped + offset_in_page(pp_addr));
	*(void **)(mapped + offset_in_page(pp_addr)) = pointer;
	vunmap(mapped);
#endif
	return 0;
}
EXPORT_SYMBOL(hook_replace_pointer);
