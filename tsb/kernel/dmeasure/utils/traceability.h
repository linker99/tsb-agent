#ifndef __TRACEABILITY_H__
#define __TRACEABILITY_H__

struct module *get_module_from_addr(unsigned long addr);
void print_hex(const char *name, unsigned char *p, int len);
int utils_init(void);

#endif
