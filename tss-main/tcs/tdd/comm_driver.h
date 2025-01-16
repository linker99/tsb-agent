/*
 * map.h
 *
 *  Created on: 2019年10月31日
 */

#ifndef TPCMDRIVER_MAP_H_
#define TPCMDRIVER_MAP_H_

struct cmd_header;

int tdd_free_cmd_header(struct cmd_header * header);
struct cmd_header *tdd_alloc_cmd_header(void);
//void  *tpcm_alloc_data_buffer_huge(void);
//int tpcm_free_data_buffer_huge(void *buffer);
//int tpcm_free_data_buffer(void *buffer);
//void  *tpcm_alloc_data_buffer(unsigned int size);

//void  *get_begin_addr(void);

//static inline char* tpcm_strcpy(char __iomem  *dst,const char *src)
//{
//	char  *s = dst;
//	while ((*dst++ = *src++));
//	return s;
//}

#endif /* TPCMDRIVER_CMD_MAN_H_ */
