/*
 * cmd_man.h
 *
 *  Created on: 2019年5月24日
 *      Author: wangtao
 */

#ifndef TPCMDRIVER_CMD_MAN_H_
#define TPCMDRIVER_CMD_MAN_H_


struct cmd_header;

int tdd_free_cmd_header(struct cmd_header * header);
struct cmd_header *tdd_alloc_cmd_header(void);
//void  *tpcm_alloc_data_buffer_huge(void);
//int tpcm_free_data_buffer_huge(void *buffer);
//int tpcm_free_data_buffer(void *buffer);
//void  *tpcm_alloc_data_buffer(unsigned int size);

extern void *sharemem_base;

#endif /* TPCMDRIVER_CMD_MAN_H_ */
