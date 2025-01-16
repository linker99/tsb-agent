#ifndef __TCSK_TCM_H__
#define __TCSK_TCM_H__

int tcsk_nv_definespace (uint32_t index, int len);
int tcsk_nv_is_definespace(uint32_t index, int len);
int tcsk_nv_write (uint32_t index, uint8_t *data, uint32_t dataLen);
int tcsk_nv_read (uint32_t index,	 uint8_t *data, uint32_t *dataLen);

#endif	/** __TCSK_TCM_H__ */

