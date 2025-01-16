/********************************************************************************/

/********************************************************************************/

#ifndef TCM_SIZEDBUFFER_H
#define TCM_SIZEDBUFFER_H

#include "tcm_structures.h"
#include "tcm_sizedbuffer.h"


void       TCM_SizedBuffer_Init(TCM_SIZED_BUFFER *tcm_sized_buffer);
TCM_RESULT TCM_SizedBuffer_Load(TCM_SIZED_BUFFER *tcm_sized_buffer,
                                unsigned char **stream,
                                uint32_t *stream_size);
TCM_RESULT TCM_SizedBuffer_Store(TCM_STORE_BUFFER *sbuffer,
                                 const TCM_SIZED_BUFFER *tcm_sized_buffer);
TCM_RESULT TCM_SizedBuffer_Set(TCM_SIZED_BUFFER *tcm_sized_buffer,
                               uint32_t size,
                               const unsigned char *data);

TCM_RESULT TCM_SizedBuffer_Copy(TCM_SIZED_BUFFER *tcm_sized_buffer_dest,
                                TCM_SIZED_BUFFER *tcm_sized_buffer_src);
void       TCM_SizedBuffer_Delete(TCM_SIZED_BUFFER *tcm_sized_buffer);
TCM_RESULT TCM_SizedBuffer_Allocate(TCM_SIZED_BUFFER *tcm_sized_buffer,
                                    uint32_t size);
TCM_RESULT TCM_SizedBuffer_GetBool(TCM_BOOL *tcm_bool,
                                   TCM_SIZED_BUFFER *tcm_sized_buffer);
TCM_RESULT TCM_SizedBuffer_GetUint32(uint32_t *uint32,
                                     TCM_SIZED_BUFFER *tcm_sized_buffer);
TCM_RESULT TCM_SizedBuffer_Append32(TCM_SIZED_BUFFER *tcm_sized_buffer,
                                    uint32_t uint32);
TCM_RESULT TCM_SizedBuffer_Remove32(TCM_SIZED_BUFFER *tcm_sized_buffer,
                                    uint32_t uint32);
void       TCM_SizedBuffer_Zero(TCM_SIZED_BUFFER *tcm_sized_buffer);

#endif
