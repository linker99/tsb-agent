#ifndef TCM_STORE_H
#define TCM_STORE_H


#include "tcm_types.h"
#include "tcm_structures.h"

void TCM_Sbuffer_Init(TCM_STORE_BUFFER *sbuffer);

TCM_RESULT TCM_Sbuffer_Load(TCM_STORE_BUFFER *sbuffer,
                            unsigned char **stream,
                            uint32_t *stream_size);



void TCM_Sbuffer_Delete(TCM_STORE_BUFFER *sbuffer);

void TCM_Sbuffer_Clear(TCM_STORE_BUFFER *sbuffer);
void TCM_Sbuffer_Get(TCM_STORE_BUFFER *sbuffer,
                     const unsigned char **buffer,
                     uint32_t *length);

void TCM_Sbuffer_GetAll(TCM_STORE_BUFFER *sbuffer,
                        unsigned char **buffer,
                        uint32_t *length,
                        uint32_t *total);

TCM_RESULT TCM_Sbuffer_Set(TCM_STORE_BUFFER *sbuffer,
                           unsigned char *buffer,
                           const uint32_t length,
                           const uint32_t total);

TCM_RESULT TCM_Sbuffer_Append(TCM_STORE_BUFFER *sbuffer,
                              const unsigned char *data,
                              size_t data_length);



TCM_RESULT TCM_Sbuffer_Append8(TCM_STORE_BUFFER *sbuffer, uint8_t data);
TCM_RESULT TCM_Sbuffer_Append16(TCM_STORE_BUFFER *sbuffer, uint16_t data);
TCM_RESULT TCM_Sbuffer_Append32(TCM_STORE_BUFFER *sbuffer, uint32_t data);
TCM_RESULT TCM_Sbuffer_AppendAsSizedBuffer(TCM_STORE_BUFFER *destSbuffer,
        TCM_STORE_BUFFER *srcSbuffer);
TCM_RESULT TCM_Sbuffer_AppendSBuffer(TCM_STORE_BUFFER *destSbuffer,
                                     TCM_STORE_BUFFER *srcSbuffer);


TCM_RESULT TCM_Bitmap_Load(TCM_BOOL *tcm_bool,
                           uint32_t tcm_bitmap,
                           uint32_t *pos);


TCM_RESULT TCM_Bitmap_Store(uint32_t *tcm_bitmap,
                            TCM_BOOL tcm_bool,
                            uint32_t *pos);

TCM_RESULT TCM_SizedBuffer_SetFromStore(TCM_SIZED_BUFFER *tcm_sized_buffer,
                                        TCM_STORE_BUFFER *sbuffer);



#endif
