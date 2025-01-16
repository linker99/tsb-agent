/********************************************************************************/

/********************************************************************************/

#ifndef TCM_LOAD_H
#define TCM_LOAD_H

#include "tcm_types.h"

TCM_RESULT TCM_Load32(uint32_t *tcm_uint32,
                      unsigned char **stream,
                      uint32_t *stream_size);
TCM_RESULT TCM_Load16(uint16_t *tcm_uint16,
                      unsigned char **stream,
                      uint32_t *stream_size);
TCM_RESULT TCM_Load8(uint8_t *tcm_uint8,
                     unsigned char **stream,
                     uint32_t *stream_size);
TCM_RESULT TCM_Loadn(BYTE *data,
                     size_t data_length,
                     unsigned char **stream,
                     uint32_t *stream_size);
TCM_RESULT TCM_LoadBool(TCM_BOOL *tcm_bool,
                        unsigned char **stream,
                        uint32_t *stream_size);

TCM_RESULT TCM_LoadLong(unsigned long *result,
                        const unsigned char *stream,
                        uint32_t stream_size);
TCM_RESULT TCM_LoadString(const char **name,
                          unsigned char **stream,
                          uint32_t *stream_size);




#endif
