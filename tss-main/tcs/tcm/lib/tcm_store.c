/*
	changelog:
		static TCM_RESULT TCM_Sbuffer_AdjustReturnCode(TCM_STORE_BUFFER *sbuffer, TCM_RESULT returnCode, //TCM_USER_RES userCode//)//remove last param: tcm_state
		TCM_RESULT TCM_Sbuffer_StoreInitialResponse(TCM_STORE_BUFFER *response,		TCM_TAG request_tag,		TCM_RESULT returnCode,		TCM_USER_RES userCode)

*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "tcm_constants.h"
#include "tcm_error.h"
#include "tcm_memory.h"
#include "tcm_store.h"
#include "tcm_load.h"
#include "tcm_sizedbuffer.h"
/*
  ->buffer;             beginning of buffer
  ->buffer_current;     first empty position in buffer
  ->buffer_end;         one past last valid position in buffer
*/

;

void TCM_Sbuffer_Init(TCM_STORE_BUFFER *sbuffer)
{
    sbuffer->buffer = NULL;
    sbuffer->buffer_current = NULL;
    sbuffer->buffer_end = NULL;
}

/* TCM_Sbuffer_Load() loads TCM_STORE_BUFFER that has been serialized using
   TCM_Sbuffer_AppendAsSizedBuffer(), as a size plus stream.
*/

TCM_RESULT TCM_Sbuffer_Load(TCM_STORE_BUFFER *sbuffer,
                            unsigned char **stream,
                            uint32_t *stream_size)
{
    TCM_RESULT  rc = 0;
    uint32_t length;

    /* get the length of the stream to be loaded */
    if (rc == 0) {
        rc = TCM_Load32(&length, stream, stream_size);
    }
    /* check stream_size */
    if (rc == 0) {
        if (*stream_size < length) {
            printf("TCM_Sbuffer_Load: Error, stream_size %u less than %u\n",
                   *stream_size, length);
            rc = TCM_BAD_PARAM_SIZE;
        }
    }
    if (rc == 0) {
        rc = TCM_Sbuffer_Append(sbuffer, *stream, length);
        *stream += length;
        *stream_size -= length;
    }
    return rc;
}

/* TCM_Sbuffer_Store() cannot simply store the elements, as they are pointers.  Rather, the
   TCM_Sbuffer_AppendAsSizedBuffer() function is used.
*/

/* TCM_Sbuffer_Delete() frees an existing buffer and reinitializes it.  It must be called when a
   TCM_STORE_BUFFER is no longer required, to avoid a memory leak.  The buffer can be reused, but in
   that case TCM_Sbuffer_Clear would be a better choice. */

void TCM_Sbuffer_Delete(TCM_STORE_BUFFER *sbuffer)
{
    if (sbuffer->buffer != NULL) {
        free(sbuffer->buffer);
    }
    TCM_Sbuffer_Init(sbuffer);
    return;
}

/* TCM_Sbuffer_Clear() removes all data from an existing buffer, allowing reuse.  Memory is NOT
   freed. */

void TCM_Sbuffer_Clear(TCM_STORE_BUFFER *sbuffer)
{
    sbuffer->buffer_current = sbuffer->buffer;
    return;
}

/* TCM_Sbuffer_Get() gets the resulting byte buffer and its size. */

void TCM_Sbuffer_Get(TCM_STORE_BUFFER *sbuffer,
                     const unsigned char **buffer,
                     uint32_t *length)
{
    *length = sbuffer->buffer_current - sbuffer->buffer;
    *buffer = sbuffer->buffer;
    return;
}

/* TCM_Sbuffer_GetAll() gets the resulting byte buffer and its size, as well as the total size. */

void TCM_Sbuffer_GetAll(TCM_STORE_BUFFER *sbuffer,
                        unsigned char **buffer,
                        uint32_t *length,
                        uint32_t *total)
{
    *length = sbuffer->buffer_current - sbuffer->buffer;
    *total = sbuffer->buffer_end - sbuffer->buffer;
    *buffer = sbuffer->buffer;
    return;
}

/* TCM_SBuffer_Set() creates a TCM_STORE_BUFFER from

   'buffer' - pointer to a buffer that was allocated (can be NULL)

   'total' - the total number of allocated bytes (ignored if buffer is NULL)

   'length' - the number of valid bytes in buffer (ignored if buffer is NULL, can be 0, cannot be
   greater than total.
*/

TCM_RESULT TCM_Sbuffer_Set(TCM_STORE_BUFFER *sbuffer,
                           unsigned char *buffer,
                           const uint32_t length,
                           const uint32_t total)
{
    TCM_RESULT rc = 0;

    if (rc == 0) {
        if (sbuffer == NULL) {
            printf("TCM_Sbuffer_Set: Error (fatal), sbuffer is NULL\n");
            rc = TCM_FAIL;
        }
    }
    if (rc == 0) {
        if (buffer != NULL) {
            if (rc == 0) {
                if (length > total) {
                    printf("TCM_Sbuffer_Set: Error (fatal), length %u > total %u\n",
                           length, total);
                    rc = TCM_FAIL;
                }
            }
            if (rc == 0) {
                sbuffer->buffer = buffer;
                sbuffer->buffer_current = buffer + length;
                sbuffer->buffer_end = buffer + total;
            }
        } else {	/* buffer == NULL */
            sbuffer->buffer = NULL;
            sbuffer->buffer_current = NULL;
            sbuffer->buffer_end = NULL;
        }
    }
    return rc;
}

/* TCM_Sbuffer_Append() is the basic function to append 'data' of size 'data_length' to the
   TCM_STORE_BUFFER

   Returns 0 if success, TCM_SIZE if the buffer cannot be allocated.
*/

TCM_RESULT TCM_Sbuffer_Append(TCM_STORE_BUFFER *sbuffer,
                              const unsigned char *data,
                              size_t data_length)
{
    TCM_RESULT  rc = 0;
    size_t free_length;         /* length of free bytes in current buffer */
    size_t current_size;        /* size of current buffer */
    size_t current_length;      /* bytes in current buffer */
    size_t new_size;            /* size of new buffer */

    /* can data fit? */
    if (rc == 0) {
        /* cast safe as end is always greater than current */
        free_length = (size_t)(sbuffer->buffer_end - sbuffer->buffer_current);
        /* if data cannot fit in buffer as sized */
        if (free_length < data_length) {
            /* This test will fail long before the add uint32_t overflow */
            if (rc == 0) {
                /* cast safe as current is always greater than start */
                current_length = (size_t)(sbuffer->buffer_current - sbuffer->buffer);
                if ((current_length + data_length) > TCM_ALLOC_MAX) {
                    printf("TCM_Sbuffer_Append: "
                           "Error, size %lu + %lu greater than maximum allowed\n",
                           (unsigned long)current_length, (unsigned long)data_length);
                    rc = TCM_SIZE;
                }
            }
            if (rc == 0) {
                /* cast safe as end is always greater than start */
                current_size = (size_t)(sbuffer->buffer_end - sbuffer->buffer);
                /* optimize realloc's by rounding up data_length to the next increment */
                new_size = current_size +       /* currently used */
                           ((((data_length - 1) / TCM_STORE_BUFFER_INCREMENT) + 1) *
                            TCM_STORE_BUFFER_INCREMENT);

                /* but not greater than maximum buffer size */
                if (new_size > TCM_ALLOC_MAX) {
                    new_size = TCM_ALLOC_MAX;
                }
                printf("   TCM_Sbuffer_Append: data_length %lu, growing from %lu to %lu\n",
                       (unsigned long)data_length,
                       (unsigned long)current_size,
                       (unsigned long)new_size);
                rc = TCM_Realloc(&(sbuffer->buffer), new_size);
            }
            if (rc == 0) {
                sbuffer->buffer_end = sbuffer->buffer + new_size;       /* end */
                sbuffer->buffer_current = sbuffer->buffer + current_length; /* new empty position */
            }
        }
    }
    /* append the data */
    if (rc == 0) {
        memcpy(sbuffer->buffer_current, data, data_length);
        sbuffer->buffer_current += data_length;
    }
    return rc;
}

/* TCM_Sbuffer_Append8() is a special append that appends a uint8_t
 */

TCM_RESULT TCM_Sbuffer_Append8(TCM_STORE_BUFFER *sbuffer, uint8_t data)
{
    TCM_RESULT  rc = 0;

    rc = TCM_Sbuffer_Append(sbuffer, (const unsigned char *)(&data), sizeof(uint8_t));
    return rc;
}

/* TCM_Sbuffer_Append16() is a special append that converts a uint16_t to big endian (network byte
   order) and appends. */

TCM_RESULT TCM_Sbuffer_Append16(TCM_STORE_BUFFER *sbuffer, uint16_t data)
{
    TCM_RESULT  rc = 0;

    uint16_t ndata = htons(data);
    rc = TCM_Sbuffer_Append(sbuffer, (const unsigned char *)(&ndata), sizeof(uint16_t));
    return rc;
}

/* TCM_Sbuffer_Append32() is a special append that converts a uint32_t to big endian (network byte
   order) and appends. */

TCM_RESULT TCM_Sbuffer_Append32(TCM_STORE_BUFFER *sbuffer, uint32_t data)
{
    TCM_RESULT  rc = 0;

    uint32_t ndata = htonl(data);
    rc = TCM_Sbuffer_Append(sbuffer, (const unsigned char *)(&ndata), sizeof(uint32_t));
    return rc;
}

/* TCM_Sbuffer_AppendAsSizedBuffer() appends the source to the destination using the
   TCM_SIZED_BUFFER idiom.  That is, for a uint32_t size is stored.  Then the data is stored.

   Use this function when the stream is not self-describing and a size must be prepended.
*/

TCM_RESULT TCM_Sbuffer_AppendAsSizedBuffer(TCM_STORE_BUFFER *destSbuffer,
        TCM_STORE_BUFFER *srcSbuffer)
{
    TCM_RESULT  rc = 0;
    const unsigned char *buffer;
    uint32_t length;

    if (rc == 0) {
        TCM_Sbuffer_Get(srcSbuffer, &buffer, &length);
        rc = TCM_Sbuffer_Append32(destSbuffer, length);
    }
    if (rc == 0) {
        rc = TCM_Sbuffer_Append(destSbuffer, buffer, length);
    }
    return rc;
}

/* TCM_Sbuffer_AppendSBuffer() appends the source to the destination.  The size is not prepended, so
   the stream must be self-describing.
*/

TCM_RESULT TCM_Sbuffer_AppendSBuffer(TCM_STORE_BUFFER *destSbuffer,
                                     TCM_STORE_BUFFER *srcSbuffer)
{
    TCM_RESULT  rc = 0;
    const unsigned char *buffer;
    uint32_t length;

    if (rc == 0) {
        TCM_Sbuffer_Get(srcSbuffer, &buffer, &length);
        rc = TCM_Sbuffer_Append(destSbuffer, buffer, length);
    }
    return rc;
}







/* TCM_Bitmap_Load() is a safe loading of a TCM_BOOL from a bitmap.

   If 'pos' is >= 32, the function fails.
   TCM_BOOL is TRUE. if The bit at pos is set
   'pos' is incremented after the load.
*/

TCM_RESULT TCM_Bitmap_Load(TCM_BOOL *tcm_bool,
                           uint32_t tcm_bitmap,
                           uint32_t *pos)
{
    TCM_RESULT  rc = 0;

    if (rc == 0) {
        if ((*pos) >= (sizeof(uint32_t) * CHAR_BIT)) {
            printf("TCM_Bitmap_Load: Error (fatal), loading from position %u\n", *pos);
            rc = TCM_FAIL;      /* should never occur */
        }
    }
    if (rc == 0) {
        *tcm_bool = (tcm_bitmap & (1 << (*pos))) != 0;
        (*pos)++;
    }
    return rc;
}

/* TCM_Bitmap_Store() is a safe storing of a TCM_BOOL into a bitmap.

   If 'pos' is >= 32, the function fails.
   The bit at pos is set if the TCM_BOOL is TRUE.
   'pos' is incremented after the store.
*/

TCM_RESULT TCM_Bitmap_Store(uint32_t *tcm_bitmap,
                            TCM_BOOL tcm_bool,
                            uint32_t *pos)
{
    TCM_RESULT  rc = 0;

    if (rc == 0) {
        if ((*pos) >= (sizeof(uint32_t) * CHAR_BIT)) {
            printf("TCM_Bitmap_Store: Error (fatal), storing to position %u\n", *pos);
            rc = TCM_FAIL;      /* should never occur */
        }
    }
    if (rc == 0) {
        if (tcm_bool) {
            *tcm_bitmap |= (1 << (*pos));
        }
        (*pos)++;
    }
    return rc;
}



TCM_RESULT TCM_SizedBuffer_SetFromStore(TCM_SIZED_BUFFER *tcm_sized_buffer,
                                        TCM_STORE_BUFFER *sbuffer)
{
    TCM_RESULT          rc = 0;
    const unsigned char *data;
    uint32_t              size;

    if (rc == 0) {
        /* get the stream and its size from the TCM_STORE_BUFFER */
        TCM_Sbuffer_Get(sbuffer, &data, &size);
        rc = TCM_SizedBuffer_Set(tcm_sized_buffer, size, data);
    }
    return rc;
}




