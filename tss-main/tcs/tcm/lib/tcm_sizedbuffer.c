/********************************************************************************/

/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "tcm_error.h"
#include "tcm_memory.h"
#include "tcm_types.h"
#include "tcm_sizedbuffer.h"
#include "tcm_store.h"
#include "tcm_load.h"

void TCM_SizedBuffer_Init(TCM_SIZED_BUFFER *tcm_sized_buffer)
{
    tcm_sized_buffer->size = 0;
    tcm_sized_buffer->buffer = NULL;
    return;
}



/* TCM_SizedBuffer_Set() reallocs a sized buffer and copies 'size' bytes of 'data' into it.

   If the sized buffer already has data, the buffer is realloc'ed.

   This function correctly handles a 'size' of 0.

   Call TCM_SizedBuffer_Delete() to free the buffer
*/

TCM_RESULT TCM_SizedBuffer_Set(TCM_SIZED_BUFFER *tcm_sized_buffer,
                               uint32_t size,
                               const unsigned char *data)
{
    TCM_RESULT  rc = 0;

    printf("  TCM_SizedBuffer_Set:\n");
    /* allocate memory for the buffer, and copy the buffer */
    if (rc == 0) {
        if (size > 0) {
            rc = TCM_Realloc(&(tcm_sized_buffer->buffer),
                             size);
            if (rc == 0) {
                tcm_sized_buffer->size = size;
                memcpy(tcm_sized_buffer->buffer, data, size);
            }
        }
        /* if size is zero */
        else {
            TCM_SizedBuffer_Delete(tcm_sized_buffer);
        }
    }
    return rc;
}





TCM_RESULT TCM_SizedBuffer_Copy(TCM_SIZED_BUFFER *tcm_sized_buffer_dest,
                                TCM_SIZED_BUFFER *tcm_sized_buffer_src)
{
    TCM_RESULT  rc = 0;
    rc = TCM_SizedBuffer_Set(tcm_sized_buffer_dest,
                             tcm_sized_buffer_src->size,
                             tcm_sized_buffer_src->buffer);
    return rc;
}




void TCM_SizedBuffer_Delete(TCM_SIZED_BUFFER *tcm_sized_buffer)
{
    if (tcm_sized_buffer != NULL) {
        free(tcm_sized_buffer->buffer);
        TCM_SizedBuffer_Init(tcm_sized_buffer);
    }
    return;
}

/* TCM_SizedBuffer_Allocate() allocates 'size' bytes of memory and sets the TCM_SIZED_BUFFER
   members.

   The buffer data is not initialized.
*/

TCM_RESULT TCM_SizedBuffer_Allocate(TCM_SIZED_BUFFER *tcm_sized_buffer,
                                    uint32_t size)
{
    TCM_RESULT  rc = 0;

    printf("  TCM_SizedBuffer_Allocate: Size %u\n", size);
    tcm_sized_buffer->size = size;
    rc = TCM_Malloc(&(tcm_sized_buffer->buffer), size);
    return rc;
}

/* TCM_SizedBuffer_GetBool() converts from a TCM_SIZED_BUFFER to a TCM_BOOL.

   If the size does not indicate a TCM_BOOL, an error is returned.
*/

TCM_RESULT TCM_SizedBuffer_GetBool(TCM_BOOL *tcm_bool,
                                   TCM_SIZED_BUFFER *tcm_sized_buffer)
{
    TCM_RESULT rc = 0;

    if (tcm_sized_buffer->size == sizeof(TCM_BOOL)) {
        *tcm_bool = *(TCM_BOOL *)tcm_sized_buffer->buffer;
        printf("  TCM_SizedBuffer_GetBool: bool %02x\n", *tcm_bool);
    } else {
        printf("TCM_SizedBuffer_GetBool: Error, buffer size %08x is not a BOOL\n",
               tcm_sized_buffer->size);
        rc = TCM_BAD_PARAMETER;
    }
    return rc;
}

/* TCM_SizedBuffer_GetUint32() converts from a TCM_SIZED_BUFFER to a uint32_t.

   If the size does not indicate a uint32_t, an error is returned.
*/


/* TCM_SizedBuffer_Append32() appends a uint32_t to a TCM_SIZED_BUFFER

*/

TCM_RESULT TCM_SizedBuffer_Append32(TCM_SIZED_BUFFER *tcm_sized_buffer,
                                    uint32_t uint32)
{
    TCM_RESULT rc = 0;

    printf("  TCM_SizedBuffer_Append32: Current size %u uint32 %08x\n",
           tcm_sized_buffer->size, uint32);
    /* allocate space for another uint32_t */
    if (rc == 0) {
        rc = TCM_Realloc(&(tcm_sized_buffer->buffer),
                         tcm_sized_buffer->size + sizeof(uint32_t));
    }
    if (rc == 0) {
        uint32_t ndata = htonl(uint32);           /* convert to network byte order */
        memcpy(tcm_sized_buffer->buffer + tcm_sized_buffer->size, /* append at end */
               (char *)&ndata,                  /* cast safe after conversion */
               sizeof(uint32_t));
        tcm_sized_buffer->size += sizeof(uint32_t);
    }
    return rc;
}




/* TCM_SizedBuffer_Zero() overwrites all data in the buffer with zeros

 */

void TCM_SizedBuffer_Zero(TCM_SIZED_BUFFER *tcm_sized_buffer)
{
    printf("  TCM_SizedBuffer_Zero:\n");
    if (tcm_sized_buffer->buffer != NULL) {
        memset(tcm_sized_buffer->buffer, 0, tcm_sized_buffer->size);
    }
    return;
}





TCM_RESULT TCM_SizedBuffer_Store(TCM_STORE_BUFFER *sbuffer,
                                 const TCM_SIZED_BUFFER *tcm_sized_buffer)
{
    TCM_RESULT  rc = 0;

    printf("  TCM_SizedBuffer_Store:\n");
    /* append the size */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append32(sbuffer, tcm_sized_buffer->size);
    }
    /* append the data */
    if (rc == 0) {
        rc = TCM_Sbuffer_Append(sbuffer, tcm_sized_buffer->buffer, tcm_sized_buffer->size);
    }
    return rc;
}

TCM_RESULT TCM_SizedBuffer_Load(TCM_SIZED_BUFFER *tcm_sized_buffer,     /* result */
                                unsigned char **stream,		/* pointer to next parameter */
                                uint32_t *stream_size)		/* stream size left */
{
    TCM_RESULT  rc = 0;

    printf("  TCM_SizedBuffer_Load:\n");
    if (rc == 0) {
        rc = TCM_Load32(&(tcm_sized_buffer->size), stream, stream_size);
    }
    /* if the size is not 0 */
    if ((rc == 0) && (tcm_sized_buffer->size > 0)) {
        /* allocate memory for the buffer */
        if (rc == 0) {
            rc = TCM_Malloc(&(tcm_sized_buffer->buffer), tcm_sized_buffer->size);
        }
        /* copy the buffer */
        if (rc == 0) {
            rc = TCM_Loadn(tcm_sized_buffer->buffer, tcm_sized_buffer->size, stream, stream_size);
        }
    }
    return rc;
}
