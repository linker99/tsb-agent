/********************************************************************************/

/********************************************************************************/

/* Generally useful utilities to deserialize structures from a stream */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tcm.h"
#include "tcm_error.h"
//#include "tcm_sizedbuffer.h"
#include "tcm_types.h"

#include "tcm_load.h"

/* TCM_Load32() loads 'tcm_uint32' from the stream.

   It checks that the stream has sufficient data, and adjusts 'stream'
   and 'stream_size' past the data.
*/

TCM_RESULT TCM_Load32(uint32_t *tcm_uint32,
                      unsigned char **stream,
                      uint32_t *stream_size)
{
    TCM_RESULT  rc = 0;

    /* check stream_size */
    if (rc == 0) {
        if (*stream_size < sizeof(uint32_t)) {
            printf("TCM_Load32: Error, stream_size %u less than %lu\n",
                   *stream_size, (unsigned long)sizeof(uint32_t));
            rc = TCM_BAD_PARAM_SIZE;
        }
    }
    /* load the parameter */
    if (rc == 0) {
        *tcm_uint32 = LOAD32(*stream, 0);
        *stream += sizeof (uint32_t);
        *stream_size -= sizeof (uint32_t);
    }
    return rc;
}

/* TCM_Load16() loads 'tcm_uint16' from the stream.

   It checks that the stream has sufficient data, and adjusts 'stream'
   and 'stream_size' past the data.
*/

TCM_RESULT TCM_Load16(uint16_t *tcm_uint16,
                      unsigned char **stream,
                      uint32_t *stream_size)
{
    TCM_RESULT  rc = 0;

    /* check stream_size */
    if (rc == 0) {
        if (*stream_size < sizeof(uint16_t)) {
            printf("TCM_Load16: Error, stream_size %u less than %lu\n",
                   *stream_size, (unsigned long)sizeof(uint16_t));
            rc = TCM_BAD_PARAM_SIZE;
        }
    }
    /* load the parameter */
    if (rc == 0) {
        *tcm_uint16 = LOAD16(*stream, 0);
        *stream += sizeof (uint16_t);
        *stream_size -= sizeof (uint16_t);
    }
    return rc;
}

TCM_RESULT TCM_Load8(uint8_t *tcm_uint8,
                     unsigned char **stream,
                     uint32_t *stream_size)
{
    TCM_RESULT  rc = 0;
    /* check stream_size */
    if (rc == 0) {
        if (*stream_size < sizeof(uint8_t)) {
            printf("TCM_Load8: Error, stream_size %u less than %lu\n",
                   *stream_size, (unsigned long)sizeof(uint8_t));
            rc = TCM_BAD_PARAM_SIZE;
        }
    }
    /* load the parameter */
    if (rc == 0) {
        *tcm_uint8 = LOAD8(*stream, 0);
        *stream += sizeof (uint8_t);
        *stream_size -= sizeof (uint8_t);
    }
    return rc;
}

/* Boolean incoming parameter values other than 0x00 and 0x01 have an implementation specific
   interpretation.  The TCM SHOULD return TCM_BAD_PARAMETER.
*/

TCM_RESULT TCM_LoadBool(TCM_BOOL *tcm_bool,
                        unsigned char **stream,
                        uint32_t *stream_size)
{
    TCM_RESULT  rc = 0;
    /* check stream_size */
    if (rc == 0) {
        if (*stream_size < sizeof(TCM_BOOL)) {
            printf("TCM_LoadBool: Error, stream_size %u less than %lu\n",
                   *stream_size, (unsigned long)sizeof(TCM_BOOL));
            rc = TCM_BAD_PARAM_SIZE;
        }
    }
    /* load the parameter */
    if (rc == 0) {
        *tcm_bool = LOAD8(*stream, 0);
        *stream += sizeof (uint8_t);
        *stream_size -= sizeof (uint8_t);
    }
    if (rc == 0) {
        if ((*tcm_bool != TRUE) && (*tcm_bool != FALSE)) {
            printf("TCM_LoadBool: Error, illegal value %02x\n", *tcm_bool);
            rc = TCM_BAD_PARAMETER;
        }
    }
    return rc;
}

/* TCM_Loadn() copies 'data_length' bytes from 'stream' to 'data' with
   no endian adjustments. */

TCM_RESULT TCM_Loadn(BYTE *data,
                     size_t data_length,
                     unsigned char **stream,
                     uint32_t *stream_size)
{
    TCM_RESULT  rc = 0;
    /* check stream_size */
    if (rc == 0) {
        if (*stream_size < data_length) {
            printf("TCM_Loadn: Error, stream_size %u less than %lu\n",
                   *stream_size, (unsigned long)data_length);
            rc = TCM_BAD_PARAM_SIZE;
        }
    }
    /* load the parameter */
    if (rc == 0) {
        memcpy(data, *stream, data_length);
        *stream += data_length;
        *stream_size -= data_length;
    }
    return rc;
}

/* TCM_LoadLong() creates a long from a stream in network byte order.

   The stream is not advanced.
*/

TCM_RESULT TCM_LoadLong(unsigned long *result,
                        const unsigned char *stream,
                        uint32_t stream_size)
{
    TCM_RESULT          rc = 0;
    size_t		i;		/* byte iterator */

    printf(" TCM_LoadLong:\n");
    if (rc == 0) {
        if (stream_size > sizeof(unsigned long)) {
            printf(" TCM_LoadLong: Error, stream size %u too large\n", stream_size);
            rc = TCM_BAD_PARAM_SIZE;
        }
    }
    if (rc == 0) {
        *result = 0;    /* initialize all bytes to 0 in case buffer is less than sizeof(unsigned
			   long) bytes */
        for (i = 0 ; i < stream_size ; i++) {
            /* copy big endian stream, put lowest address in an upper byte, highest address in byte
               0 */
            *result |= stream[i] << ((stream_size - 1 - i) * 8);
        }
        printf(" TCM_LoadLong: Result %08lx\n", *result);
    }
    return rc;
}

/* TCM_LoadString() returns a pointer to a C string.  It does not copy the string.

 */

TCM_RESULT TCM_LoadString(const char **name,
                          unsigned char **stream,
                          uint32_t *stream_size)
{
    TCM_RESULT          rc = 0;
    char                *ptr;

    *name = NULL;
    /* search for the first nul character */
    if (rc == 0) {
        ptr = memchr(*stream, (int)'\0', *stream_size);
        if (ptr == NULL) {
            rc = TCM_BAD_PARAM_SIZE;
        }
    }
    if (rc == 0) {
        *name = (char *)*stream;        /* cast because converting binary to string */
        *stream_size -= (ptr - *name) + 1;
        *stream = (unsigned char *)ptr + 1;
    }
    return rc;
}



