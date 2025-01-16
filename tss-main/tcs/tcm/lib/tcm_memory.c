/********************************************************************************/
/*Changelog:
*/
/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "tcm_constants.h"
#include "tcm_error.h"
#include "tcm_memory.h"

/* TCM_Malloc() is a general purpose wrapper around malloc()
 */

TCM_RESULT TCM_Malloc(unsigned char **buffer, uint32_t size)
{
    TCM_RESULT          rc = 0;

    /* assertion test.  The coding style requires that all allocated pointers are initialized to
       NULL.  A non-NULL value indicates either a missing initialization or a pointer reuse (a
       memory leak). */
    if (rc == 0) {
        if (*buffer != NULL) {
            printf("TCM_Malloc: Error (fatal), *buffer %p should be NULL before malloc\n", *buffer);
            rc = TCM_FAIL;
        }
    }
    /* verify that the size is not "too large" */
    if (rc == 0) {
        if (size > TCM_ALLOC_MAX) {
            printf("TCM_Malloc: Error, size %u greater than maximum allowed\n", size);
            rc = TCM_SIZE;
        }
    }
    /* verify that the size is not 0, this would be implementation defined and should never occur */
    if (rc == 0) {
        if (size == 0) {
            printf("TCM_Malloc: Error (fatal), size is zero\n");
            rc = TCM_FAIL;
        }
    }
    if (rc == 0) {
        *buffer = malloc(size);
        if (*buffer == NULL) {
            printf("TCM_Malloc: Error allocating %u bytes\n", size);
            rc = TCM_SIZE;
        }
    }
    return rc;
}

/* TCM_Realloc() is a general purpose wrapper around realloc()
 */

TCM_RESULT TCM_Realloc(unsigned char **buffer,
                       uint32_t size)
{
    TCM_RESULT          rc = 0;
    unsigned char       *tmpptr = NULL;

    /* verify that the size is not "too large" */
    if (rc == 0) {
        if (size > TCM_ALLOC_MAX) {
            printf("TCM_Realloc: Error, size %u greater than maximum allowed\n", size);
            rc = TCM_SIZE;
        }
    }
    if (rc == 0) {
        tmpptr = realloc(*buffer, size);
        if (tmpptr == NULL) {
            printf("TCM_Realloc: Error reallocating %u bytes\n", size);
            rc = TCM_SIZE;
        }
    }
    if (rc == 0) {
        *buffer = tmpptr;
    }
    return rc;
}

/* TCM_Free() is the companion to the TCM allocation functions.  It is not used internally.  The
   intent is for use by an application that links directly to a TCM and wants to free memory
   allocated by the TCM.

   It avoids a potential problem if the application uses a different allocation library, perhaps one
   that wraps the functions to detect overflows or memory leaks.
*/

void TCM_Free(unsigned char *buffer)
{
    free(buffer);
    return;
}

