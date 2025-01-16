/********************************************************************************/
/*Changelog:
*/
/********************************************************************************/

#ifndef TCM_MEMORY_H
#define TCM_MEMORY_H

#include "tcm_types.h"

TCM_RESULT TCM_Malloc(unsigned char **buffer, uint32_t size);
TCM_RESULT TCM_Realloc(unsigned char **buffer, uint32_t size);
void       TCM_Free(unsigned char *buffer);

#endif
