#ifndef __TCS_TCM_H__
#define __TCS_TCM_H__

#define TCM_ST_CLEAR		0x0001 /* The TCM is starting up from a clean state */

int tcm_init (void);
int tcm_startup (uint16_t mode);

#endif	/** __TCS_TCM_H__ */

