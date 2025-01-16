#ifndef __TRANSMIT_H__
#define __TRANSMIT_H__

enum{
	TPCM_SPI_ERROR_IO = 2048,
};


int tpcm_transmit (void *sbuf, int slength, void *rbuf, int *rlength);


#endif	/** __TRANSMIT_H__ */

