
#include <linux/kernel.h>
#ifndef CRC_H_
#define CRC_H_



/*
 *  This polynomial ( 0xEDB88320L) DOES generate the same CRC values as ZMODEM and PKZIP
 */
u32 httcsec_ssh_crc32(const u8 *buf, u32 size);
u32 httcsec_ssh_crc32_block(u32 crc,const u8 *buf, u32 size);

/*
 *   This polynomial (0x04c11db7) is used at: AUTODIN II, Ethernet, & FDDI
 */
u32  httcsec_mpeg_crc32(const u8 *data, int len);
u32  httcsec_mpeg_crc32_block(u32 crc,const u8 *data, int len);



#endif /* CRC_H_ */
