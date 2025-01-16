
#ifndef TSB_UDISK_H_
#define TSB_UDISK_H_
/*
Bus 001 Device 005: ID abcd:1234 Unknown UDisk
Bus 001 Device 004: ID 0951:1666 Kingston Technology DataTraveler 100 G3/G4/SE9 G2
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
*/

#define __GUID_LENGTH (48)

struct udisk_id
{
        uint32_t devno;
        uint32_t access_ctrl;
        char vender_name[64];  /* 供应商名称 */
        char dev_name[64];
}__attribute__ ((packed));


/* #define __UUDI_TAG__ ("DISK_TAG:") */
#define USB_DISK_TAG_LENGTH 12
#define USB_DISK_NAME_LENGTH 32
const static char tags[USB_DISK_TAG_LENGTH] = "DISK_TAG:";
struct udisk_mark
{
	char tag[USB_DISK_TAG_LENGTH];   /* mark 时不填 */
	char name[USB_DISK_NAME_LENGTH];
	char guid[__GUID_LENGTH];
} __attribute__ ((packed));

struct udisk_recover
{
	char guid[__GUID_LENGTH];
	struct udisk_mark disk_mark;
}__attribute__ ((packed));

struct udisk_info
{
	struct   udisk_id id;
	uint32_t marked;    /* 1 or 0 */
	struct   udisk_mark disk_mark;
}__attribute__ ((packed));

struct udisk_log
{
	unsigned int status;     /*  0--不可见 1--只读  2--可读可写 */
	unsigned short marked;    /*  0--未标记，1--标记 */
	unsigned short operate;    /*  参考 《外设审计操作定义》 */
	char name[USB_DISK_NAME_LENGTH];
	char guid[__GUID_LENGTH];
	char vender_name[64];
	char dev_name[64];
}__attribute__ ((packed));

int tsb_udisk_query(struct udisk_info **diskinfo, int *num);
int tsb_udisk_mark(struct udisk_id* id,struct udisk_mark *disk_mark);
int tsb_cdrom_switch(unsigned long opcode);
int tsb_udisk_recover(char *guid, struct udisk_mark *disk_mark);

#endif /* TSB_UDISK_H_ */


