
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
	uint16_t busno;
	uint16_t devno;
	uint16_t vender_id;
	uint16_t dev_id;
	char dev_name[64];
}__attribute__ ((packed));


//#define __UUDI_TAG__ ("DISK_TAG:")
#define USB_DISK_TAG_LENGTH 12
#define USB_DISK_NAME_LENGTH 32
const static char tags[USB_DISK_TAG_LENGTH] = "DISK_TAG:";
struct udisk_mark
{
	char tag[USB_DISK_TAG_LENGTH];   /* mark 时不填*/
	char name[USB_DISK_NAME_LENGTH];
	char guid[__GUID_LENGTH];
} __attribute__ ((packed));


struct udisk_info
{
	struct   udisk_id id;
	uint32_t marked;    /* 1 or 0 */
	struct   udisk_mark disk_mark;
}__attribute__ ((packed));

int tsb_udisk_query(struct udisk_info **diskinfo, int *num);
int tsb_udisk_mark(struct udisk_id* id,struct udisk_mark *disk_mark);
int tsb_udisk_umark(struct udisk_id* id,struct udisk_mark *disk_mark_backup);


#endif /* TSB_UDISK_H_ */


