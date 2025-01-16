#ifndef _HASH_WHITELIST_H
#define _HASH_WHITELIST_H

//#include "hash_table.h"
#include "sec_domain.h"

#define HASH_TAB_BITS	16
#define HASH_TAB_SIZE	(1<<HASH_TAB_BITS)
#define HASH_TAB_MASK	(HASH_TAB_SIZE-1)

struct whitelist_feature_conf {
	uint32_t is_enabled;    //be_program_measure_on
	uint32_t control_mode;  //be_program_control
	uint32_t measure_mode;  //be_program_measure_mode
	uint32_t cache_mode;    //be_measure_use_cache
	uint32_t match_mode;    //be_program_measure_match_mode
};
//struct u_st_digest {
//	__u8 digest[LEN_HASH];
//	int len_name;
//	char name[0];
//};
//
//struct k_st_digest {
//	struct hash_unit *mother;
//	struct u_st_digest digest;
//};
struct whitelist_digest {
	struct hlist_node list;
	__u8 digest[LEN_HASH];
	int len_name;
	char name[0];
};

int whitelist_init(void/*struct hash_handle *handle*/);
void whitelist_exit(void/*struct hash_handle *handle*/);

//int whitelist_add(struct sk_buff *skb, struct nlmsghdr *nlh);
//int whitelist_del(struct sk_buff *skb, struct nlmsghdr *nlh);
//int whitelist_query(struct sk_buff *skb, struct nlmsghdr *nlh,
//		    struct sk_buff_head *p);
long ioctl_whitelist_add_policy(unsigned long param);
long ioctl_whitelist_del_policy(unsigned long param);
long ioctl_whitelist_reload_policy(unsigned long param);
long ioctl_whitelist_user_interface(unsigned long param);
int load_whitelist(void);

int get_whitelist(void *input, void **output);
void put_whitelist(void *input);

int digest_cal(struct file *file, char *digest, int len);
int digest_check(struct file *file, struct sec_domain *sec_d, int type);
int digest_check_tpcm(struct file *file, struct sec_domain *sec_d, int type);
int digest_check_tpcm_simple(struct file *file, struct sec_domain *sec_d, int type);

int check_module_digest(const void *buf, int len, char *digest);

int query_process_identity_lib_hash(const char *hash_str, int len);

#endif
