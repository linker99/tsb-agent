#include "list.h"
#include "ht_crypt.h"

#define SM3_LEN 32
#define UUID_LEN 36
#define ARRAY_MAX_LEN 10000

#define SCAN_DEFAULT_PATH	"/"
#define WHITELIST_DB_NAME	"whitelist.db"

struct task {
	char file[PATH_MAX_LEN];
	struct list_head list;
};

struct whitelist {
	char guid[UUID_LEN + 1];
	char path[PATH_MAX_LEN + 1];
	char hash[SM3_LEN*2 + 1];
};
