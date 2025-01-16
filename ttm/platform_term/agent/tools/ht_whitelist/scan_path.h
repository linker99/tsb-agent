#include "list.h"
#include "ht_crypt.h"
#include "tools_log.h"

#define SM3_LEN 32
#define UUID_LEN 36
#define PATH_MAX_LEN 512
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


#define BACKUP_PATH         "/usr/local/bak_httcsec/"
#define DB_BACKUP_PATH      "/usr/local/bak_httcsec/db_bak/"
#define ETC_BACKUP_PATH     "/usr/local/bak_httcsec/etc_bak/"
#define CONF_BACKUP_PATH    "/usr/local/bak_httcsec/conf_bak/"
#define DB_PATH             "/usr/local/httcsec/ttm/db/"
#define ETC_PATH            "/usr/local/httcsec/ttm/etc/"
#define CONF_PATH           "/usr/local/httcsec/conf/"
#define HOME_DEFAULT_PATH	"/usr/local/"
#define HOME_PATH			"/usr/local/httcsec/ttm"

#define HTTC_PATH			"httcsec/ttm"
#define HTTC_LOGPATH		"httcsec/ttm/var/log/ht_agent.log"

int sdp_get_local_adminkey(admin_t *admin);
int ht_set_switch_whitelist(int on_off_flag );
int ht_mkdir(char *file_dir);
int ht_copy_dir(char *srcpath, const char *dstpath);
int ht_rmdir(char *file_dir);

int tools_log_init();
int tools_log_destroy();