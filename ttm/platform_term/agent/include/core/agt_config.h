#ifndef __AGENT_CONFIG_AGENT__
#define __AGENT_CONFIG_AGENT__

#include "cJSON.h"
#include "agt_util.h"

#define STR_NAME		512
#define ROOT_PATH_LEN	32
#define COM_DEFAULT_KEY	"0123456789ABCDEF"


enum {
	RUNTIME_MODE_OFFLINE,
	RUNTIME_MODE_ONLINE
};

enum {
	CONF_SAVE_TYPE_NV,
	CONF_SAVE_TYPE_FILE,
};

typedef struct config_server {
	int		use_ssl;
	char	ca_cert[STR_NAME];
	char	client_cert[STR_NAME];
	char	client_key[STR_NAME];
	char	ip[STR_NAME];
	int		port;
} config_server_t;

typedef struct config_timer {
	int	check_per_millisecond;
} config_timer_t;

typedef struct config_log {
	FILE	*fp;
	char	path[STR_NAME];
	int		size;
	int		level;
} config_log_t;

typedef struct main_config {
	int		work_threads;
	int		run_mode;
	int     bmc_flag;
	char	install_path[STR_NAME];
	char	bash_file[STR_NAME];
	int		local_ui_enable;
	char	local_ui_path[STR_NAME];
	int		remote_ui_enable;
	int		remote_ui_listen_port;
	int		conf_save_type;
	config_server_t	server;
	config_timer_t	timer;
	config_log_t	log;
} main_config_t;

/* modules */
typedef struct module_license {
	char	path[STR_NAME];
} module_license_t;

typedef struct module_platform {
	int	notice_check_per_seconds;
} module_platform_t;

typedef struct module_trust_verify {
	int	upload_trust_report_interval;
	int	upload_platform_status_interval;
} module_trust_verify_t;

typedef struct module_audit {
	char	kafka_ip[IP_LEN];
	int		kafka_port;
	char	kafka_username[STR_NAME];
	char	kafka_password[STR_NAME];
	int	db_clear_max_items;
	int	db_clear_max_days;
} module_audit_t;



typedef struct module_config {
	module_license_t	license;
	module_platform_t	platform;
	module_trust_verify_t	trust_verify;
	module_audit_t		audit;
} module_config_t;

typedef struct agent_config {
	main_config_t		common;
	module_config_t		modules;
} agent_config_t;

int agent_set_default_config(void *master);
int agent_config_parse(void *master);
void agt_config_print(void *master);

#endif
