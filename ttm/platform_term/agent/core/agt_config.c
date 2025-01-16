#include "agt_util.h"
#include "agt_log.h"
#include "agt_config.h"

char g_conf_file[ROOT_PATH_LEN * 2] = {0};

static int agent_config_equal(cJSON *item, int key);

int agent_set_default_config(void *agent)
{
	agent_t *master = (agent_t *)agent;

	main_config_t *common = &master->config.common;
	common->work_threads = 2;
	common->run_mode = RUNTIME_MODE_ONLINE;
	strcpy(common->install_path, "/usr/local/httcsec/ttm/");
	strcpy(common->bash_file, "/bin/ht_bash");
	common->local_ui_enable = 1;
	sprintf(common->local_ui_path, "%s/%s", master->root_path, "local_ui_path");
	common->remote_ui_enable = 0;
	common->remote_ui_listen_port = 9001;
	common->conf_save_type = 0;

	common->server.use_ssl = 1;
	sprintf(common->server.ca_cert, "%s/%s", master->root_path, "etc/ssl/ca.cert");
	sprintf(common->server.client_cert, "%s/%s", master->root_path, "etc/ssl/client.cert");
	sprintf(common->server.client_key, "%s/%s", master->root_path, "etc/ssl/client.key");
	strcpy(common->server.ip, "127.0.0.1");
	common->server.port = 7000;

	common->timer.check_per_millisecond = 500;

	sprintf(common->log.path, "%s/%s", master->root_path, "var/ht_agent.log");
	common->log.size = 512;
	common->log.level = 1;

	module_config_t *module = &master->config.modules;
	sprintf(module->license.path, "%s/%s", master->root_path, "etc/license");

	module->platform.notice_check_per_seconds = 3;

	module->trust_verify.upload_trust_report_interval = 600;	
	module->trust_verify.upload_platform_status_interval = 600;	

	strcpy(module->audit.kafka_ip, "127.0.0.1");
	strcpy(module->audit.kafka_username, "producer");
	strcpy(module->audit.kafka_password, "prod-sec");
	module->audit.kafka_port = 9092;
	module->audit.db_clear_max_items = 100000;
	module->audit.db_clear_max_days = 30;;

	return 0;
}

static int agent_config_equal(cJSON *item, int key)
{
	if(item) {
		if(item->type != key) {
			agent_log(HTTC_WARN, "[%s:%d] unexpect item type key: %s!\n", __FILE__, __LINE__, item->string);
			return 0;
		}
		return 1;
	}

	return 0;
}

int agent_config_parse(void *agent)
{
	agent_t *master = (agent_t *)agent;

	if(!master)
		return -1;

	int len;
	FILE *fp = NULL;
	char *buffer = NULL;
	struct stat st;
	cJSON *root, *object, *sub, *item;

	strcpy(master->root_path, DEFAULT_ROOT_PATH);

	agent_set_default_config(master);

	if(!master->conf_file) {
		snprintf(g_conf_file, sizeof(g_conf_file) - 1, "%s/etc/agent.conf", master->root_path);
		master->conf_file = g_conf_file;
	}

	if((fp = fopen(master->conf_file, "r")) == NULL || stat(master->conf_file, &st) < 0) {
		agent_log(HTTC_ERROR, "[%s:%d] open %s fail!\n", __FILE__, __LINE__, master->conf_file);
		if(fp)
			fclose(fp);
		return -1;
	}

	len = st.st_size;
	buffer = (char *)agent_calloc(len);
	if(!buffer) {
		agent_log(HTTC_ERROR, "[%s:%d] malloc error\n", __FILE__, __LINE__);
		fclose(fp);
		return -1;
	}
	fread(buffer, 1, len, fp);
	root = cJSON_Parse(buffer);
	agent_free(buffer);
	fclose(fp);

	if(!root) {
                char error_ptr[2048] = {0};
                strncpy(error_ptr, cJSON_GetErrorPtr(), sizeof(error_ptr) - 1);
                agent_log(HTTC_WARN, "cJSON_Parse error: %s\n", error_ptr);
                return -1;
	}

	main_config_t *common = &master->config.common;
	config_timer_t *timer = &common->timer;
	config_log_t *log = &common->log;

	module_config_t *module = &master->config.modules;
	module_license_t *license = &module->license;
	module_platform_t *platform = &module->platform;
	module_trust_verify_t *trust_verify = &module->trust_verify;
	module_audit_t *audit = &module->audit;
	
	object = cJSON_GetObjectItem(root,"main");
	if(object) {
		item=cJSON_GetObjectItem(object,"id");
		if(agent_config_equal(item, cJSON_String)) {
			strncpy(master->id, item->valuestring, AGENT_ID_LEN);
		}
		item=cJSON_GetObjectItem(object,"work_threads");
		if(agent_config_equal(item, cJSON_Number)) {
			if(item->valueint > 0)
				common->work_threads = item->valueint;
		}
		item=cJSON_GetObjectItem(object,"run_mode");
		if(agent_config_equal(item, cJSON_String)) {
			if(!strcmp(item->valuestring, "offline"))
				common->run_mode = RUNTIME_MODE_OFFLINE;
		}
		item=cJSON_GetObjectItem(object,"bmc_flag");
		if(agent_config_equal(item, cJSON_String)) {
			common->bmc_flag = atoi(item->valuestring);
		}
		item=cJSON_GetObjectItem(object,"install_path");
		if(agent_config_equal(item, cJSON_String)) {
			strcpy(common->install_path, item->valuestring);
		}
		item=cJSON_GetObjectItem(object,"bash_file");
		if(agent_config_equal(item, cJSON_String)) {
			strcpy(common->bash_file, item->valuestring);
		}
		item=cJSON_GetObjectItem(object,"local_ui_enable");
		if(agent_config_equal(item, cJSON_Number)) {
			if(item->valueint == 0)
				common->local_ui_enable = 0;
			else
				common->local_ui_enable = 1;
		}
		item=cJSON_GetObjectItem(object,"local_ui_path");
		if(agent_config_equal(item, cJSON_String)) {
			sprintf(common->local_ui_path, "%s/%s", master->root_path, item->valuestring);
		}
		item=cJSON_GetObjectItem(object,"remote_ui_enable");
		if(agent_config_equal(item, cJSON_Number)) {
			if(item->valueint == 0)
				common->remote_ui_enable = 0;
			else
				common->remote_ui_enable = 1;
		}
		item=cJSON_GetObjectItem(object,"remote_ui_listen_port");
		if(agent_config_equal(item, cJSON_Number)) {
			if(item->valueint > 0)
				common->remote_ui_listen_port = item->valueint;
		}
		item=cJSON_GetObjectItem(object,"conf_save_type");
		if(agent_config_equal(item, cJSON_Number)) {
			if(item->valueint == 0)
				common->conf_save_type = 0;
			else
				common->conf_save_type = 1;
		}

		sub = cJSON_GetObjectItem(object, "server");
		if(sub) {
			config_server_t *server = &common->server;

			item=cJSON_GetObjectItem(sub,"use_ssl");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint == 0)
					server->use_ssl = 0;
			}
			item=cJSON_GetObjectItem(sub,"ca_cert");
			if(agent_config_equal(item, cJSON_String)) {
				sprintf(server->ca_cert, "%s/%s", master->root_path, item->valuestring);
			}
			item=cJSON_GetObjectItem(sub,"client_cert");
			if(agent_config_equal(item, cJSON_String)) {
				sprintf(server->client_cert, "%s/%s", master->root_path, item->valuestring);
			}
			item=cJSON_GetObjectItem(sub,"client_key");
			if(agent_config_equal(item, cJSON_String)) {
				sprintf(server->client_key, "%s/%s", master->root_path, item->valuestring);
			}
			item=cJSON_GetObjectItem(sub,"ip");
			if(agent_config_equal(item, cJSON_String)) {
				strcpy(server->ip, item->valuestring);
			}
			item=cJSON_GetObjectItem(sub,"port");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint > 0)
					server->port = item->valueint;
			}
		}

		sub = cJSON_GetObjectItem(object, "timer");
		if(sub) {
			item=cJSON_GetObjectItem(sub,"check_per_millisecond");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint > 0)
					timer->check_per_millisecond = item->valueint;
			}
		}
		sub = cJSON_GetObjectItem(object, "log");
		if(sub) {

			item=cJSON_GetObjectItem(sub,"path");
			if(agent_config_equal(item, cJSON_String)) {
				sprintf(log->path, "%s/%s", master->root_path, item->valuestring);
			}
			item=cJSON_GetObjectItem(sub,"size");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint > 0)
					log->size = item->valueint;
			}
			item=cJSON_GetObjectItem(sub,"level");
			if(agent_config_equal(item, cJSON_Number)) {
					log->level = item->valueint;
			}
		}

	}

	object = cJSON_GetObjectItem(root,"modules");
	if(object) {
		sub = cJSON_GetObjectItem(object, "license");
		if(sub) {
			item=cJSON_GetObjectItem(sub,"path");
			if(agent_config_equal(item, cJSON_String)) {
				sprintf(license->path, "%s/%s", master->root_path, item->valuestring);
			}
		}
		sub = cJSON_GetObjectItem(object, "platform");
		if(sub) {
			item=cJSON_GetObjectItem(sub,"notice_check_per_seconds");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint > 0)
					platform->notice_check_per_seconds = item->valueint;
			}
		}
		sub = cJSON_GetObjectItem(object, "trust_verify");
		if(sub) {
			item=cJSON_GetObjectItem(sub,"upload_trust_report_interval");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint > 0)
					trust_verify->upload_trust_report_interval = item->valueint;
			}
			item=cJSON_GetObjectItem(sub,"upload_platform_status_interval");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint > 0)
					trust_verify->upload_platform_status_interval = item->valueint;
			}
		}
		sub = cJSON_GetObjectItem(object, "audit");
		if(sub) {
			item=cJSON_GetObjectItem(sub,"kafka_ip");
			if(agent_config_equal(item, cJSON_String)) {
					strcpy(audit->kafka_ip, item->valuestring);
			}
			item=cJSON_GetObjectItem(sub,"kafka_port");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint > 0)
					audit->kafka_port = item->valueint;
			}
			item=cJSON_GetObjectItem(sub,"kafka_username");
			if(agent_config_equal(item, cJSON_String)) {
					strcpy(audit->kafka_username, item->valuestring);
			}
			item=cJSON_GetObjectItem(sub,"kafka_password");
			if(agent_config_equal(item, cJSON_String)) {
					strcpy(audit->kafka_password, item->valuestring);
			}
			item=cJSON_GetObjectItem(sub,"db_clear_max_items");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint > 0)
					audit->db_clear_max_items = item->valueint;
			}
			item=cJSON_GetObjectItem(sub,"db_clear_max_days");
			if(agent_config_equal(item, cJSON_Number)) {
				if(item->valueint > 0)
					audit->db_clear_max_days = item->valueint;
			}
		}
	}
	cJSON_Delete(root);

	/* 初始化默认加密秘钥 */
	memcpy(master->encrypt_key.comkey, COM_DEFAULT_KEY, strlen(COM_DEFAULT_KEY));

	memcpy(&bak_agent, master, sizeof(agent_t));
	return 0;
}

void agt_config_print(void *master)
{
	agent_t *agent = (agent_t *)master;

	main_config_t *common = &agent->config.common;
	const config_log_t *log = &common->log;
	module_config_t *module = &agent->config.modules;
	module_audit_t *audit = &module->audit;

	agent_log(HTTC_INFO, "Agent Start with the following parameters: ");
	agent_log(HTTC_INFO, "main :[work_threads :%d, install_path: %s ]", common->work_threads, agent->root_path);
	agent_log(HTTC_INFO, "modules :[log path :%s, size :%d, level :%d]", log->path, log->size, log->level);


	agent_log(HTTC_INFO, "audit :[db_clear_max_items :%d, db_clear_max_days :%d]", 
			audit->db_clear_max_items, audit->db_clear_max_days);

}
