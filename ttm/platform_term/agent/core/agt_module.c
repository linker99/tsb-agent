#include "agt_log.h"
#include "agt_util.h"
#include "agt_module.h"
#include "agt_socket.h"
#include "ht_crypt.h"

extern agent_module_t agent_module_audit;

agent_module_t *agent_modules[AGENT_MODULE_MAX] = {
	&agent_module_audit,
};


int agent_module_init(agent_t *master)
{
	int i;

	for (i=0; i<AGENT_MODULE_MAX; i++) {
		if(master->want_destroy)
			exit(0);
		
		if (agent_modules[i] && agent_modules[i]->module_init) {

			if (agent_modules[i]->module_init((void *)master, NULL) != HTTC_OK) {
				continue;
			}
			
			list_add_tail(&agent_modules[i]->list, &master->module_list);
		}
	}

	return 0;
}

void agent_module_exit(agent_t *master)
{
	int i;

	for (i=0; i<AGENT_MODULE_MAX; i++) {
		if (agent_modules[i] && agent_modules[i]->module_exit) {
			
			agent_modules[i]->module_exit((void *)master, NULL);
		}
	}
}

