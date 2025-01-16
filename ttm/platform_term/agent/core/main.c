#include "agt_log.h"
#include "agt_event.h"
#include "agt_module.h"
#include "agt_timer.h"
#include "agt_util.h"
#include "tsbapi/tsb_admin.h"

agent_t *g_master = NULL;

static void usage()
{
	fprintf(stderr, "Agent Usage:\n");
	fprintf(stderr, "	maple -[fc:n:h]\n");
	fprintf(stderr, "	-f:	running in front\n");
	fprintf(stderr, "	-c:	conf_file\n");
	fprintf(stderr, "	-h:	print usage help information\n");
}

static void sig_handler(int sig) 
{
	switch (sig) {
		case SIGINT:
			fprintf(stdout, "receive signal: sigint\n");
			if(g_master->workers) {
				agent_destroy(g_master);
				exit(0);
			}
			else {
				g_master->want_destroy = 1;
				fprintf(stdout, "waiting for current running module exit!\n");
			}
			break;
		case SIGTERM:
			fprintf(stdout, "receive signal: sigterm\n");
			break;
		case SIGHUP:
			fprintf(stdout, "receive signal: sighup\n");
			break;
		case SIGILL:
			fprintf(stdout, "receive signal: sigill\n");
			break;
		case SIGUSR1:
			fprintf(stdout, "receive signal: sigusr1\n");
			break;
		default:
			break;
	}
}

static void set_signal_handle()
{
	struct sigaction action;
	action.sa_handler = sig_handler;
	sigfillset(&action.sa_mask);
	action.sa_flags = 0;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGHUP, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGUSR1, &action, NULL);
	sigaction(SIGALRM, &action, NULL);
	sigaction(SIGCHLD, &action, NULL);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
}

void agent_param_parse(agent_t *master, int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "fc:p:h")) != -1) {
		switch(c) {
			case 'f' :
				master->foreground = 1;
				break;
			case 'c' :
				master->conf_file = optarg;
				break;
			case 'h' :
				usage();
				exit(0);
			default :
				usage();
				exit(1);
		}
	}

	argc -= optind;
	if(argc != 0) {
		fprintf(stderr, "invalid parameters specified\n");
		exit(1);
	}
	optind = 0;
}

int main(int argc, char *argv[])
{
	set_signal_handle();

	agent_t *master;
	g_master = agent_create(&master);

	agent_param_parse(master, argc, argv);

	if (!master->foreground) {
		daemon(0, 0);
	}

	if(agent_running() != 0) {
		fprintf(stderr, "Another agent may be running, exit...\n");
		agent_free(master);
		exit(0);
	}

	//把current进程加到受保护（防杀死）的列表
	if (tsb_set_process_protect()) {
		fprintf(stderr, "tsb_set_process_protect fail, exit...\n");
		exit(0);
	}
	
	do {
		agent_init(master);

		CHECK(agent_config_parse(master));

		CHECK(agent_log_init(master));

		CHECK(agent_create_socket(master));

		CHECK(agent_module_init(master));

		agent_create_workers(master);

	} while (event_select_wait(master) == HTTC_RELOAD);

	tsb_set_unprocess_protect();

	return 0;
}
