
CROSS_COMPILE ?=
CC:= $(CROSS_COMPILE)gcc -g
LD:= $(CROSS_COMPILE)ld

all:
	$(CC) whitelist_test.c -o whitelist_test -L. -lhttctsb
	$(CC) dmesure_test.c -o dmesure_test -L. -lhttctsb
	$(CC) global_test.c -o global_test -L. -lhttctsb
	$(CC) log_test.c -o log_test -L. -lhttctsb
	$(CC) log_config_test.c -o log_config_test -L. -lhttctsb
	$(CC) process_identity_test.c sm3.c -o process_identity_test -L. -lhttctsb
	$(CC) process_roles_test.c -o process_roles_test -L. -lhttctsb
	$(CC) dmesure_process_test.c -o dmesure_process_test -L. -lhttctsb
	$(CC) ptrace_test.c -o ptrace_test -L. -lhttctsb
	$(CC) tsb_user_interface_test.c -o tsb_user_interface_test -L. -lhttctsb
	$(CC) write_user_log_test.c -o write_user_log_test -L. -lhttctsb
	$(CC) write_user_info_log_test.c -o write_user_info_log_test -L. -lhttctsb
	$(CC) log_mem_block_test.c -o log_mem_block_test -L. -lhttctsb
	$(CC) log_mem_nonblock_test.c -o log_mem_nonblock_test -L. -lhttctsb
	$(CC) log_mem_nonblock_recv.c -o log_mem_nonblock_recv -L. -lhttctsb
	$(CC) fac_test.c -o fac_test -L. -lhttctsb
	$(CC) fac_write.c sm3.c -o fac_write

clean:
	rm -f whitelist_test dmesure_test global_test log_test log_config_test process_identity_test process_roles_test dmesure_process_test ptrace_test tsb_user_interface_test write_user_log_test \
	log_mem_block_test log_mem_nonblock_test log_mem_nonblock_recv fac_test fac_write
