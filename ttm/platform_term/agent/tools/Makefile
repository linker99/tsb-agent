include ../rule.mk

all:
	make -C ht_init
	make -C ht_whitelist
	make -C ht_get_systeminfo
	make -C ht_global_policy_switch
	make -C ht_dmeasure
	make -C log-set-tools
	make -C ht_audit_switch

clean:
	make -C ht_init clean
	make -C ht_whitelist clean
	make -C ht_get_systeminfo clean
	make -C ht_global_policy_switch clean
	make -C ht_dmeasure clean
	make -C log-set-tools clean
	make -C ht_audit_switch clean

install:
	make -C ht_init install
	make -C ht_whitelist install
	make -C ht_get_systeminfo install
	make -C ht_global_policy_switch install
	make -C ht_dmeasure install
	make -C log-set-tools install
	make -C ht_audit_switch install

uninstall:
	make -C ht_init uninstall
	make -C ht_whitelist uninstall
	make -C ht_get_systeminfo uninstall
	make -C ht_global_policy_switch uninstall
	make -C ht_dmeasure uninstall
	make -C log-set-tools uninstall
	make -C ht_audit_switch uninstall
