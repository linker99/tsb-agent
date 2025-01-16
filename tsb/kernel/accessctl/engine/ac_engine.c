#include "access_control.c"


int accessctl_engine_init(void)
{
	int ret = 0;
	struct global_control_policy global_policy = {0};
	uint32_t tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);
	else
		update_fac_conf(&global_policy, valid_license);

	ret = register_feature_conf_notify(FEATURE_FAC, fac_feature_conf_notify_func);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Enter:[%s], register_feature_conf_notify error ret[%d]!\n",__func__, ret);


	global_self_hook = kzalloc( sizeof(struct httcsec_intercept_module), GFP_KERNEL);

	global_old_hook = httcsec_get_hook();
	if(global_old_hook != NULL)
		memcpy(global_self_hook, global_old_hook, sizeof(struct httcsec_intercept_module));

	atomic_set(&global_self_hook->intercept_refcnt, 0);
	//global_self_hook->file_permission = smeasure_file_permission;
	//global_self_hook->inode_permission = smeasure_inode_permission; //echo "aaa">>a.txt;  vim; vi
	//global_self_hook->inode_getattr = smeasure_inode_getattr;
	//global_self_hook->inode_setattr = smeasure_inode_setattr;
	global_self_hook->inode_link = smeasure_inode_link;     //ln
	global_self_hook->inode_unlink = smeasure_inode_unlink; //rm -f
	global_self_hook->inode_rename = smeasure_inode_rename; //mv
	global_self_hook->inode_create = smeasure_inode_create; //mv cp
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	global_self_hook->file_open = smeasure_fac_file_open; //echo "aaa">>a.txt;  vim; vi
#else
	global_self_hook->dentry_open = smeasure_fac_dentry_open;
#endif
	global_self_hook->inode_rmdir = smeasure_inode_rmdir; //rmdir
	global_self_hook->inode_mkdir = smeasure_inode_mkdir; //mkdir

	global_self_hook->httc_module = THIS_MODULE;

	ret = httcsec_register_hook(global_old_hook, global_self_hook);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Httcsec Register accessctl Engine ERROR!\n");
	else
		DEBUG_MSG(HTTC_TSB_DEBUG, "Httcsec Register accessctl Engine OK!\n");
	return ret;
}

int accessctl_engine_exit(void)
{
	int ret = 0;
	//ret = httcsec_unregister_accessctl_engine(&smeasure_engine);
	//if (ret)
	//	printk("Httcsec UNRegister Measure Engine ERROR!\n");
	//else
	//	printk("Httcsec UNRegister Measure Engine OK!\n");
	ret = httcsec_unregister_hook(global_old_hook, global_self_hook);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO, "Httcsec UNRegister ptrace Engine ERROR!\n");
	else
		DEBUG_MSG(HTTC_TSB_DEBUG, "Httcsec UNRegister ptrace Engine OK!\n");
	if(global_self_hook)
		kfree(global_self_hook);


	unregister_feature_conf_notify(FEATURE_FAC, fac_feature_conf_notify_func);

	return ret;
}
