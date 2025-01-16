#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include "tcsapi/tcs_policy_def.h"
#include "../policy/feature_configure.h"
#include "../utils/debug.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
struct global_params 
{
	char *procname;
	unsigned short mode;
	struct  proc_ops *proc_fops;
}; 
#else
struct global_params 
{
	char *procname;
	unsigned short mode;
	struct file_operations *proc_fops;
};
#endif


static struct proc_dir_entry *proc_parent;

static ssize_t measure_on_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_boot_measure_on);
	ret_data = copy_to_user(buf, ibuf, len);
	

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	    return 0;
	}

	return 0;
}

static ssize_t program_measure_on_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_program_measure_on);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
           return 0;
	}

	return 0;
}

static ssize_t dynamic_measure_on_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_dynamic_measure_on);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
            return 0;
	}

	return 0;
}

static ssize_t boot_control_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_boot_control);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	 	return 0;
	}

	return 0;
}

static ssize_t program_control_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_program_control);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	   return 0;
	}

	return 0;
}

static ssize_t tsb_flag1_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_tsb_flag1);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	   return 0;
	}
	return 0;
}

static ssize_t tsb_flag2_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_tsb_flag2);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
           return 0;
	}
	return 0;
}

static ssize_t tsb_flag3_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_tsb_flag3);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	   return 0;
	}
	return 0;
}

static ssize_t program_measure_mode_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_program_measure_mode);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	   return 0;
	}
	return 0;
}

static ssize_t measure_use_cache_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_measure_use_cache);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	   return 0;
	}

	return 0;
}

static ssize_t dmeasure_max_busy_delay_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_dmeasure_max_busy_delay);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	    return 0;
	}
	return 0;
}

static ssize_t dmeasure_ref_mode_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_process_dmeasure_ref_mode);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	   return 0;
	}

	return 0;
}

static ssize_t dmeasure_match_mode_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_process_dmeasure_match_mode);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	    return 0;
	}

	return 0;
}

static ssize_t measure_match_mode_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_program_measure_match_mode);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	   return 0;
	}
		
	return 0;
}

static ssize_t dmeasure_lib_mode_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_process_dmeasure_lib_mode);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	  return 0;
	}

	return 0;
}

static ssize_t process_verify_lib_mode_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_process_verify_lib_mode);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
	 	return 0;
	}

	return 0;
}

static ssize_t dmeasure_sub_process_mode_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_process_dmeasure_sub_process_mode);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	    return 0;


	return 0;
}

static ssize_t dmeasure_old_process_mode_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_process_dmeasure_old_process_mode );
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
           return 0;
	}
	return 0;
}

static ssize_t dmeasure_interval_read_proc(struct file *filp,char __user *buf,size_t count,loff_t *offp )
{
	char ibuf[32];
	static char flag = 0;
	int len;
	int ret;
	int ret_data;
	struct global_control_policy global_policy = {0};
	unsigned int tpcm_feature = 0;
	int valid_license = 0;

	ret = get_global_feature_conf(&global_policy, &tpcm_feature, &valid_license);
	if (ret)
		DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], get_global_feature_conf error ret[%d]!\n",__func__, ret);

	len = sprintf(ibuf,"%d\n",global_policy.be_process_dmeasure_interval);
	ret_data = copy_to_user(buf, ibuf, len);

	if (flag == 0)
	{
		flag = 1;
		return len;
	}
	else 
	{
		flag = 0;
		return 0;
	}

	if(ret_data)
	{
           return 0;
	}

	return 0;
}

/*
static ssize_t write_proc(struct file *filp,const char __user *buffer, size_t count, loff_t *offp)
{
	int ret = 0;
	return ret;
}
*/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)

static struct proc_ops measure_on_proc_fops =
{
        .proc_read = measure_on_read_proc,
	/* .write = write_proc, */
};

static struct proc_ops program_measure_on_proc_fops =
{
        .proc_read = program_measure_on_read_proc,
};

static struct proc_ops dynamic_measure_on_proc_fops =
{
	.proc_read = dynamic_measure_on_read_proc,
};

static struct proc_ops boot_control_proc_fops =
{
	.proc_read = boot_control_read_proc,
};

static struct proc_ops program_control_proc_fops =
{
	.proc_read = program_control_read_proc,
};

static struct proc_ops tsb_flag1_proc_fops =
{
	.proc_read = tsb_flag1_read_proc,
};

static struct proc_ops tsb_flag2_proc_fops =
{
	.proc_read = tsb_flag2_read_proc,
};

static struct proc_ops tsb_flag3_proc_fops =
{
	.proc_read = tsb_flag3_read_proc,
};

static struct proc_ops program_measure_mode_proc_fops =
{
	.proc_read = program_measure_mode_read_proc,
};

static struct proc_ops measure_use_cache_proc_fops =
{
	.proc_read = measure_use_cache_read_proc,
};

static struct proc_ops dmeasure_max_busy_delay_proc_fops =
{
	.proc_read = dmeasure_max_busy_delay_read_proc,
};

static struct proc_ops dmeasure_ref_mode_proc_fops =
{
	.proc_read = dmeasure_ref_mode_read_proc,
};

static struct proc_ops dmeasure_match_mode_proc_fops =
{
	.proc_read = dmeasure_match_mode_read_proc,
};

static struct proc_ops measure_match_mode_proc_fops =
{
	.proc_read = measure_match_mode_read_proc,
};

static struct proc_ops dmeasure_lib_mode_proc_fops =
{
	.proc_read = dmeasure_lib_mode_read_proc,
};

static struct proc_ops process_verify_lib_mode_proc_fops =
{
	.proc_read = process_verify_lib_mode_read_proc,
};

static struct proc_ops dmeasure_sub_process_mode_proc_fops =
{
	.proc_read = dmeasure_sub_process_mode_read_proc,
};

static struct proc_ops dmeasure_old_process_mode_proc_fops =
{
	.proc_read = dmeasure_old_process_mode_read_proc,
};

static struct proc_ops dmeasure_interval_proc_fops =
{
	.proc_read = dmeasure_interval_read_proc,
};

static struct global_params global_proc_params[] =
{
	{
		.procname	= "measure_on",
		.mode		= 0444,
                .proc_fops      = &measure_on_proc_fops,
	},
	{
		.procname	= "program_measure_on",
		.mode		= 0444,
		.proc_fops      = &program_measure_on_proc_fops,

	},
	{
		.procname	= "dynamic_measure_on",
		.mode		= 0444,
		.proc_fops      = &dynamic_measure_on_proc_fops,
	},
	{
		.procname	= "boot_control",
		.mode		= 0444,
		.proc_fops      = &boot_control_proc_fops,
	},
	{
		.procname	= "program_control",
		.mode		= 0444,
		.proc_fops      = &program_control_proc_fops,
	},
	{
		.procname       = "tsb_flag1",
		.mode		= 0444,
		.proc_fops      = &tsb_flag1_proc_fops,
	},
	{
		.procname       = "tsb_flag2",
		.mode		= 0444,
		.proc_fops      = &tsb_flag2_proc_fops,
	},
	{
		.procname       = "tsb_flag3",
		.mode		= 0444,
		.proc_fops      = &tsb_flag3_proc_fops,
	},
	{
		.procname       = "program_measure_mode",
		.mode		= 0444,
		.proc_fops      = &program_measure_mode_proc_fops,
	},
	{
		.procname       = "measure_use_cache",
		.mode		= 0444,
		.proc_fops      = &measure_use_cache_proc_fops,
	},
	{
		.procname       = "dmeasure_max_busy_delay",
		.mode		= 0444,
		.proc_fops      = &dmeasure_max_busy_delay_proc_fops,
	},
	{
		.procname       = "dmeasure_ref_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_ref_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_match_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_match_mode_proc_fops,
	},
	{
		.procname       = "measure_match_mode",
		.mode		= 0444,
		.proc_fops      = &measure_match_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_lib_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_lib_mode_proc_fops,
	},
	{
		.procname       = "process_verify_lib_mode",
		.mode		= 0444,
		.proc_fops      = &process_verify_lib_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_sub_process_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_sub_process_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_old_process_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_old_process_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_interval",
		.mode		= 0444,
		.proc_fops      = &dmeasure_interval_proc_fops,
	},
	{ },
};


#else

static struct file_operations measure_on_proc_fops =
{ 
        .read = measure_on_read_proc,
	/* .write = write_proc, */
};

static struct file_operations program_measure_on_proc_fops =
{ 
        .read = program_measure_on_read_proc,
};

static struct file_operations dynamic_measure_on_proc_fops =
{ 
	.read = dynamic_measure_on_read_proc,
};

static struct file_operations boot_control_proc_fops =
{ 
	.read = boot_control_read_proc,
};

static struct file_operations program_control_proc_fops =
{ 
	.read = program_control_read_proc,
};

static struct file_operations tsb_flag1_proc_fops =
{ 
	.read = tsb_flag1_read_proc,
};

static struct file_operations tsb_flag2_proc_fops =
{ 
	.read = tsb_flag2_read_proc,
};

static struct file_operations tsb_flag3_proc_fops =
{ 
	.read = tsb_flag3_read_proc,
};

static struct file_operations program_measure_mode_proc_fops =
{ 
	.read = program_measure_mode_read_proc,
};

static struct file_operations measure_use_cache_proc_fops =
{ 
	.read = measure_use_cache_read_proc,
};

static struct file_operations dmeasure_max_busy_delay_proc_fops =
{ 
	.read = dmeasure_max_busy_delay_read_proc,
};

static struct file_operations dmeasure_ref_mode_proc_fops =
{ 
	.read = dmeasure_ref_mode_read_proc,
};

static struct file_operations dmeasure_match_mode_proc_fops =
{ 
	.read = dmeasure_match_mode_read_proc,
};

static struct file_operations measure_match_mode_proc_fops =
{ 
	.read = measure_match_mode_read_proc,
};

static struct file_operations dmeasure_lib_mode_proc_fops =
{ 
	.read = dmeasure_lib_mode_read_proc,
};

static struct file_operations process_verify_lib_mode_proc_fops =
{ 
	.read = process_verify_lib_mode_read_proc,
};

static struct file_operations dmeasure_sub_process_mode_proc_fops =
{ 
	.read = dmeasure_sub_process_mode_read_proc,
};

static struct file_operations dmeasure_old_process_mode_proc_fops =
{ 
	.read = dmeasure_old_process_mode_read_proc,
};

static struct file_operations dmeasure_interval_proc_fops =
{ 
	.read = dmeasure_interval_read_proc,
};

static struct global_params global_proc_params[] =
{
	{
		.procname	= "measure_on",
		.mode		= 0444,
                .proc_fops      = &measure_on_proc_fops,
	},
	{
		.procname	= "program_measure_on",
		.mode		= 0444,
		.proc_fops      = &program_measure_on_proc_fops,
		
	},
	{
		.procname	= "dynamic_measure_on",
		.mode		= 0444,
		.proc_fops      = &dynamic_measure_on_proc_fops,
	},
	{
		.procname	= "boot_control",
		.mode		= 0444,
		.proc_fops      = &boot_control_proc_fops,
	},
	{
		.procname	= "program_control",
		.mode		= 0444,
		.proc_fops      = &program_control_proc_fops,
	},
	{
		.procname       = "tsb_flag1",
		.mode		= 0444,
		.proc_fops      = &tsb_flag1_proc_fops,
	},
	{
		.procname       = "tsb_flag2",
		.mode		= 0444,
		.proc_fops      = &tsb_flag2_proc_fops,
	},
	{
		.procname       = "tsb_flag3",
		.mode		= 0444,
		.proc_fops      = &tsb_flag3_proc_fops,
	},
	{
		.procname       = "program_measure_mode",
		.mode		= 0444,
		.proc_fops      = &program_measure_mode_proc_fops,
	},
	{
		.procname       = "measure_use_cache",
		.mode		= 0444,
		.proc_fops      = &measure_use_cache_proc_fops,
	},
	{
		.procname       = "dmeasure_max_busy_delay",
		.mode		= 0444,
		.proc_fops      = &dmeasure_max_busy_delay_proc_fops,
	},
	{
		.procname       = "dmeasure_ref_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_ref_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_match_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_match_mode_proc_fops,
	},
	{
		.procname       = "measure_match_mode",
		.mode		= 0444,
		.proc_fops      = &measure_match_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_lib_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_lib_mode_proc_fops,
	},
	{
		.procname       = "process_verify_lib_mode",
		.mode		= 0444,
		.proc_fops      = &process_verify_lib_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_sub_process_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_sub_process_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_old_process_mode",
		.mode		= 0444,
		.proc_fops      = &dmeasure_old_process_mode_proc_fops,
	},
	{
		.procname       = "dmeasure_interval",
		.mode		= 0444,
		.proc_fops      = &dmeasure_interval_proc_fops,
	},
	{ },
};
#endif
int tsb_create_proc_entry(void) 
{
	struct global_params *proc_dir = NULL;
 
	proc_parent = proc_mkdir("tpcm",NULL);
	if(!proc_parent)
	{
		DEBUG_MSG(HTTC_TSB_INFO,"Error creating proc entry");
		return -1;
	}

	for(proc_dir = global_proc_params; proc_dir->procname != NULL; proc_dir++) 
		proc_create(proc_dir->procname, proc_dir->mode ,proc_parent, proc_dir->proc_fops);

	return 0;
}

int proc_init (void) 
{
	int ret;
	ret = tsb_create_proc_entry();
	return ret;
}

void proc_exit(void) 
{
	struct global_params *proc_dir = NULL;
	if(proc_parent != NULL)
	{
		for(proc_dir = global_proc_params; proc_dir->procname != NULL; proc_dir++) 
			remove_proc_entry(proc_dir->procname,proc_parent);
	}
	remove_proc_entry("tpcm",NULL);
}
