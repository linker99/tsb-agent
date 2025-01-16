#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include "../../include/common.h"
#include "../msg/command.h"
#include "trust_score.h"
#include "../utils/debug.h"
rwlock_t trust_score_lock;
struct trust_score t_score;

static long ioctl_set_trust_score(unsigned long param)
{
    int ret,trust_score=0;
   read_lock(&trust_score_lock);
   
    ret =copy_from_user(&trust_score,(void *)param, sizeof(uint32_t));

    if (ret)
    {
    	DEBUG_MSG(HTTC_TSB_INFO,"Enter:[%s], copy_to_user get trust score err!\n", __func__);
    }

    t_score.score=trust_score;
    read_unlock(&trust_score_lock);
    return ret;
}

int tsb_get_trust_state(unsigned long param)
{
	int score;
	read_lock(&trust_score_lock);
	score = t_score.score;
	read_unlock(&trust_score_lock);

	return score;
}
EXPORT_SYMBOL(tsb_get_trust_state);

// int tsb_set_trust_state(unsigned long param)
// {

//     read_lock(&trust_score_lock);
//     t_score.score=param;
//     read_unlock(&trust_score_lock);

// 	return 0;
// }
// EXPORT_SYMBOL(tsb_set_trust_state);


int trust_score_init(void)
{
    int ret=0;
    rwlock_init(&trust_score_lock);
    memset(&t_score,0,sizeof(struct trust_score));
    ret=httcsec_io_command_register(COMMAND_SET_TRUST_SCORE, (httcsec_io_command_func)ioctl_set_trust_score);
    if (ret)
        {
            DEBUG_MSG(HTTC_TSB_INFO,"Command NR duplicated %d.\n",COMMAND_SET_TRUST_SCORE);
           
        }
    return ret;
}

void trust_score_exit(void)
{
  httcsec_io_command_unregister(COMMAND_SET_TRUST_SCORE, (httcsec_io_command_func)ioctl_set_trust_score);

}
