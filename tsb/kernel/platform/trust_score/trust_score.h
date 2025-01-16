#ifndef __TRUST_SCORE_H__
#define __TRUST_SCORE_H__
struct trust_score
{
    unsigned long score;
};

int tsb_get_trust_state(unsigned long param);
int tsb_set_trust_state(unsigned long param);
int trust_score_init(void);
void trust_score_exit(void);
#endif