
#ifndef INCLUDE_TCFAPI_TCF_PROTECT_H_
#define INCLUDE_TCFAPI_TCF_PROTECT_H_
struct ptrace_protect_update;
struct ptrace_protect_user{
	int is_ptrace_protect;//�Ƿ������̸��ٱ���
	int ptracer_number;//������̣��ɸ����������̵Ľ��̣�������ͨ���������ݼ�����
	int	non_tracee_number;//���ɱ����ٵĽ�����������ʹ���������������Ҳ���ɸ�����Щ���̣�
	char **ptracer_names;//���̵������б�
	char **non_tracee_names;//���̵������б�
	//struct process_name[ptracer_number + untraceable_number] 4 byte align
};

/*
 * 	׼�����¶�̬��������
 */
int tcf_prepare_ptrace_protect_policy(
		struct ptrace_protect_user *items,
		unsigned char *tpcm_id,int tpcm_id_length,
		uint32_t action,	uint64_t replay_counter,
		struct ptrace_protect_update **update,int *olen);

int tcf_update_ptrace_protect_policy(struct ptrace_protect_update *update,
		const char *uid,int cert_type,
		int auth_length,unsigned char *auth);

/*
 * ��ȡ���̸��ٷ�������
 */
int tcf_get_ptrace_protect_policy(struct ptrace_protect_user **ptrace_protect);

/*
 * �ͷŽ��̸��ٷ��������ڴ�
 */
void tcf_free_ptrace_protect_policy(struct ptrace_protect_user *ptrace_protect);
#endif /* INCLUDE_TCFAPI_TCF_PROTECT_H_ */
