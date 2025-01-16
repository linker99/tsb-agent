
#ifndef FT_TPCM_H_
#define FT_TPCM_H_


enum{
	TPCM_ERROR_UNSUPPORTED_CMD_TYPE = 1001,
	TPCM_ERROR_INVALID_COMMAND,
	TPCM_ERROR_MAP_FAIL,
	TPCM_ERROR_NO_SPACE,	//无命令空间
};

struct share_memory{
	uint32_t cmd_type;//命令类型
	int32_t  cmd_length;//命令内容长度

	uint64_t cmd_sequence;//命令序列号
	uint64_t cmd_addr_phys;//命令头物理地址,指向命令头cmd_header

	uint32_t cmd_handled;//命令已处理标记，发送命令时必须为0,TPCM 处理后设置为1,主机发现并未1后读取cmd_ret重新将cmd_handled重新设置为0。
	int32_t cmd_ret;//命令中断处理返回值，由TPCM设值

	int32_t notify_type;//通知类型
	int32_t notify_length;//通知长度
	uint64_t notify_sequence;//序列
	uint64_t notify_addr_phys;//通知物理地址，由TPCM设置
	uint32_t notify_pending;//通知待处理标记，TPCM发送通知时必须为0，发送前设置为1。主机处理完通知中断后重新设置为0
	uint32_t pad;
	//char data_area[0];//数据区域，可用于保存通知的内容。
} __attribute__((packed));



struct cmd_header{
	//输入参数
	//uint64_t cmd_sequence;作为发送命令参数，通过共享内存传递，从命令头移除
	uint64_t input_addr;  //命令输入地址
	uint64_t output_addr;	//命令输出地址
	int32_t input_length;  //命令输入长度
	int32_t output_maxlength;//输出缓冲区最大长度

	//输出参数
//	uint64_t cmd_sequence;//命令序列号，只有异步命令需要，通过共享内存区域notify_sequence传递
	volatile int out_length; //，命令处理后保存输出实际长度
	volatile int out_return; //命令执行结果

} __attribute__((packed));


#endif /* FT_TPCM_H_ */
