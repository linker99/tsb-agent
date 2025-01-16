/*
 * comm_driver.h
 *
 */

#ifndef SRC_CORE_MODULES_SYSTEM_COMM_DRIVER_H_
#define SRC_CORE_MODULES_SYSTEM_COMM_DRIVER_H_
#include <basic_types.h>


struct command_info{
	uint32_t cmd_type;
	int32_t  cmd_length;
	uint64_t cmd_sequence;
	uint64_t input_addr;
	uint64_t output_addr;
	uint32_t input_length;
	int32_t output_maxlength;
	uint32_t out_length;
	uint32_t out_return;
	char private_data[];//array size = COMMAND_EXTRA_SIZE
};



enum COMMAND_ID_E {
	TDD_CMD_CATEGORY_INIT =0,
	TDD_CMD_CATEGORY_MANAGE,
	TDD_CMD_CATEGORY_TCM,
	TDD_CMD_CATEGORY_TPCM,
	TDD_CMD_CATEGORY_RESERVED_4,
	TDD_CMD_CATEGORY_RESERVED_5,
	TDD_CMD_CATEGORY_RESERVED_6,
	TDD_CMD_CATEGORY_UNSET_REG_ADDR,
	TDD_CMD_CATEGORY_INIT_ASYNC = 8,
	TDD_CMD_CATEGORY_MANAGE_ASYNC,
	TDD_CMD_CATEGORY_TCM_ASYNC,
	TDD_CMD_CATEGORY_TPCM_ASYNC,
	TDD_CMD_CATEGORY_RESERVED_12,
	TDD_CMD_CATEGORY_RESERVED_13,
	TDD_CMD_CATEGORY_RESERVED_14,
	TDD_CMD_CATEGORY_IMAGE_VERIFY=15,
	TDD_CMD_CATEGORY_MAX = 16
};

enum{
	TPCM_NOTIFY_TYPE_LOG = (1 << 1),
	TPCM_NOTIFY_TYPE_MEASURE_ERR = (1 << 2),
	TPCM_NOTIFY_TYPE_LICENSE_EXPIRED = (1 << 3),      //add license expired
	TPCM_NOTIFY_TYPE_POLICIES_VERSION = (1 << 4)     //add license no expired
};

typedef uint32_t (* COMMAND_NOIFTY)(struct command_info *info);
int tpcm_comm_map_address(struct command_info *info,void **input,void **output);
void tpcm_comm_release_command(struct command_info *info);
void tpcm_comm_set_notify_handler(COMMAND_NOIFTY func);
void tpcm_comm_async_command_handled(struct command_info *info);
void tpcm_comm_send_bios_measure_result(uint32_t ret);
void tpcm_comm_send_simple_notify(uint32_t notify_type);
int tpcm_create_sharemem(void);
void tpcm_destroy_sharemem(void);

#endif /* SRC_CORE_MODULES_SYSTEM_COMM_DRIVER_H_ */
