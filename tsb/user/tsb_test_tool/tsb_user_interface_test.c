#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "../tsbapi/tsb_measure_user.h"

int main(int argc, char **argv)
{
	int ret = 0;
	char name[512] = {0};
	int length = 0;
	//tsb_measure_process(123);

	//ret = tsb_verify_process(18760, "helloa");
	//ret = tsb_get_process_identity(name, &length);
	//printf("name[%s] length[%d]\n", name, length);
	//ret = tsb_is_role_member("helloa");

	//ret = tsb_measure_kernel_memory("kernel_section");
	//ret = tsb_measure_kernel_memory_all();
	//ret = tsb_measure_process(30759);

	//ret = tsb_measure_file("/root/hyq/a.sh");
	ret = tsb_measure_file_path("//root/hyq/a.sh");
	//ret = tsb_match_file_integrity("123456789", 9);
	//ret = tsb_match_file_integrity_by_path("123456789", 9, "/root/test1.sh", strlen("/root/test1.sh"));

	printf("ret[%d]\n", ret);
	
	return 0;
}