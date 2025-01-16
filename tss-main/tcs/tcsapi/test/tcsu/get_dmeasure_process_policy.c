#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "mem.h"
#include "debug.h"
#include "convert.h"
#include "tcs_dmeasure.h"
#include "tcs_policy_def.h"

static void usage ()
{
	printf ("\n"
			" Usage: ./get_dmeasure_policy\n"
			"\n");
}

int main (int argc, char **argv)
{
	int ret = 0;
	int i = 0;
	int num = 0;
	int ops = 0;
	int size = 0;
	int item_size = 0;
	uint8_t *policy = NULL;
	struct dmeasure_process_item *item = NULL;
	ret = tcs_get_dmeasure_process_policy ((struct dmeasure_process_item **)&policy, &num, &size);
	if (ret){
		printf ("[tcs_get_dmeasure_process_policy] ret: %d(0x%x)\n", ret, ret);
		return -1;
	}

	for (i = 0; i < num; i ++){
		if ((ops + sizeof (struct dmeasure_process_item)) >= size){
				httc_util_pr_error ("Invalid item[%d] data!\n", i);
				ret = -1;
				goto out;
		}
		item = (struct dmeasure_process_item *)(policy + ops);
		item_size = HTTC_ALIGN_SIZE (sizeof (struct  dmeasure_process_item) + ntohs(item->be_object_id_length), 4);
		if ((ops + item_size) > size){
				httc_util_pr_error ("Invalid item[%d] data!\n", i);
				ret = -1;
				goto out;
		}

		printf ("\n");
		printf ("item index: %d\n", i);
        printf ("[%d].object_id_type: %d\n", i, item->object_id_type);
        printf ("[%d].sub_process_mode: %d\n", i, item->sub_process_mode);
        printf ("[%d].old_process_mode: %d\n", i, item->old_process_mode);
        printf ("[%d].share_lib_mode: %d\n", i, item->share_lib_mode);
        printf ("[%d].measure_interval: %d\n", i, ntohl(item->be_measure_interval));
        printf ("[%d].object_id_length :%d\n", i, ntohs(item->be_object_id_length));
		if (item->object_id_type == PROCESS_DMEASURE_OBJECT_ID_HASH){
			printf ("[%d].", i); httc_util_dump_hex ("object_id", item->object_id, ntohs(item->be_object_id_length));
		}else
			printf ("[%d].object_id: %s\n", i, item->object_id);
		ops += item_size;
	}
	printf ("\n");

out:
	if (policy)	httc_free (policy);
	return ret;
}



