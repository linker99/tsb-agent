#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include "httcutils/debug.h"
#include "tcfapi/tcf_key.h"

struct test{
	char name[20];
	int length;
	struct test *next[0];
};


void usage()
{
	printf ("\n"
			" Usage: ./read_tree [options]\n"
			" options:\n"
			"	 	 -k <keypath>			- The key path\n"
			"		 -l <level>			    - The level want to read\n"
			"		 -r <recursive>			- Release mode 0:current 1:all(default)\n"
			"    eg. ./read_tree -k s://a/b  -l 1 -r 1 \n"			
			"\n");
}

static void show_node(struct key_node *node){

	int i = 0;
	struct key_node *curnode = NULL;
	curnode = node;
	while(1){
//			printf("i:%d number:%d add:%p\n",i,curnode->children_number,node->children[i]);
			if(curnode->children_number && node->children[i]) show_node(node->children[i]);
			printf("\n\n");	
			printf("node name:%s\n",curnode->name);			
			if(!curnode->key.key_size){ 
				printf("node seal size:%d\n",curnode->seal_data.size);
			}else{
				printf("node key_type:%d\n",curnode->key.key_type);
				printf("node key_use:%d\n",curnode->key.key_use);
				printf("node origin:%d\n",curnode->key.origin);
				printf("node key_size:%d\n",curnode->key.key_size);
				printf("node migratable:%d\n",curnode->key.migratable);
				printf("node attribute:%d\n",curnode->key.attribute);
			}
			if(curnode->policy.policy_flags){
				printf("policy->flags:0x%08X\n",curnode->policy.policy_flags);
				printf("policy->process_or_role:%s\n",curnode->policy.process_or_role);
				printf("policy->user_or_group:%d\n",curnode->policy.user_or_group);
				
			}
			printf("node children number:%d\n",curnode->children_number);
			i++;
			if(!node->children[i]) break;
			curnode = node->children[i];
		}
}


int main(int argc, char **argv){

	int ret = 0;
	int ch = 0;
	unsigned int level = 0;
	int recursive = 1;
	char *key_path = NULL;
	struct key_node *node = NULL; 
	
	if (argc < 5){
		usage ();
		return -1;
	}
	
	while ((ch = getopt(argc, argv, "k:l:r:")) != -1)
	{
		switch (ch) 
		{
			case 'k':
				key_path = optarg;
				printf ("keypath: %s\n", key_path);
				break;
			case 'l':
				level = atoi(optarg);
				break;
			case 'r':
				recursive = atoi(optarg);
				break;
			default:
				usage();
				break;				
		}
	}


	if(!level || !key_path) {
		usage();
		return -1;
	}
	ret = tcf_read_keytree((const char *)key_path,&node,level);
	if(ret){
		printf("tcm_read_keytree fail!\n");
		return -1;
	}
	show_node(node);
	ret = tcf_free_keynode(&node,recursive);
	return 0;	
}




