#ifndef __AGENT_STRING_H__
#define __AGENT_STRING_H__

#include "cJSON.h"
#include <stdio.h>
#include <string.h>


void str_to_binary(const char *src, char *dst, int dst_len);
void binary_to_str(const void *src, char *dst, int dst_len);

char *audit_packet_encrypt(void *agent, cJSON *root);

#endif
