/*
 * array.h
 *
 *  Created on: 2021年4月25日
 *      Author: wangtao
 */

#ifndef HTTCUTILS_ARRAY_H_
#define HTTCUTILS_ARRAY_H_

struct  httc_util_array//建立一个数组结构体
{
	int inc_capability;
	int element_size;
	void *array;
    int capability;
    int size;
};
int httc_util_array_init(struct  httc_util_array *a,int element_size,
		int init_capability,int inc_capability);
int httc_util_array_get(struct  httc_util_array *a,int index,void *data);
int httc_util_array_append(struct  httc_util_array *a,void *data);
int httc_util_array_set(struct  httc_util_array *a,int index,void *data);
int httc_util_array_set_size(struct  httc_util_array *a,int nsize);
int httc_util_array_get_size(struct  httc_util_array *a);
int httc_util_array_check(struct  httc_util_array *a, void *data);
#endif /* HTTCUTILS_ARRAY_H_ */
