//const int BLOCK_SIZE=20;  //数组每次增长20个单元为一个单位
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <httcutils/mem.h>
#include <httcutils/array.h>
#if defined platform_2700
#include <httcutils/convert.h>
#endif
static int httc_util_array_inflate(struct  httc_util_array *a,int more_num)  //增长数组的函数more_num为增长单元的数量
{
		int nsize = a->element_size * (a->capability + more_num);
		//printf("increase capability to %d\n",a->capability + more_num);
        void *p = httc_malloc(nsize);  //建立一个增长后的数组空间p
        if(!p)return -1;
        memcpy(p,a->array,a->element_size * a->size);
    	httc_free(a->array);  //释放原有数组的空间
    	a->array=p;  //将数组a的指针指向p所指的新空间
    	a->capability +=  more_num;  //数组a的长度更新
    	return 0;
}
int httc_util_array_init(struct  httc_util_array *a,int element_size,
		int init_cap,int inc_cap){
	  int nsize = element_size * init_cap;
	  void *p = httc_malloc(nsize);
	  if(!p)return -1;
	  memset(p,0,nsize);
	  a->array = p;
	  a->element_size = element_size;
	  a->capability = init_cap;
	  a->size = 0;
	  a->inc_capability = inc_cap;
	  return 0;
}


int httc_util_array_get(struct  httc_util_array *a,int index,void *data)  //输出数组某个位置的值
{
	if(index < 0 && index >= a->size){
		return -1;
	}
	memcpy(data,a->array + index * a->element_size,a->element_size);
	return 0;
}

int httc_util_array_set(struct  httc_util_array *a,int index,void *data)  //数组的赋值
{
	if(index < 0 && index >= a->size){
		return -1;
	}
	memcpy(a->array + index * a->element_size,data,a->element_size);
	return 0;
}
int httc_util_array_append(struct  httc_util_array *a,void *data){
	int r;
	if(a->size == a->capability){
		r = httc_util_array_inflate(a,a->inc_capability);
		if(r)return r;
	}
	memcpy(a->array + a->size++ * a->element_size,data,a->element_size);
	return 0;
}
int httc_util_array_set_size(struct  httc_util_array *a,int nsize){
	int r;
	if(nsize > a->capability){
		r = httc_util_array_inflate(a,nsize -  a->capability);
		if(r)return r;
	}
	a->size = nsize;
	return 0;
}

int httc_util_array_get_size(struct  httc_util_array *a){
	return a->size;
}

int httc_util_array_check(struct  httc_util_array *a, void *data)
{
	int i = 0;
	for (i = 0; i < a->size; i++){
		if (!memcmp (a->array + i*a->element_size, data, a->element_size))
			return 0;
	}	
	return 1;
}

#if defined platform_2700
int ctoi (char c)
{
	int n = 0;
	if (c >= '0' && c <= '9'){
		n = c - '0';
	}
	else if (c >= 'a' && c <= 'f'){
		n = c - 'a' + 10;
	}
	else if (c >= 'A' && c <= 'F'){
		n = c - 'A' + 10;
	}

	return n;
}


void httc_util_str2array (uint8_t *output, uint8_t *input, uint32_t insize)
{
    uint32_t i = 0;    
	while (i < (insize / 2)) {
		output[i] = (ctoi(input[i*2]) << 4) | ctoi(input[i*2+1]);
       	i++;
	}
}

#endif


