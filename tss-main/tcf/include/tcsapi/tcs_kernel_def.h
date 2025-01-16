#ifndef TCSAPI_TCS_KERNEL_DEF_H_
#define TCSAPI_TCS_KERNEL_DEF_H_

#pragma pack(push, 1)
/** Intercept measure unit sturcture */
struct physical_memory_block{
	uint64_t physical_addr; /** Physical Address */
	uint32_t length;
};
#pragma pack(pop)

#endif
