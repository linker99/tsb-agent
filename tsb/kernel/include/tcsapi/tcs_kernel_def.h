#ifndef TCSAPI_TCS_KERNEL_DEF_H_
#define TCSAPI_TCS_KERNEL_DEF_H_

#pragma pack(push, 1)
/** Intercept measure unit sturcture */
struct physical_memory_block{
#if defined platform_2700
		uint32_t physical_addr; /** Physical Address */
#else
		uint64_t physical_addr; /** Physical Address */
#endif
	uint32_t length;
};
#pragma pack(pop)

#endif