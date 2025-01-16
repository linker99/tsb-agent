#!/bin/sh

sm2_speed_test()
{
	./sm2_speed -t 100     # 100 times	
	./sm2_speed -t 200     # 200 times	
	./sm2_speed -t 500     # 500 times	
}


sm2_speed_E_test()
{
        ./sm2_speed_E -s 0x80 	  -t 	20     # 128B * 20 times
        ./sm2_speed_E -s 0x200 	  -t 	20     # 512B * 20 times
        ./sm2_speed_E -s 0x400    -t 	20     # 1KB  * 20 times
        ./sm2_speed_E -s 0x2000   -t 	20     # 8KB  * 20 times
        ./sm2_speed_E -s 0x10000  -t 	20     # 64KB * 20 times
}

sm3_speed_test()
{
	./sm3_speed -s 0x400      -t 	20    # 1KB   *  20 times
	./sm3_speed -s 0x20000    -t 	20    # 128KB * 20 times
	./sm3_speed -s 0x80000 	  -t 	20    # 512KB * 20 times
	./sm3_speed -s 0x100000   -t 	20    # 1MB   * 20 times
	./sm3_speed -s 0x800000   -t 	20    # 8MB   * 20 times
	./sm3_speed -s 0x4000000  -t 	20    # 64MB  * 20 times
}

sm4_speed_test()
{
	./sm4_speed -s 0x400      -t 	20    # 1MB * 20 times
	./sm4_speed -s 0x20000    -t 	20    # 4MB * 20 times
	./sm4_speed -s 0x80000    -t 	20    # 8MB * 20 times
	./sm4_speed -s 0x100000   -t 	20    # 1MB * 20 times
	./sm4_speed -s 0x800000   -t 	20    # 4MB * 20 times
	./sm4_speed -s 0x4000000  -t 	20    # 8MB * 20 times
}

main()
{
	echo ""
	sm2_speed_test
	echo ""
	sm2_speed_E_test
	echo ""
	sm3_speed_test
	echo ""
	sm4_speed_test
	echo ""

}

main

