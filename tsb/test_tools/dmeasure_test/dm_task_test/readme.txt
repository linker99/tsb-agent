1、到测试目录执行“./printname”

2、ps查看printname的进程ID（如进程ID为11011）

3、查看进程的内存空间布局：“cat /proc/11011/maps”；（选“r-xp”标识的内存段进行改写，待确认）

4、用gdb修改进程的内存数据：
   gdb -p 11011
   查看内存数据：x/8xb 0x00400000
   修改内存数据：set *(unsigned char*)(0x00400000)=0x79