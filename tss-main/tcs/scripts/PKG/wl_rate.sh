

FILE_INTEGRITY_UID="file-integrity-uid"
PLATFORM_PRIVKEY=60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C
PLATFORM_PUBKEY=09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A

no_extern_test()
{
	echo ""
	echo "reset速率测试，不带扩展..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "reset速率测试，每次清空后测试，不带扩展..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "add速率测试，不带扩展..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "add速率测试，每次清空后测试，不带扩展..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "delete速率测试，不带扩展..."
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -l 20 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 2 -u $FILE_INTEGRITY_UID -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 2 -u $FILE_INTEGRITY_UID -l 5 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 2 -u $FILE_INTEGRITY_UID -l 10 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "modify速率测试，不带扩展..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -l 5 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -l 10 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
}

library_test()
{
	echo ""
	echo "reset速率测试，带扩展lib库..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "reset速率测试，每次清空后测试，带扩展lib库..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "add速率测试，带扩展lib库..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "add速率测试，每次清空后测试，带扩展lib库..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "delete速率测试，带扩展lib库..."
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 20 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 2 -u $FILE_INTEGRITY_UID -e -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 2 -u $FILE_INTEGRITY_UID -e -l 5 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 2 -u $FILE_INTEGRITY_UID -e -l 10 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "modify速率测试，带扩展lib库..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -e -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -e -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -e -l 5 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -e -l 10 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "modify速率测试，已存在，带扩展数据..."
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -e -l 20 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -e -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -e -l 5 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -e -l 10 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
}

extern_test()
{
	echo ""
	echo "reset速率测试，带扩展数据..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "reset速率测试，每次清空后测试，带扩展数据..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "add速率测试，带扩展数据..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "add速率测试，每次清空后测试，带扩展数据..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 1000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 2000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 5000 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "delete速率测试，带扩展数据..."
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 20 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 2 -u $FILE_INTEGRITY_UID -F 0x80 -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 2 -u $FILE_INTEGRITY_UID -F 0x80 -l 5 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 2 -u $FILE_INTEGRITY_UID -F 0x80 -l 10 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "modify速率测试，带扩展数据..."
	./user/tcs/update_file_integrity -o 0 -u $FILE_INTEGRITY_UID -F 0x80 -f /bin/ls -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -F 0x80 -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -F 0x80 -l 5 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -F 0x80 -l 10 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	echo ""
	echo "modify速率测试，已存在，带扩展数据..."
	./user/tcs/update_file_integrity -o 1 -u $FILE_INTEGRITY_UID -F 0x80 -l 20 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY > /dev/null
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -F 0x80 -l 1 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -F 0x80 -l 5 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
	./user/tcs/update_file_integrity -o 3 -u $FILE_INTEGRITY_UID -F 0x80 -l 10 -d /usr -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY
}

main ()
{
	echo ""
	no_extern_test
	library_test
	extern_test
	echo "测试完毕"
	echo ""
}

main 










