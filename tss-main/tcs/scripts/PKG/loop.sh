PLATFORM_PRIVKEY=60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C
PLATFORM_PUBKEY=09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A
PLATFORM_PUBKEY_SIGN=6D9054788B55B8FA3FA22B25426597565887BCE8805C7B52E057C44B2AE712EF5E3610B360D09FE40694DFA510758AA06FF24EE9263F972E2FA7A4383E4EAA14
TPCM_PIK_HANDLE_FILE=tpcm-pik-handle.txt

if [ ! -z $1 ];then
        cycle=$1
else
        echo ""
        echo " Usage: ./loop.sh [cycle] [option]"
        echo "   e.g. ./loop.sh 10 1"
        echo ""
        exit 0
fi



error ()
{
	local msg; local logtype;
	logtype="error"
	msg=$1
	datetime=`date +'%F %H:%M:%S'`
	logformat="[${logtype}]\t${datetime}\t${msg}"
	echo "${logformat}" 
}

exec_check ()
{
	if [ ! $? -eq 0 ]; then
		error "$1 error!"
		exit 1
	fi
}

right_check ()
{
	if [ $? -eq 0 ]; then
		error "$1 right!"
		exit 1
	fi
}

:<<!
if [ ! -z $2 ];then
        option=$2
else
        echo ""
        echo " Usage: ./loop.sh [cycle] [option]"
        echo "   e.g. ./loop.sh 10 1"
        echo ""
        exit 0
fi
test()
{
	
	echo "$2"
	case $option in
	"1")	./user/tpcm/get_update_bootmeasurereference -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY; exec_check "get_update_bootmeasurereference";;
	"2") 	./user/tpcm/get_trustedcredential; exec_check "get_trustedcredential";;
	"3")	./user/tpcm/get_tpcmstatus; exec_check "get_tpcmstatus";;
	"4")	./user/tpcm/get_tpcmmark; exec_check "get_tpcmmark";;
	"5")	./user/tpcm/get_tpcmfeature; exec_check "get_tpcmfeature";;
	"6")	./user/tpcm/set_dynamic_measurepolicy -s on -d 10 -k $PLATFORM_PRIVKEY$PLATFORM_PUBKEY;exec_check "set_dynamic_measurepolicy";;
	"7")	./user/tpcm/set_measureswitch im on $PLATFORM_PRIVKEY$PLATFORM_PUBKEY; exec_check "set_measureswitch im";;
	"9")	insmod ./kernel/tpcm/get_tpcmmark.ko size=32; exec_check "get_tpcmmark.ko";
			rmmod get_tpcmmark;;
	"10")	insmod ./kernel/tpcm/get_tpcmfeature.ko; exec_check "get_tpcmfeature.ko";
			rmmod get_tpcmfeature;;
	"11")	insmod ./kernel/tpcm/get_trustedcredential.ko; exec_check "get_trustedcredential.ko";
			rmmod get_trustedcredential;;
	"12")	insmod ./kernel/tpcm/savekey.ko key=74CC3A48E12E26C059BD0F7AAD0B437666985080A011E5FB3625E90549EDC9B2; exec_check "savekey.ko";
			rmmod savekey;;
	"13")   insmod ./kernel/tpcm/getkey.ko size=32; exec_check "getkey.ko";
			rmmod getkey;;
	*)
        echo ""
        echo " Usage: ./loop.sh [cycle] [option]"
        echo "   e.g. ./loop.sh 10 1"
        echo ""
        exit 0
	esac
}
!
./user/test/tcs/tcs_init httc@123
./user/test/tcs/generate_tpcm_pik httc@123
finished=0
while [ $cycle -gt 0 ]
do
	test
	cycle=$((cycle-1))
#	./user/test/tcs/create_seal_key -k s://seal/$finished -t 0 -p 123456 -o 0
#	./user/test/tcs/create_sign_key -k s://$finished -t 0 -p 123456 -o 0
#	./user/test/tcm/createkey -ku b -kt s -hp 0x40000000 -pwdp httc@123 -pwdk 123123 -ok $finished.key;
#	./user/test/tcm/physicalenable
	./user/test/tcs/get_tpcm_id
	finished=$((finished+1))
	echo "####################### RUN $finished Cycles Finished #######################"
#	sleep 10
done
