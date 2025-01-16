PLATFORM_PRIVKEY=60FFA139866D596A8E107C76F3B92BB32422ED302701FA6865B86CC82DAAFC2C
PLATFORM_PUBKEY=09AA298AE0D2FF1A541C4CB02AF80D0C118F427A2623C5DB2D08A151D873CA99FD76A2F4BD9FA0D6FDB52BDE2124DB29B2B170E570A6E1BEE41138608F04750A
PLATFORM_PUBKEY_SIGN=6D9054788B55B8FA3FA22B25426597565887BCE8805C7B52E057C44B2AE712EF5E3610B360D09FE40694DFA510758AA06FF24EE9263F972E2FA7A4383E4EAA14
UPGRADE_SRC=test.bin
UPGRADE_NAME=tpcm_up_image
PBF_VERSION=0x11110000
UEFI_VERSION=0x22220000
UPGRADE_VERSION=0x33330000
COMPARE_FILE=one.txt

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

#../user/tpcm/set_platform_pik_pubkey $PLATFORM_PUBKEY$PLATFORM_PUBKEY_SIGN; exec_check "set_platform_pik_pubkey"
../pack_tool/pack tpcm_all_firm_up_cmd $UPGRADE_SRC $UPGRADE_NAME $PBF_VERSION $UEFI_VERSION $UPGRADE_VERSION $PLATFORM_PRIVKEY $PLATFORM_PUBKEY
:<<!
./user/test/tcs/upgrade_firmware $UPGRADE_NAME; exec_check "upgrade_firmware"
bytes=`ls $UPGRADE_SRC -l | awk  '{print $5}'`
dd if=/opt/httc_flash of=$COMPARE_FILE bs=1 count=$bytes
cmp -s $COMPARE_FILE $UPGRADE_SRC
exec_check "upgrade"
./user/tcs/test/get_tpcmstatus; exec_check "get_tpcmstatus"
!
