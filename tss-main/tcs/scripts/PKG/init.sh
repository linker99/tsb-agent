
EK=1234567812345678123456781234567812345678123456781234567812345678
PSW=123

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

cd ./user/test/tcm
./tcminit; exec_check "tcminit"
./tcmbios; exec_check "tcmbios"
./physicalpresence -x 0x0020; exec_check "physicalpresence -x 0x0020"
./physicalpresence -x 0x0008; exec_check "physicalpresence -x 0x0008"
./physicalenable; exec_check "physicalenable"
./physicalsetdeactivated -c; exec_check "physicalsetdeactivated -c"
./tcminit; exec_check "tcminit"
./tcmbios; exec_check "tcmbios"
./physicalpresence -x 0x0020; exec_check "physicalpresence -x 0x0020"
./physicalpresence -x 0x0008; exec_check "physicalpresence -x 0x0008"
./createrevek  -pwdk $EK -v;
./takeown -pwdo $PSW -pwds $PSW -v;

