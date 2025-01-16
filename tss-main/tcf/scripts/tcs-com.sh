usage ()
{
	echo ""
	echo " Usage: ./tcs-com.sh  [debug|release]"
	echo "   e.g. ./tcs-com.sh  release"
	echo "   e.g. ./tcs-com.sh  debug"
	echo ""
}



if [ "$#" -eq 1 ]; then
	if [ $1 == debug ]; then
		cd ../../tcs/scripts/ && chmod +x *.sh && ./debug.sh 
	elif [ $1 == release ]; then
		cd ../../tcs/scripts/ && chmod +x *.sh &&./release.sh 
	else
		usage
		exit 0
	fi
else
	usage
	exit 0
fi
