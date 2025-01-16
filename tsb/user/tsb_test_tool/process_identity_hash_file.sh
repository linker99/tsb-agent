if [ $# != 1 ]; then
	echo "param error!"
	exit 1
fi

echo $1

cat /proc/$1/maps | awk -F ' ' '{print $6}' | uniq > process_identity_hash_file.txt
sed -i -e '/\//! d' process_identity_hash_file.txt
