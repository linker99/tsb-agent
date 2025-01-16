echo ""
#!/bin/sh

echo ""
echo "Cert write: 1234567890"
./cert_write -p abc -c 1234567890
./cert_read -p abc
echo ""
