#!/bin/sh

echo ""
echo "cert_write - Auth: abc"
./cert_write -p abc -c 1234567890
echo "cert read - Auth: 123"
./cert_read -p 123
echo "cert read - Auth: abc"
./cert_read -p abc
echo ""

