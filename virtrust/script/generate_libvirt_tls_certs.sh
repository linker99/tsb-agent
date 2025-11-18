#!/bin/bash

# 证书生成工具脚本（基于GnuTLS certtool）
# 功能：创建CA、服务器和客户端证书

set -e  # 遇到错误立即退出
set -u  # 使用未定义变量时报错

# 全局配置
CA_ORG="HW"
SERVER_HOST="compute1.libvirt.org"
SERVER_DNS=("compute1" "compute1.libvirt.org")
if [ $# -eq 0 ]; then
    read -p "请输入服务器 IP: " SERVER_IP
    SERVER_IPS=("$SERVER_IP")
else
    SERVER_IPS=("$@")  # 使用所有传入的参数作为 IP 列表
fi
CLIENT_CN="client1"
CLIENT_COUNTRY="CN"
CLIENT_STATE="XIAN"
CLIENT_LOCALITY="XIAN"

# 安装目录（根据需要修改）
CA_CERT_PATH="/etc/pki/CA/cacert.pem"
SERVER_KEY_PATH="/etc/pki/libvirt/private/serverkey.pem"
SERVER_CERT_PATH="/etc/pki/libvirt/servercert.pem"
CLIENT_KEY_PATH="/etc/pki/libvirt/private/clientkey.pem"
CLIENT_CERT_PATH="/etc/pki/libvirt/clientcert.pem"

# 检查certtool是否安装
if ! command -v certtool &> /dev/null; then
    echo "错误：certtool未安装。请安装gnutls-utils包："
    echo "  Fedora/RHEL: sudo dnf install gnutls-utils"
    echo "  Debian/Ubuntu: sudo apt-get install gnutls-bin"
    exit 1
fi

# 创建临时目录
TMP_DIR=./libvirt_tlscerts
mkdir -p "$TMP_DIR"

# 1. 创建CA证书
echo "===== 创建CA证书 ====="
cat > "$TMP_DIR/ca.info" <<EOF
cn = $CA_ORG
ca
cert_signing_key
EOF

certtool --generate-privkey > "$TMP_DIR/cakey.pem"
certtool --generate-self-signed \
    --load-privkey "$TMP_DIR/cakey.pem" \
    --template "$TMP_DIR/ca.info" \
    --outfile "$TMP_DIR/cacert.pem"

echo "CA证书已生成："
certtool -i --infile "$TMP_DIR/cacert.pem" | grep -E "Subject:|Validity:"

# 2. 创建服务器证书
echo -e "\n===== 创建服务器证书 ====="
cat > "$TMP_DIR/server.info" <<EOF
organization = $CA_ORG
cn = $SERVER_HOST
EOF

# 添加DNS名称
for dns in "${SERVER_DNS[@]}"; do
    echo "dns_name = $dns" >> "$TMP_DIR/server.info"
done

# 添加IP地址
for ip in "${SERVER_IPS[@]}"; do
    echo "ip_address = $ip" >> "$TMP_DIR/server.info"
done

# 添加扩展字段
cat >> "$TMP_DIR/server.info" <<EOF
tls_www_server
signing_key
encryption_key
EOF

certtool --generate-privkey > "$TMP_DIR/serverkey.pem"
certtool --generate-certificate \
    --load-privkey "$TMP_DIR/serverkey.pem" \
    --load-ca-certificate "$TMP_DIR/cacert.pem" \
    --load-ca-privkey "$TMP_DIR/cakey.pem" \
    --template "$TMP_DIR/server.info" \
    --outfile "$TMP_DIR/servercert.pem"

echo "服务器证书已生成："
certtool -i --infile "$TMP_DIR/servercert.pem" | grep -E "Subject:|Subject Alternative Name"

# 3. 创建客户端证书
echo -e "\n===== 创建客户端证书 ====="
cat > "$TMP_DIR/client.info" <<EOF
country = $CLIENT_COUNTRY
state = $CLIENT_STATE
locality = $CLIENT_LOCALITY
organization = $CA_ORG
cn = $CLIENT_CN
tls_www_client
signing_key
encryption_key
EOF

certtool --generate-privkey > "$TMP_DIR/clientkey.pem"
certtool --generate-certificate \
    --load-privkey "$TMP_DIR/clientkey.pem" \
    --load-ca-certificate "$TMP_DIR/cacert.pem" \
    --load-ca-privkey "$TMP_DIR/cakey.pem" \
    --template "$TMP_DIR/client.info" \
    --outfile "$TMP_DIR/clientcert.pem"

echo "客户端证书已生成："
certtool -i --infile "$TMP_DIR/clientcert.pem" | grep -E "Subject:"

# 5. 验证证书链（可选）
echo -e "\n验证证书链..."
certtool --verify --infile "$TMP_DIR/servercert.pem" \
    --load-ca-certificate "$TMP_DIR/cacert.pem"

echo -e "\n生成证书完成，位置： $TMP_DIR，需手动将证书复制到客户端和服务端如下位置："
echo "服务端和客户端：CA证书 -> $CA_CERT_PATH"
echo "服务端：服务器私钥 -> $SERVER_KEY_PATH"
echo "服务端：服务器证书 -> $SERVER_CERT_PATH"
echo "客户端：客户端私钥 -> $CLIENT_KEY_PATH"
echo "客户端：客户端证书 -> $CLIENT_CERT_PATH"