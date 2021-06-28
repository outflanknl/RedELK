#!/bin/sh
#
# Part of RedELK
# Script to generate TLS certificates, SSH keys and installation packages required for RedELK
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="./redelk-inintialsetup.log"
INSTALLER="RedELK cert and key installer"

echoerror() {
    printf "`date +'%b %e %R'` $INSTALLER - ${RC} * ERROR ${EC}: $@\n" >> $LOGFILE 2>&1
}

printf "`date +'%b %e %R'` $INSTALLER - Starting installer\n" > $LOGFILE 2>&1
echo ""
echo ""
echo ""
echo "    ____            _  _____  _      _  __"
echo "   |  _ \  ___   __| || ____|| |    | |/ /"
echo "   | |_) |/ _ \ / _  ||  _|  | |    | ' / "
echo "   |  _ <|  __/| (_| || |___ | |___ | . \ "
echo "   |_| \__\___| \____||_____||_____||_|\_\\"
echo ""
echo ""
echo ""
echo "This script will generate necessary keys and packages for RedELK deployments"
echo ""
echo ""

if ! [ $# -eq 1 ] ; then
    echo "[X] ERROR missing parameter"
    echo "[X] require 1st parameter: path of openssl config file (likely 'certs/config.cnf')"
    echoerror "[X] Incorrect amount of parameters"
    exit 1
fi

if [  ! -f $1 ];then
    echo "[X]  ERROR Could not find openssl config file. Stopping"
    echoerror "[X] Could not find openssl config file"
    exit 1
fi >> $LOGFILE 2>&1

echo ""
echo "[*] Will generate TLS certificates for the following DNS names and/or IP addresses:" | tee -a $LOGFILE
grep -E "^DNS\.|^IP\." certs/config.cnf
echo ""
echo "[!] Make sure your ELK server will be reachable on these DNS names or IP addresses or your TLS setup will fail!" | tee -a $LOGFILE
echo "[*] Abort within 10 seconds to correct if needed." | tee -a $LOGFILE
sleep 10

echo "[*] Creating certs dir if necessary" | tee -a $LOGFILE
if [ ! -d "./certs" ]; then
    mkdir ./certs
fi >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not create ./certs directory (Error Code: $ERROR)."
fi

echo "[*] Generating private key for CA" | tee -a $LOGFILE
if [ ! -f "./certs/redelkCA.key" ]; then
    openssl genrsa -out ./certs/redelkCA.key 2048
fi  >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not generate private key for CA (Error Code: $ERROR)."
fi

echo "[*] Creating Certificate Authority" | tee -a $LOGFILE
if [ ! -f "./certs/redelkCA.crt" ]; then
    openssl req -new -x509 -days 3650 -nodes -key ./certs/redelkCA.key -sha256 -out ./certs/redelkCA.crt -extensions v3_ca -config $1
fi  >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not generate certificate authority (Error Code: $ERROR)."
fi

echo "[*] Generating private key for ELK server" | tee -a $LOGFILE
if [ ! -f "./certs/elkserver.key" ]; then
    openssl genrsa -out ./certs/elkserver.key 2048
fi  >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not generate private key for ELK server (Error Code: $ERROR)."
fi

echo "[*] Generating certificate for ELK server" | tee -a $LOGFILE
if [ ! -f "./certs/elkserver.csr" ]; then
    openssl req -sha512 -new -key ./certs/elkserver.key -out ./certs/elkserver.csr -config $1
fi >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not generate certificates for elk server  (Error Code: $ERROR)."
fi

echo "[*] Signing certificate of ELK server with our new CA" | tee -a $LOGFILE
if [ ! -f "./certs/elkserver.crt" ]; then
    openssl x509 -days 3650 -req -sha512 -in ./certs/elkserver.csr -CAcreateserial -CA ./certs/redelkCA.crt -CAkey ./certs/redelkCA.key -out ./certs/elkserver.crt -extensions v3_req -extfile $1
fi >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not sign elk server certificate with CA (Error Code: $ERROR)."
fi

echo "[*] Converting ELK server private key to PKCS8 format" | tee -a $LOGFILE
if [ ! -f "./certs/elkserver.key.pem" ]; then
    cp ./certs/elkserver.key ./certs/elkserver.key.pem && openssl pkcs8 -in ./certs/elkserver.key.pem -topk8 -nocrypt -out ./certs/elkserver.key
fi  >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not convert ELK server private key to PKCS8 format(Error Code: $ERROR)."
fi

echo "[*] Copying certificates to relevant redir and c2servers folders." | tee -a $LOGFILE
mkdir -p ./elkserver/mounts/logstash-config/certs_inputs/ >> $LOGFILE 2>&1
cp -r ./certs/* ./elkserver/mounts/logstash-config/certs_inputs/ >> $LOGFILE 2>&1
cp ./certs/redelkCA.crt ./c2servers/filebeat/ >> $LOGFILE 2>&1
cp ./certs/redelkCA.crt ./redirs/filebeat/ >> $LOGFILE 2>&1

echo "[*] Copying certificates to elkserver directory." | tee -a $LOGFILE
mkdir elkserver/initial-setup-data && cp -r certs elkserver/initial-setup-data/ >> $LOGFILE 2>&1

echo "[*] Creating ssh directories if necessary" | tee -a $LOGFILE
if [ ! -d "./sshkey" ] || [ ! -d "./elkserver/mounts/redelk-ssh" ] || [ ! -d "./c2servers/ssh" ] ; then
    mkdir -p ./sshkey && mkdir -p ./elkserver/mounts/redelk-ssh && mkdir -p ./c2servers/ssh
fi >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not create ssh directories (Error Code: $ERROR)."
fi

echo "[*] Generating SSH key pair for scponly user" | tee -a $LOGFILE
if [ ! -f "./sshkey/id_rsa" ] ||  [ ! -f "sshkey/id_rsa.pub" ]; then
    ssh-keygen -t rsa -f "./sshkey/id_rsa" -P ""
fi >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not generate SSH key pair for scponly user (Error Code: $ERROR)."
fi

echo "[*] Copying sshkeys to relevant folders." | tee -a $LOGFILE
cp ./sshkey/id_rsa.pub ./c2servers/ssh/id_rsa.pub >> $LOGFILE 2>&1
cp ./sshkey/id_rsa* ./elkserver/mounts/redelk-ssh/ >> $LOGFILE 2>&1

echo "[*] Copying VERSION file to subfolders." | tee -a $LOGFILE
if [ -f "./VERSION" ]; then
    cp ./VERSION c2servers/
    cp ./VERSION elkserver/
    cp ./VERSION redirs/
fi >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not copy VERSION file to subfolders (Error Code: $ERROR)."
fi

echo "[*] Creating TGZ packages for easy distribution" | tee -a $LOGFILE
if [ ! -f "./elkserver.tgz" ]; then
    tar zcvf elkserver.tgz elkserver/
fi >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not TGZ for elkserver directory (Error Code: $ERROR)."
fi
if [ ! -f "./redirs.tgz" ]; then
    tar zcvf redirs.tgz redirs/
fi >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not TGZ for redirs directory (Error Code: $ERROR)."
fi
if [ ! -f "./c2servers.tgz" ]; then
    tar zcvf c2servers.tgz c2servers/
fi >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not TGZ for c2servers directory (Error Code: $ERROR)."
fi

grep -i error $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -eq 0 ]; then
    echo "[X] There were errors while running this installer. Manually check the log file $LOGFILE. Exiting now."
    exit
fi

echo ""
echo ""
echo "[*] Done with initial setup." | tee -a $LOGFILE
echo "[*] Copy the redirs.tgz, c2servers.tgz and elkserver.tgz packages to every redirector, c2servers or ELK-server. Then run the relevant setup script there locally." | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
