#!/bin/sh
#
# Part of RedELK
# Script to install RedELK on redirector
#
# Author: Outflank B.V. / Marc Smeets 
#

LOGFILE="redelk-install.log"
INSTALLER="RedELK redirector installer"
TIMEZONE="Europe/Amsterdam"
ELKVERSION="6.4.1"

echoerror() {
    printf "`date +'%b %e %R'` $INSTALLER - ${RC} * ERROR ${EC}: $@\n" >> $LOGFILE 2>&1
}

preinstallcheck() {
   echo "Starting pre installation checks"
    if [ -n "$(dpkg -s filebeat 2>/dev/null| grep Status)" ]; then
        INSTALLEDVERSION=`dpkg -s filebeat |grep Version|awk '{print $2}'` >> $LOGFILE 2>&1
        if [ "$INSTALLEDVERSION" != "$ELKVERSION" ]; then
            echo "[X] Filebeat: installed version $INSTALLEDVERSION, required version $ELKVERSION. Please fix manually."
            echoerror "Filebeat version mismatch. Please fix manually."
            exit 1
        else
            echo "[!] Filebeat: required version is installed ($INSTALLEDVERSION). Should be good. Stopping service now before continuing installation."
            service filebeat stop
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echoerror "Could not stop filebeat (Error Code: $ERROR)."
            fi
        fi
    fi
}

echo "This script will install and configure necessary components for RedELK on redirectors"
printf "`date +'%b %e %R'` $INSTALLER - Starting installer\n" > $LOGFILE 2>&1

if ! [ $# -eq 3 ] ; then
    echo "[X] ERROR Incorrect amount of parameters"
    echo "[X] require 1st parameter: identifier of this machine to set in filebeat config."
    echo "[X] require 2nd parameter: attackscenario name."
    echo "[X] require 3rd parameter: IP/DNS:port where to ship logs to."
    echoerror "Incorrect amount of parameters"
    exit 1
fi

preinstallcheck

echo "Setting timezone"
timedatectl set-timezone $TIMEZONE >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not set timezone (Error Code: $ERROR)."
fi

echo "Restarting rsyslog deamon for new timezone to take effect"
service rsyslog restart >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not restart rsyslog deamon (Error Code: $ERROR)."
fi

echo "Adding GPG key of Elastic"
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not add GPG key (Error Code: $ERROR)."
fi

echo "Installing apt-transport-https"
apt-get install -y apt-transport-https >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install apt-transport-https (Error Code: $ERROR)."
fi

echo "Adding Elastic APT repository"
if [ ! -f  /etc/apt/sources.list.d/elastic-6.x.list ]; then
    echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-6.x.list >> $LOGFILE 2>&1
fi
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not add APT repository (Error Code: $ERROR)."
fi

echo "Updating APT"
apt-get update  >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not update APT (Error Code: $ERROR)."
fi

echo "Installing filebeat ..."
apt-get install -y filebeat=$ELKVERSION >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install filebeat (Error Code: $ERROR)."
fi

echo "Setting filebat to auto start after reboot"
update-rc.d filebeat defaults 95 10 >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not change auto boot settings (Error Code: $ERROR)."
fi

echo "Making backup of original filebeat config"
mv /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.ori >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not make backup (Error Code: $ERROR)."
fi

echo "Copying new config file"
cp ./filebeat/filebeat.yml /etc/filebeat/ >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy filebeat config (Error Code: $ERROR)."
fi

echo "Copying ca file ..."
cp ./filebeat/redelkCA.crt /etc/filebeat/ >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy ca file (Error Code: $ERROR)."
fi

echo "Altering hostname field in filebeat config"
sed -i s/'@@HOSTNAME@@'/$1/g /etc/filebeat/filebeat.yml  >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not change hostname field in filebeat config (Error Code: $ERROR)."
fi

echo "Altering attackscenario field in filebeat config "
sed -i s/'@@ATTACKSCENARIO@@'/$2/g /etc/filebeat/filebeat.yml >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not change attackscenario field in filebeat config (Error Code: $ERROR)."
fi

echo "Altering log destination field in filebeat config "
sed -i s/'@@HOSTANDPORT@@'/$3/g /etc/filebeat/filebeat.yml >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not change log destination field in filebeat config (Error Code: $ERROR)."
fi

echo "Altering logrotate settings for HAProxy - rotate weekly instead of daily"
sed -i s/'daily'/'weekly'/g /etc/logrotate.d/haproxy >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not change logrotate settings for HAProxy (Error Code: $ERROR). "
fi

echo "Starting filebeat"
service filebeat start >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not start filebeat (Error Code: $ERROR)."
fi

grep -i error $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -eq 0 ]; then
    echo "[X] There were errors while running this installer. Manually check the log file $LOGFILE. Exiting now."
    exit
fi

echo ""
echo ""
echo "Done with setup of RedELK on redirector."
echo ""
