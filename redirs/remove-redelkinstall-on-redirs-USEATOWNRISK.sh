#!/bin/sh
#
# Part of RedELK
# Script to remove RedELK on redirectors
#
# Author: Outflank B.V. / Marc Smeets
#


echo ""
echo ""
echo "        !! USE AT OWN RISK !!         "
echo ""
echo " This script will rudimentarily remove"
echo " all kinds of things on your system."
echo ""
echo " Check the code before running. "
echo ""
echo " 5 sec to abort"
echo ""
sleep 5

echo "[-] Stopping ELK services"
service filebeat stop

echo "[-] Nuking crontab for redelk user actions"
rm -rf /cp /etc/cron.d/redelk*

echo "[-] Removing apt-transport-https"
apt-get remove -y apt-transport-https

echo "[-] Removing FileBeat"
apt-get purge -y filebeat

echo "[-] Removing FileBeat directories"
rm -rf /etc/filebeat
rm -rf /usr/share/filebeat
rm -rf /var/log/filebeat*
rm -rf /var/lib/filebeat

echo "[-] Removing other not used packages"
apt -y autoremove

echo "[-] Removing apt elastic file"
rm -rf /etc/apt/sources.list.d/elastic-*.x.list

echo "[*] Done. You can manually remove this directory as well if you like."
echo ""
