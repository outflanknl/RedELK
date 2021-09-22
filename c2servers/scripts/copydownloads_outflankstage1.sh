#!/bin/sh
#
# Part of RedELK
# Script to copy downloaded files from the Outflank Stage teamserver's downloads folder to the homedir of the scponly user.
# It also adds "_orginal file name" to the file name, e.g. 9ce6fbfb1 becomes 9ce6fbfb1_testdoc.txt
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="/var/log/redelk/copydownloads.log"

mkdir -p /home/scponly/stage1/downloads >> $LOGFILE 2>&1

echo "`date` ######## Start downloads copy" >> $LOGFILE 2>&1

for fileid in $(ls /root/stage1c2server/shared/downloads/ | grep -v '\.'); do
  orifilename=`grep -rn $fileid /root/stage1c2server/shared/logs/stage1/*|awk 'BEGIN {FS="taskResponse: Downloaded"}; {print $2}'|awk -F"] " '{print $2}'|tr -d ";"|awk '{$1=$1};1'`
  if [ ! -f "/home/scponly/stage1/downloads/${fileid}_${orifilename}" ]; then
    cp /root/stage1c2server/shared/downloads/${fileid} "/home/scponly/stage1/downloads/${fileid}_${orifilename}"
    chown scponly:scponly "/home/scponly/stage1/downloads/${fileid}_${orifilename}"
  fi
done

echo "`date` ######## Done with downloads copy" >> $LOGFILE 2>&1
