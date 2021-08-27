#!/bin/sh
#
# Part of RedELK
# Script to copy downloaded files from the CobaltStrike teamserver's downloads folder to the homedir of the scponly user.
# It also adds "_orginal file name" to the file name, e.g. 9ce6fbfb1 becomes 9ce6fbfb1_testdoc.txt
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="/var/log/redelk/copydownloads.log"

mkdir -p /home/scponly/cobaltstrike/downloads >> $LOGFILE 2>&1

echo "`date` ######## Start downloads copy" >> $LOGFILE 2>&1

for fileid in $(ls /root/cobaltstrike/downloads/ | grep -v '\.'); do
  orifilename=`grep -rn $fileid /root/cobaltstrike/logs/*/downloads.log|awk 'BEGIN {FS="\t"}; {print $6}'`
  if [ ! -f "/home/scponly/cobaltstrike/downloads/${fileid}_${orifilename}" ]; then
    cp /root/cobaltstrike/downloads/${fileid} "/home/scponly/cobaltstrike/downloads/${fileid}_${orifilename}"
    chown scponly:scponly "/home/scponly/cobaltstrike/downloads/${fileid}_${orifilename}"
  fi
done

echo "`date` ######## Done with downloads copy" >> $LOGFILE 2>&1