#!/bin/sh
#
# Part of RedELK
# Script to update Abuse.ch SSLBL Botnet C2 IP Blacklist
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="/var/log/redelk/abusebotnetc2ip.log"
CONFIGFILE="/etc/redelk/abusebotnetc2ip.conf"
TEMPFILE="/tmp/abusebotnetc2ip.txt"


curl -s https://sslbl.abuse.ch/blacklist/sslipblacklist.txt |grep -v '#' > $TEMPFILE
LINECOUNT=`wc -l $TEMPFILE|awk '{print $1}'`
if [ $LINECOUNT -ge 10 ]; then
    echo "# Part of RedELK - list of Abuse.ch SSLBL Botnet C2 IP - AUTO UPDATED, DO NOT MAKE MANUAL CHANGES" > $CONFIGFILE
    sed -e "s/\r//g" $TEMPFILE  >> $CONFIGFILE
    rm $TEMPFILE
    echo "$LINECOUNT lines added">> $LOGFILE
    printf "`date +'%b %e %R'` Abuse.ch SSLBL Botnet C2 IP update script ran \n" >> $LOGFILE 2>&1
fi
