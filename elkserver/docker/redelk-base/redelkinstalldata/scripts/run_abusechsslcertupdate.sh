#!/bin/sh
#
# Part of RedELK
# Script to update Abuse.ch SSLBL SSL Certificate Blacklist
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="/var/log/redelk/abusesslcert.log"
CONFIGFILE="/etc/redelk/abusesslcert.conf"
TEMPFILE="/tmp/abusesslcert.txt"


curl -s https://sslbl.abuse.ch/blacklist/sslblacklist.csv |awk -F\, '{print $2}' | grep -v SHA1 | grep . > $TEMPFILE
LINECOUNT=`wc -l $TEMPFILE|awk '{print $1}'`
if [ $LINECOUNT -ge 10 ]; then
    echo "# Part of RedELK - list of Abuse.ch SSLBL SSL Certificate Blacklist - AUTO UPDATED, DO NOT MAKE MANUAL CHANGES" > $CONFIGFILE
    cat $TEMPFILE >> $CONFIGFILE
    rm $TEMPFILE
    echo "$LINECOUNT lines added">> $LOGFILE
    printf "`date +'%b %e %R'` Abuse.ch SSLBL SSL Certificate Blacklist update script ran \n" >> $LOGFILE 2>&1
fi