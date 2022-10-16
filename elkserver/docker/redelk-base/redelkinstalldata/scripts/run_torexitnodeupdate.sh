#!/bin/sh
#
# Part of RedELK
# Script to update list of TOR exit node IP addresses
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="/var/log/redelk/torupdate.log"
CONFIGFILE="/etc/redelk/torexitnodes.conf"
TEMPFILE="/tmp/torexitnodes.txt"


curl -s https://check.torproject.org/exit-addresses | awk '/ExitAddress/ {print $2}' > $TEMPFILE
LINECOUNT=`wc -l /tmp/torexitnodes.txt|awk '{print $1}'`
if [ $LINECOUNT -ge 10 ]; then
    echo "# Part of RedELK - list of TOR exit node addresses - AUTO UPDATED, DO NOT MAKE MANUAL CHANGES" > $CONFIGFILE
    cat $TEMPFILE >> $CONFIGFILE
    rm $TEMPFILE
    echo "$LINECOUNT lines added">> $LOGFILE
    printf "`date +'%b %e %R'` TOR update script ran \n" >> $LOGFILE 2>&1
fi
