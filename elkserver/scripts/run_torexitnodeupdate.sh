#!/bin/sh
#
# Part of RedELK
# Script to update list of TOR exit ndoe IP addresses 
#
# Author: Outflank B.V. / Marc Smeets / @mramsmeets
#

LOGFILE="/var/log/redelk/torupdate.log"
CONFIGFILE="/etc/redelk/torexitnodes.conf"


curl -s https://check.torproject.org/exit-addresses | awk '/ExitAddress/ {print $2}' > /tmp/torexitnodes.txt
TORLINES=`wc -l /tmp/torexitnodes.txt|awk '{print $1}'`
if [ $TORLINES -ge 10 ]; then 
    echo "# Part of RedELK - list of TOR exit node addresses - AUTO UPDATED, DO NOT MAKE MANUAL CHANGES" > $CONFIGFILE
    cat /tmp/torexitnodes.txt >> $CONFIGFILE
    rm /tmp/torexitnodes.txt
    echo $TORLINES >> $LOGFILE
    printf "`date +'%b %e %R'` TOR update script ran \n" >> $LOGFILE 2>&1
fi
