#!/bin/sh
#
# Part of RedELK
# Script to start enrichment process of data in elasticsearch
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="/var/log/redelk/alarm.log"

# Check if there isnt an old process running, we dont want to run this in parallel
pgrep alarm.py > /dev/null
ALARMRUNNING=$?
if [ $ALARMRUNNING -eq 1 ]; then
    cd /usr/share/redelk/bin
    /usr/share/redelk/bin/alarm.py >> $LOGFILE 2>&1
    printf "`date +'%b %e %R'` Alarm script ran \n" >> $LOGFILE 2>&1
fi

# ENABLE TO ALARM ONLY ONCE 
cat /tmp/ALARMED_alarm_check1.ips /etc/redelk/iplist_alarmed.conf  | sort -u > /etc/redelk/iplist_alarmed.conf
