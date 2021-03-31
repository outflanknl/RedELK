#!/bin/sh
#
# Part of RedELK
# Script to start alarm, enrichment and notification processes of data in elasticsearch
#
# Author:
# - Outflank B.V. / Marc Smeets
# - Lorenzo Bernardi (@fastlorenzo)
#

LOGFILE="/var/log/redelk/daemon.log"

# Check if there isn't an old process running, we dont want to run this in parallel
pgrep daemon.py > /dev/null
DAEMON_RUNNING=$?
if [ $DAEMON_RUNNING -eq 1 ]; then
    cd /usr/share/redelk/bin
    /usr/share/redelk/bin/daemon.py >> $LOGFILE 2>&1
    printf "`date +'%b %e %R'` Daemon script ran \n" >> $LOGFILE 2>&1
fi
