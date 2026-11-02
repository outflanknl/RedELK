#!/bin/sh
#
# Part of RedELK
# Script to start alarm, enrichment and notification processes of data in elasticsearch
#
# Author:
# - Outflank B.V. / Marc Smeets
# - Lorenzo Bernardi (@fastlorenzo)
#

# INIT-LOGFILE is the first log file created
# Keep it for root cause analysis
LOGFILE="/var/log/redelk/daemon.log"
INIT_LOGFILE="/var/log/redelk/init-daemon.log"

# du default size listing is 1024B/1KB
# 2 MB = 2048
MAXLOGSIZE=$((1024 * 50))

# Check if there isn't an old process running, we dont want to run this in parallel
pgrep -f daemon.py >/dev/null
DAEMON_RUNNING=$?
if [ $DAEMON_RUNNING -eq 1 ]; then
    cd /usr/share/redelk/bin

    # Check if file is larger than max log size
    # We want to keep the first log file for troubleshooting
    CURRENTLOGSIZE=$(/usr/bin/du $LOGFILE | /usr/bin/cut -f1)
    if [ $CURRENTLOGSIZE -gt $MAXLOGSIZE ]; then
        if [ ! -f "$INIT-LOGFILE" ]; then
            /usr/bin/mv $LOGFILE $INIT_LOGFILE
        fi

        python3 /usr/share/redelk/bin/daemon.py >$LOGFILE 2>&1
    else
        python3 /usr/share/redelk/bin/daemon.py >>$LOGFILE 2>&1
    fi
    printf "$(date +'%b %e %R') Daemon script ran \n" >>$LOGFILE 2>&1
fi
