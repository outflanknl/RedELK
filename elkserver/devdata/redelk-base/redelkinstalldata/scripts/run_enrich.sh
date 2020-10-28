#!/bin/sh
#
# Part of RedELK
# Script to start enrichment process of data in elasticsearch 
#
# Author: Outflank B.V. / Marc Smeets
#
# License : BSD3
#
# Version: 0.8
#

LOGFILE="/var/log/redelk/enrich.log"

# Check if there isnt an old process running, we dont want to run this in parallel
pgrep enrich.py > /dev/null
ENRICHRUNNING=$?
if [ $ENRICHRUNNING -eq 1 ]; then
    cd /usr/share/redelk/bin
    /usr/share/redelk/bin/enrich.py >> $LOGFILE 2>&1
    printf "`date +'%b %e %R'` Enrich script ran \n" >> $LOGFILE 2>&1
else
    printf "`date +'%b %e %R'` Enrich did not run, process already running\n" >> $LOGFILE 2>&1
fi