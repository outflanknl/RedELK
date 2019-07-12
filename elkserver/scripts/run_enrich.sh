#!/bin/sh
#
# Part of RedELK
# Script to start enrichment process of data in elasticsearch 
#
# Author: Outflank B.V. / Marc Smeets / @mramsmeets
#

LOGFILE="/var/log/redelk/enrich.log"

# Check if there isnt an old process running, we dont want to run this in parallel
pgrep enrich.py > /dev/null
ENRICHRUNNING=$?
if [ $ENRICHRUNNING -eq 1 ]; then 
    /usr/share/redelk/bin/enrich.py >> $LOGFILE 2>&1
    printf "`date +'%b %e %R'` Enrich script ran \n" >> $LOGFILE 2>&1
fi
