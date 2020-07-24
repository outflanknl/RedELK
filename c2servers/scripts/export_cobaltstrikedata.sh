#!/bin/sh
#
# Part of RedELK
# Script to start the exporting of data of Cobalt Strike data. Haevy lifting is done by exportcsdata.py, 
# this shell script only calls the python script and logs its running
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="/var/log/redelk/exportcobaltstrikesdata.log"
CSDIR="/root/cobaltstrike"

echo "`date` ######## Start CS data export" >> $LOGFILE 2>&1

# Export CS credentials
cd $CSDIR/data && python3 /usr/share/redelk/bin/exportcsdata.py --credentials /root/cobaltstrike/data/credentials.bin >> $LOGFILE 2>&1

echo "`date` ######## Done with CS data export" >> $LOGFILE 2>&1
