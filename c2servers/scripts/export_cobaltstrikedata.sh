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

# Copy old listeners file for comparison (if exists)
if [ -f "$CSDIR/data/export_listeners.tsv" ]; then
  cp $CSDIR/data/export_listeners.tsv $CSDIR/data/export_listeners.old.tsv
fi

# Export CS credentials and listeners
cd $CSDIR/data && python3 /usr/share/redelk/bin/exportcsdata.py --credentials $CSDIR/data/credentials.bin --listeners $CSDIR/data/listeners.bin >> $LOGFILE 2>&1

# Output listener changes in log file
if [ -f "$CSDIR/data/export_listeners.old.tsv" ]; then
  diff $CSDIR/data/export_listeners.old.tsv $CSDIR/data/export_listeners.tsv --changed-group-format='%>' --unchanged-group-format='' >> $CSDIR/data/export_listeners.log
else
  cat $CSDIR/data/export_listeners.tsv >> $CSDIR/data/export_listeners.log
fi

echo "`date` ######## Done with CS data export" >> $LOGFILE 2>&1
