#!/bin/sh
#
# Part of RedELK
# Script to update list of known rogue domain names
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="/var/log/redelk/roguedomains.log"
CONFIGFILE="/etc/redelk/roguedomains.conf"
INTERMEDIATEFILE="/tmp/roguedomains.txt"

## DNS-BH malwaredomains.com
TEMPFILE="/tmp/roguedomains_malwaredomains.com.txt"
curl -s http://mirror1.malwaredomains.com/files/domains.txt | grep -v '#'|awk '{print $1}'|grep -P '(?=^.{1,254}$)(^(?>(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)' > $TEMPFILE
LINECOUNT=`wc -l $TEMPFILE|awk '{print $1}'`
if [ $LINECOUNT -ge 10 ]; then
    cat $TEMPFILE |awk '{print $1 "     # malwaredomains.com"}' >> $INTERMEDIATEFILE
    echo "$LINECOUNT lines added from malwaredomains.com">> $LOGFILE
fi

## abuse.ch URLhaus Plain-Text URL List (URLs only)
TEMPFILE="/tmp/roguedomains_urlhaus.abuse.ch.txt"
curl -s https://urlhaus.abuse.ch/downloads/text/ | grep -v '#'|awk '{print $1}'|grep '^http' | sed -e "s/\r//g" > $TEMPFILE
LINECOUNT=`wc -l $TEMPFILE|awk '{print $1}'`
if [ $LINECOUNT -ge 10 ]; then
    cat $TEMPFILE |awk '{print $1 "     # urlhaus.abuse.ch"}' >> $INTERMEDIATEFILE
    echo "$LINECOUNT lines added from urlhaus.abuse.ch">> $LOGFILE
fi

## host list form malwaredomainlist.com
TEMPFILE="/tmp/roguedomains_malwaredomainlist.com.txt"
curl -s http://www.malwaredomainlist.com/hostslist/hosts.txt | grep -v '#'|awk '{print $2}'|sed -e "s/\r//g"|grep -P '(?=^.{1,254}$)(^(?>(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$)' > $TEMPFILE
LINECOUNT=`wc -l $TEMPFILE|awk '{print $1}'`
if [ $LINECOUNT -ge 10 ]; then
    cat $TEMPFILE |awk '{print $1 "     # malwaredomainlist.com"}' >> $INTERMEDIATEFILE
    echo "$LINECOUNT lines added from malwaredomainlist.com">> $LOGFILE
fi

# Put it all together
LINECOUNT=`wc -l $INTERMEDIATEFILE|awk '{print $1}'`
if [ $LINECOUNT -ge 10 ]; then
    echo "# Part of RedELK - Rogue domain names form multiple sources - AUTO UPDATED, DO NOT MAKE MANUAL CHANGES" > $CONFIGFILE
    cat $INTERMEDIATEFILE >> $CONFIGFILE
    rm $INTERMEDIATEFILE
    echo "$LINECOUNT lines added">> $LOGFILE
    printf "`date +'%b %e %R'` rogue domain name update script ran \n" >> $LOGFILE 2>&1
fi

printf "`date +'%b %e %R'` Now running chameleon.py for checking classifications of our domains\n" >> $LOGFILE 2>&1

# Now run chameleon.py to check if our domains 
cd /usr/share/redelk/bin/Chameleon/
python3 chameleon.py --redelk --proxy a >> $LOGFILE 2>&1
