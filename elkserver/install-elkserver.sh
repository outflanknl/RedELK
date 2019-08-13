#!/bin/sh
#
# Part of RedELK
# Script to install RedELK on ELK server
#
# Author: Outflank B.V. / Marc Smeets 
#


LOGFILE="redelk-install.log"
INSTALLER="RedELK elkserver installer"
TIMEZONE="Europe/Amsterdam"
CWD=`pwd`
ELKVERSION="6.8.2"

#set locale for current session and default locale
export LC_ALL="en_US.UTF-8"
echo -e 'LANG=en_US.UTF-8\nLC_ALL=en_US.UTF-8' > /etc/default/locale
locale-gen

echoerror() {
    printf "`date +'%b %e %R'` $INSTALLER - ${RC} * ERROR ${EC}: $@\n" >> $LOGFILE 2>&1
}

preinstallcheck() {
    echo "Starting pre installation checks"
    SHOULDEXIT=false
    # checking logstash version
    if [ -n "$(dpkg -s logstash 2>/dev/null| grep Status)" ]; then
        INSTALLEDVERSION=`dpkg -s logstash |grep Version|awk '{print $2}'|sed 's/^1\://g'|sed 's/\-1$//g'` >> $LOGFILE 2>&1
        if [ "$INSTALLEDVERSION" != "$ELKVERSION" ]; then
            echo "[X] Logstash: installed version $INSTALLEDVERSION, required version $ELKVERSION. Please fix manually."
            echoerror "Logstash version mismatch. Please fix manually."
            SHOULDEXIT=true
        else
            echo "[!] Logstash: required version is installed ($INSTALLEDVERSION). Should be good. Stopping now before continuing installation."
            service logstash stop
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echoerror "Could not stop logstash (Error Code: $ERROR)."
            fi
        fi
    fi
    # checking elasticsearch version
    if [ -n "$(dpkg -s elasticsearch 2>/dev/null| grep Status)" ]; then
        INSTALLEDVERSION=`dpkg -s elasticsearch |grep Version|awk '{print $2}'` >> $LOGFILE 2>&1
        if [ "$INSTALLEDVERSION" != "$ELKVERSION" ]; then
            echo "[X] Elasticsearch: installed version $INSTALLEDVERSION, required version $ELKVERSION. Please fix manually."
            echoerror "Elasticsearch version mismatch. Please fix manually."
            SHOULDEXIT=true
        else
            echo "[!] Elasticsearch: required version is installed ($INSTALLEDVERSION). Should be good. Stopping now before continuing installation."
            service elasticsearch stop
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echoerror "Could not stop elasticsearch (Error Code: $ERROR)."
            fi
        fi
   fi
   if [ "$SHOULDEXIT" = true ]; then
       exit 1
   fi
}

echo "This script will install and configure necessary components for RedELK on ELK server"
printf "`date +'%b %e %R'` $INSTALLER - Starting installer\n" > $LOGFILE 2>&1

preinstallcheck

echo "Setting timezone"
timedatectl set-timezone $TIMEZONE  >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not set timezone (Error Code: $ERROR)."
fi

echo "Restarting rsyslog deamon for new timezone to take effect"
service rsyslog restart >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not restart rsyslog deamon (Error Code: $ERROR)."
fi

echo "Adding GPG key of Elastic"
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not add GPG key (Error Code: $ERROR)."
fi

echo "Installing apt-transport-https"
apt-get install -y apt-transport-https >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install apt-transport-https (Error Code: $ERROR)."
fi

echo "Adding Elastic APT repository"
if [ ! -f  /etc/apt/sources.list.d/elastic-6.x.list ]; then
    echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-6.x.list >> $LOGFILE 2>&1
fi
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not add APT repository (Error Code: $ERROR)."
fi

echo "Updating APT"
apt-get update  >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not update APT (Error Code: $ERROR)."
fi

echo "Installing openjdk-11-jre-headless"
apt-get install -y openjdk-11-jre-headless >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install openjdk-11-jre-headless (Error Code: $ERROR)."
fi

echo "Installing logstash"
apt-get install -y logstash=1:$ELKVERSION-1 > $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install logstash (Error Code: $ERROR)."
fi

echo "Copying new logstach config files"
cp ./logstash/conf.d/* /etc/logstash/conf.d/ >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy logstash config (Error Code: $ERROR)."
fi

echo "Copying Logstash certificate files"
cp -r ./logstash/certs /etc/logstash/ >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy Logstash certificate files (Error Code: $ERROR)."
fi

echo "Setting ownership of Logstash certificate files"
chown logstash /etc/logstash/certs/* >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Error with setting ownership of Logstach cert files (Error Code: $ERROR)."
fi

echo "Copying logstash Ruby scripts"
cp -r ./logstash/ruby-scripts /etc/logstash/ >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy logstash Ruby scripts (Error Code: $ERROR)."
fi

echo "Setting logstash to auto start after reboot"
systemctl enable logstash >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Coul not change auto boot settings (Error Code: $ERROR)."
fi

echo "Downloading GeoIP database files"
mkdir -p /usr/share/logstash/GeoLite2-dbs >> $LOGFILE 2>&1 && cd /tmp && curl http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz -O >> $LOGFILE 2>&1 && curl http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz -O >> $LOGFILE 2>&1 && tar zxvf /tmp/GeoLite2-ASN.tar.gz >> $LOGFILE 2>&1 && tar zxvf /tmp/GeoLite2-City.tar.gz >> $LOGFILE 2>&1 && mv /tmp/Geo*/*.mmdb /usr/share/logstash/GeoLite2-dbs >> $LOGFILE 2>&1 && chown -R logstash:logstash /usr/share/logstash/GeoLite2-dbs >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not download geoIP database files (Error Code: $ERROR)."
fi
cd $CWD

echo "Installing elasticsearch"
apt-get install -y elasticsearch=$ELKVERSION > $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install elasticsearch (Error Code: $ERROR)."
fi

echo "Setting elasticsearch to auto start after reboot"
systemctl enable elasticsearch >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Coul not change auto boot settings (Error Code: $ERROR)."
fi

echo "Installing Kibana"
apt-get install -y kibana=$ELKVERSION > $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Kibana (Error Code: $ERROR)."
fi

echo "Setting Kibana to auto start after reboot"
systemctl enable kibana >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Coul not change auto boot settings (Error Code: $ERROR)."
fi

echo "Installing nginx"
apt-get install -y nginx > $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install nginx (Error Code: $ERROR)."
fi

echo "Setting nginx to auto start after reboot"
systemctl enable nginx >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Coul not change auto boot settings (Error Code: $ERROR)."
fi

echo "Copying nginx config files"
cp ./nginx/htpasswd.users /etc/nginx/ && mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default_backup && cp ./nginx/sites-available/* /etc/nginx/sites-available >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy nginx config (Error Code: $ERROR)."
fi

echo "Creating www dirs and setting permissions"
mkdir -p /var/www/html/cslogs && chown -R www-data:www-data /var/www/html/cslogs && chmod 775 /var/www/html/cslogs >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not create WWW dirs and set permissions (Error Code: $ERROR)."
fi

echo "Starting elasticsearch"
systemctl start elasticsearch >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not start Elasticsearch (Error Code: $ERROR)."
fi
sleep 10

echo "Starting Kibana"
systemctl start kibana >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not start Kibana (Error Code: $ERROR)."
fi

echo "Restarting nginx"
service nginx restart >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not start nginx (Error Code: $ERROR)."
fi

echo "Creating redelk user"
grep redelk /etc/passwd > /dev/null
EXIT=$?
if [ $EXIT -ne 0  ]; then
    useradd -m -p $(openssl passwd -1 `head /dev/urandom | tr -dc A-Za-z0-9 | head -c20`) redelk && usermod -a -G www-data redelk
fi  >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not create redelk user (Error Code: $ERROR)."
fi

echo "Setting up ssh keys for redelk user"
mkdir -p /home/redelk/.ssh && cp ./ssh/id* /home/redelk/.ssh/ && chown -R redelk:redelk /home/redelk/.ssh && chmod 700 /home/redelk/.ssh && chmod 600 /home/redelk/.ssh/id* >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not setup ssh keys for redelk user (Error Code: $ERROR)."
fi

echo "Copying RedELK background running scripts (remote logs, thumbnails, enrichment, alarms, etc)"
mkdir -p /usr/share/redelk/bin && cp -r ./scripts/* /usr/share/redelk/bin/ && chmod -R 775 /usr/share/redelk/bin/*>> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy background running scripts (Error Code: $ERROR)."
fi

echo "Installing script dependencies"
apt-get install -y python3-pil python3-pip >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install script dependencies (Error Code: $ERROR)."
fi

echo "Installing python elasticsearch library"
pip3 install elasticsearch >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install python elasticsearch library (Error Code: $ERROR)."
fi

echo "Creating RedELK config directory"
mkdir -p /etc/redelk >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not create RedELK config directory (Error Code: $ERROR)."
fi

echo "Copying RedELK config files"
cp -r ./etc/redelk/* /etc/redelk/ && chown redelk /etc/redelk/* >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy RedELK config files (Error Code: $ERROR)."
fi

echo "Checking if Kibana is up before continuing"
sleep 30
COUNTER=0
RECHECK=true
while [ "$RECHECK" = true ]; do
    touch /tmp/kibanaupcheck.txt
    curl -XGET 'http://localhost:5601/status' -I -o /tmp/kibanaupcheck.txt >> $LOGFILE 2>&1
    sleep 3
    if [ -n "$(grep '200 OK' /tmp/kibanaupcheck.txt)" ]; then
        RECHECK=false
    fi
    echo "Kibana not up yet, sleeping another few seconds."
    sleep 3
    COUNTER=$((COUNTER+1))
    if [ $COUNTER -eq "20" ]; then
        echoerror "Kibana still not up, waited for way too long. Continuing and hoping for the best."
        RECHECK=false
    fi
done
sleep 10 # just to give Kibana some extra time after systemd says Kibana is active.

echo "Installing Kibana template"
curl -X POST "http://localhost:5601/api/saved_objects/_bulk_create" -H 'kbn-xsrf: true' -H "Content-Type: application/json" -d @./templates/redelk_kibana_all.json >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Kibana template (Error Code: $ERROR)."
fi

# setting default index to rtops
echo "Setting the Kibana default index"
curl -X POST "http://localhost:5601/api/kibana/settings/defaultIndex" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d"{\"value\":\"rtops\"}" >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not set the default index for Kibana (Error Code: $ERROR)."
fi

echo "Installing GeoIP index template adjustment"
curl -XPUT -H 'Content-Type: application/json' http://localhost:9200/_template/redirhaproxy- -d@./templates/elasticsearch-template-geoip-es6x.json >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install GeoIP index template adjust (Error Code: $ERROR)."
fi

# GeoIP is built-in since version 6.7 - no longer required to install
#echo "Installing GeoIP elasticsearch plugin"
#echo Y | /usr/share/elasticsearch/bin/elasticsearch-plugin -s install ingest-geoip >> $LOGFILE 2>&1
#ERROR=$?
#if [ $ERROR -ne 0 ]; then
#    echoerror "Could not install GeoIP elasticsearch plugin (Error Code: $ERROR)."
#fi

echo "Creating crontab for redelk user actions"
cp ./cron.d/redelk /etc/cron.d/redelk >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not create crontab for redelk user actions (Error Code: $ERROR)."
fi

echo "Creating RedELK log directory"
mkdir -p /var/log/redelk >> $LOGFILE 2>&1 && chown -R redelk:redelk /var/log/redelk >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not create RedELK log directory (Error Code: $ERROR)."
fi

echo "Starting logstash"
systemctl start logstash >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not start logstash (Error Code: $ERROR)."
fi

echo "Inserting the superawesomesauce RedELK logo into Kibana"
cp /usr/share/kibana/optimize/bundles/commons.style.css /usr/share/kibana/optimize/bundles/commons.style.css.ori && cp ./kibana/* /usr/share/kibana/optimize/bundles/ >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not adjust Kibana logo (Error Code: $ERROR)."
fi

grep -i error $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -eq 0 ]; then
    echo "[X] There were errors while running this installer. Manually check the log file $LOGFILE. Exiting now."
    exit
fi

echo ""
echo ""
echo "Done with base setup of RedELK on ELK server"
echo "You can now login to RedELK Kibana on this machine using redelk:redelk as credentials."
echo ""
echo "!!! WARNING - YOU ARE NOT DONE YET !!!"
echo ""
echo "You are *REQUIRED* to:"
echo " - adjust the /etc/cron.d/redelk file to include your teamservers"
echo " - adjust all config files in /etc/redelk/ to include your specifics like VT API, email server details, etc"
echo ""
echo "You are *ADVISED* to:"
echo " - reset default nginx credentials by adjusting the file /etc/nginx/htpasswd.users. You can use the htpasswd tool from apache2-utils package"
echo ""
echo ""
