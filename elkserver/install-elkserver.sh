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
ELKVERSION="7.8.0"

echo ""
echo "This script will install and configure necessary components for RedELK on ELK server"
printf "`date +'%b %e %R'` $INSTALLER - Starting installer\n" > $LOGFILE 2>&1
echo ""

if [ ${#} -ne 0 ] && [ ${1} = "limited" ]; then
    echo "Parameter 'limited' found. Going for the limited RedELK experience."
    echo ""
    echo "5 Seconds to abort"
    echo ""
    sleep 5
    WHATTOINSTALL=limited
else
    echo "No 'limited' parameter found. Going for the full RedELK installation including: "
    echo " - RedELK"
    echo " - Jupyter notebooks"
    echo " - BloodHound / Neo4j"
    echo ""
    echo "5 Seconds to abort"
    echo ""
    sleep 5
    WHATTOINSTALL=full
fi

echoerror() {
    printf "`date +'%b %e %R'` $INSTALLER - ${RC} * ERROR ${EC}: $@\n" >> $LOGFILE 2>&1
}

preinstallcheck() {
    echo "Starting pre installation checks"

    SHOULDEXIT=false

    # Checking if OS is Debian / APT based
    if [ ! -f  /etc/debian_version ]; then
        echo "[X] This system does not seem to be Debian/APT-based. RedELK installer only supports Debian/APT based systems."
        echoerror "System is not Debian/APT based. Not supported. Quitting."
        SHOULDEXIT=true
    fi

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

    # checking system memory and setting variables
    AVAILABLE_MEMORY=$(awk '/MemAvailable/{printf "%.f", $2/1024}' /proc/meminfo)

    # check for full or limited install
    if [ ${WHATTOINSTALL} = "limited" ]; then
        if [ ${AVAILABLE_MEMORY} -le 3999 ]; then
            echo "less than recommended 8GB memory found - yolo continuing"
            ES_MEMORY=1g
        elif [ ${AVAILABLE_MEMORY} -ge 4000 -a ${AVAILABLE_MEMORY} -le 7999 ]; then
            echo "less than recommended 8GB memory found - yolo continuing"
            ES_MEMORY=2g
        elif [ ${AVAILABLE_MEMORY} -ge 8000 ]; then
            echo "8GB or more memory found"
            ES_MEMORY=4g
        fi
    else # going for full install means in check in determine how much memory NEO4J and ES get
        if [ ${AVAILABLE_MEMORY} -le 7999 ]; then
            echo "[X] Not enough memory for full install (less than 8GB). Quitting."
            SHOULDEXIT=true
        elif [ ${AVAILABLE_MEMORY} -ge 8000 ] &&  [ ${AVAILABLE_MEMORY} -le 8999 ]; then
            echo "8-9GB memory found"
            ES_MEMORY=1g
            NEO4J_MEMORY=2G
        elif [ ${AVAILABLE_MEMORY} -ge 9000 ] && [ ${AVAILABLE_MEMORY} -le 9999 ]; then
            echo "9-10GB memory found"
            ES_MEMORY=1g
            NEO4J_MEMORY=3G
        elif [ ${AVAILABLE_MEMORY} -ge 10000 ] && [ ${AVAILABLE_MEMORY} -le 10999 ]; then
            echo "10-11GB memory found"
            ES_MEMORY=2g
            NEO4J_MEMORY=3G
        elif [ ${AVAILABLE_MEMORY} -ge 11000 ] && [ ${AVAILABLE_MEMORY} -le 11999 ]; then
            echo "11-12GB memory found"
            ES_MEMORY=2g
            NEO4J_MEMORY=4G
        elif [ ${AVAILABLE_MEMORY} -ge 12000 ] && [ ${AVAILABLE_MEMORY} -le 12999 ]; then
            echo "12-13GB memory found"
            ES_MEMORY=3g
            NEO4J_MEMORY=4G
        elif [ ${AVAILABLE_MEMORY} -ge 13000 ] && [ ${AVAILABLE_MEMORY} -le 13999 ]; then
            echo "13-14GB memory found"
            ES_MEMORY=3g
            NEO4J_MEMORY=4500M
        elif [ ${AVAILABLE_MEMORY} -ge 14000 ] && [ ${AVAILABLE_MEMORY} -le 14999 ]; then
            echo "14-15GB memory found"
            ES_MEMORY=3g
            NEO4J_MEMORY=5G
        elif [ ${AVAILABLE_MEMORY} -ge 15000 ] && [ ${AVAILABLE_MEMORY} -le 15999 ]; then
            echo "15-16GB memory found"
            ES_MEMORY=4g
            NEO4J_MEMORY=5G
        elif [ ${AVAILABLE_MEMORY} -ge 16000 ]; then
            echo "16GB or more memory found"
            ES_MEMORY=5g
            NEO4J_MEMORY=5G
        fi
    fi

    if [ "$SHOULDEXIT" = true ]; then
        exit 1
    fi
}


preinstallcheck
#set locale for current session and default locale
echo "Setting locale"
export LC_ALL="en_US.UTF-8"
printf 'LANG=en_US.UTF-8\nLC_ALL=en_US.UTF-8\n' > /etc/default/locale >> $LOGFILE 2>&1
locale-gen >> $LOGFILE 2>&1

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
if [ ! -f  /etc/apt/sources.list.d/elastic-7.x.list ]; then
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list >> $LOGFILE 2>&1
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
apt-get install -y logstash=1:$ELKVERSION-1 >> $LOGFILE 2>&1
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

echo "Copying GeoIP database files"
mkdir -p /usr/share/logstash/GeoLite2-dbs >> $LOGFILE 2>&1 && cp logstash/*.mmdb /usr/share/logstash/GeoLite2-dbs >> $LOGFILE 2>&1 && chown -R logstash:logstash /usr/share/logstash/GeoLite2-dbs >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy geoIP database files (Error Code: $ERROR)."
fi
cd $CWD

echo "Installing elasticsearch"
apt-get install -y elasticsearch=$ELKVERSION >> $LOGFILE 2>&1
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

echo "Adjusting memory settings for ES"
sed -E -i.bak "s/Xms1g/Xms${ES_MEMORY}/g" /etc/elasticsearch/jvm.options && sed -E -i.bak2 "s/Xmx1g/Xmx${ES_MEMORY}/g" /etc/elasticsearch/jvm.options  && sed -E -i.bak "s/#bootstrap.memory_lock: true/bootstrap.memory_lock: true/g" /etc/elasticsearch/elasticsearch.yml >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Coul not adjust ES memory settings (Error Code: $ERROR)."
fi

echo "Installing Kibana"
apt-get install -y kibana=$ELKVERSION >> $LOGFILE 2>&1
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
apt-get install -y nginx >> $LOGFILE 2>&1
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
cp ./nginx/htpasswd.users /etc/nginx/ && cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default_backup && cp ./nginx/sites-available/* /etc/nginx/sites-available && ln -s /etc/nginx/sites-available/jupyter /etc/nginx/sites-enabled/jupyter >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy nginx config (Error Code: $ERROR)."
fi

echo "Creating www dirs and setting permissions"
mkdir -p /var/www/html/c2logs && chown -R www-data:www-data /var/www/html/c2logs && chmod 775 /var/www/html/c2logs >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not create WWW dirs and set permissions (Error Code: $ERROR)."
fi

echo "Copying attack-navigator files"
cp -r ./attack-navigator /var/www/html/ && chown -R www-data:www-data /var/www/html/attack-navigator && chmod u+rwX,g+rwX,o-rwx /var/www/html/attack-navigator >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not copy attack-navigator files (Error Code: $ERROR)."
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
mkdir -p /usr/share/redelk/bin && cp -r ./scripts/* /usr/share/redelk/bin/ && chmod -R 775 /usr/share/redelk/bin/* >> $LOGFILE 2>&1
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

echo "Installing Kibana index patterns"
for i in ./templates/redelk_kibana_index-pattern*.ndjson; do
    curl -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" -H 'kbn-xsrf: true' -F file=@$i
    sleep 1
done >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Kibana index patterns (Error Code: $ERROR)."
fi

echo "Installing Kibana searches"
curl -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" -H 'kbn-xsrf: true' -F file=@./templates/redelk_kibana_search.ndjson >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Kibana searches (Error Code: $ERROR)."
fi
sleep 1

echo "Installing Kibana visualizations"
curl -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" -H 'kbn-xsrf: true' -F file=@./templates/redelk_kibana_visualization.ndjson >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Kibana visualizations (Error Code: $ERROR)."
fi
sleep 1

echo "Installing Kibana dashboards"
curl -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" -H 'kbn-xsrf: true' -F file=@./templates/redelk_kibana_dashboard.ndjson >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Kibana dashboards (Error Code: $ERROR)."
fi
sleep 1

# Default index is now set as part of Kibana advanced settings, below
#echo "Setting the Kibana default index"
#curl -X POST "http://localhost:5601/api/kibana/settings/defaultIndex" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d"{\"value\":\"redirtraffic\"}" >> $LOGFILE 2>&1
#ERROR=$?
#if [ $ERROR -ne 0 ]; then
#    echoerror "Could not set the default index for Kibana (Error Code: $ERROR)."
#fi

echo "Installing Kibana advanced settings"
curl -X POST "http://localhost:5601/api/kibana/settings" -H 'kbn-xsrf: true' -F file=@./templates/redelk_kibana_advanced_settings.ndjson >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Kibana advanced settings (Error Code: $ERROR)."
fi
sleep 1

echo "Installing Kibana SIEM detection rules (for MITRE ATT&CK mapping)"
curl -X POST "http://localhost:5601/api/detection_engine/rules/_import?overwrite=true" -H 'kbn-xsrf: true' -F file=@./templates/redelk_siem_detection_rules.ndjson >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Kibana SIEM detection rules (Error Code: $ERROR)."
fi
sleep 1

echo "Installing Elasticsearch ILM policy"
curl -X PUT "http://localhost:9200/_ilm/policy/redelk" -H "Content-Type: application/json" -d @./templates/redelk_elasticsearch_ilm.json >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Elasticsearch ILM policy (Error Code: $ERROR)."
fi

echo "Installing Elasticsearch index templates"
for i in implantsdb rtops redirtraffic; do curl -X POST "http://localhost:9200/_template/$i" -H "Content-Type: application/json" -d @./templates/redelk_elasticsearch_template_$i.json; done >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not install Elasticsearch index templates (Error Code: $ERROR)."
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
curl 'http://localhost:5601/api/spaces/space/default?overwrite=true' -H 'kbn-xsrf: true' -X PUT -H 'Content-Type: application/json' -d @./kibana/redelklogo.json >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not adjust Kibana logo (Error Code: $ERROR)."
fi

if [ ${WHATTOINSTALL} = "full" ]; then
    echo "Installing Docker.io"
    apt-get install -y docker.io >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install Docker.io (Error Code: $ERROR)."
    fi

    echo "Creating Docker bridged network"
    # checking of network is already there
    if [ ! "docker network ls|grep dockernetredelk" ]; then docker network create -d bridge --subnet 192.168.254.0/24 --gateway 192.168.254.1 dockernetredelk >> $LOGFILE 2>&1 ; fi
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create Docker bridged network (Error Code: $ERROR)."
    fi

    echo "Creating Jupyter Notebooks working dir and copying notebooks"
    mkdir /usr/share/redelk/jupyter && cp ./jupyter/* /usr/share/redelk/jupyter/ && chown -R redelk:redelk /usr/share/redelk/jupyter >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create Jupyter working dir or copy notebooks (Error Code: $ERROR)."
    fi

    echo "Installing Jupyter Notebooks docker image"
    docker pull --quiet jupyter/scipy-notebook >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install Jupyter docker image (Error Code: $ERROR)."
    fi

    echo "Starting Jupyter Notebooks docker image"
    docker run --restart unless-stopped --name jupyter-notebook -d --network dockernetredelk --ip 192.168.254.2 -p8888:8888 --add-host="elasticsearch:192.168.254.1" --add-host="bloodhound:192.168.254.3"  -v /usr/share/redelk/jupyter:/home/jovyan/work jupyter/scipy-notebook start-notebook.sh --NotebookApp.token='' --NotebookApp.password='' --NotebookApp.allow_remote_access='True' --NotebookApp.allow_origin='*' >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not start Jupyter docker image (Error Code: $ERROR)."
    fi

    echo "Modifying elasticsearch config file to include docker ip interface"
    DOCKERIP="192.168.254.1" && cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.backup &&  echo 'network.bind_host: ["127.0.0.1","'$DOCKERIP'"]' >> /etc/elasticsearch/elasticsearch.yml >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Error with modifying elasticsearch config file to include docker ip interface (Error Code: $ERROR)."
    fi

    echo "Restarting Elasticsearch with new config"
    systemctl restart elasticsearch >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not restart Elasticsearch (Error Code: $ERROR)."
    fi

    echo "Creating Neo4j/BloodHound working dir"
    mkdir -p /usr/share/redelk/neo4j/data && mkdir /usr/share/redelk/neo4j/logs && mkdir /usr/share/redelk/neo4j/import && mkdir /usr/share/redelk/neo4j/plugins && chown -R redelk:redelk /usr/share/redelk/neo4j >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create Neo4j/BloodHound working dir or copy notebooks (Error Code: $ERROR)."
    fi

    echo "Installing Neo4j/BloodHound docker image"
    docker pull --quiet specterops/bloodhound-neo4j >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install  Neo4j/BloodHound docker image (Error Code: $ERROR)."
    fi

    echo "Starting Neo4j/BloodHound docker image"
    docker run --restart unless-stopped --name bloodhound -d --network dockernetredelk --ip 192.168.254.3 -p7474:7474 -p7687:7687 --add-host="elasticsearch:192.168.254.1" --add-host="jupyter:192.168.254.2" -v /usr/share/redelk/neo4j/data:/data -v /usr/share/redelk/neo4j/logs:/logs -v /usr/share/redelk/neo4j/import:/var/lib/neo4j/import -v /usr/share/redelk/neo4j/plugins:/plugins --env NEO4J_AUTH=neo4j/BloodHound --env NEO4J_dbms_memory_heap_initial__size=${NEO4J_MEMORY} --env NEO4J_dbms_memory_heap_max__size=${NEO4J_MEMORY} --env NEO4J_dbms_memory_pagecache_size=${NEO4J_MEMORY} specterops/bloodhound-neo4j >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not start Neo4j/BloodHound docker image (Error Code: $ERROR)."
    fi
fi

echo "Creating crontab for redelk user actions"
cp ./cron.d/redelk /etc/cron.d/redelk >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "Could not create crontab for redelk user actions (Error Code: $ERROR)."
fi

grep -i error $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -eq 0 ]; then
    echo "[X] There were errors while running this installer. Manually check the log file $LOGFILE. Exiting now."
    exit
fi

echo ""
echo ""
echo ""
echo " Done with base setup of RedELK on ELK server"
echo " You can now login with redelk:redelk on "
echo "   - Main RedELK Kibana interface on port 80 (redelk:redelk)"
if [ ${WHATTOINSTALL} != "limited" ]; then
    echo "   - RedELK Jupyter notebook on port 88 (redelk:redelk)"
    echo "   - Neo4J using the Neo4J browser on port 7474"
    echo "   - Neo4J using the BloodHound app on bolt://$IP:7687 (neo4j:BloodHound)"
fi
echo ""
echo ""
echo ""
echo " !!! WARNING"
echo " !!! WARNING - IF YOU WANT FULL FUNCTIONALITY YOU ARE NOT DONE YET !!!"
echo " !!! WARNING"
echo ""
echo " You should really:"
echo "   - adjust the /etc/cron.d/redelk file to include your teamservers"
echo "   - adjust all config files in /etc/redelk/ to include your specifics like VT API, email server details, etc"
echo "   - reset default nginx credentials by adjusting the file /etc/nginx/htpasswd.users. You can use the htpasswd tool from apache2-utils package"
echo ""
echo ""
