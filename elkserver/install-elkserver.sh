#!/bin/bash
#
# Part of RedELK
# Script to install RedELK on ELK server
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="redelk-install.log"
INSTALLER="RedELK elkserver installer"
DEV="no"
DRYRUN="no"
WHATTOINSTALL="full"
FIXEDMEMORY="no"
DOCKERCONFFILE="redelk-full.yml"
DOCKERENVFILE=".env"
DOCKERENVTMPLFILE=".env.tmpl"
BLOODHOUND_APP_CONFIG="./mounts/bloodhound-config/bloodhound.config.json"

printf "[*] `date +'%b %e %R'` $INSTALLER - Starting installer\n" > $LOGFILE 2>&1
echo ""
echo ""
echo ""
echo "    ____            _  _____  _      _  __"
echo "   |  _ \  ___   __| || ____|| |    | |/ /"
echo "   | |_) |/ _ \ / _  ||  _|  | |    | ' / "
echo "   |  _ <|  __/| (_| || |___ | |___ | . \ "
echo "   |_| \__\___| \____||_____||_____||_|\_\\"
echo ""
echo ""
echo ""
echo ""
echo ""
echo "This script will install and configure necessary components for RedELK on ELK server"
echo ""
echo ""

printinstallsummary() {
    echo ""
    echo ""
    if [ $WHATTOINSTALL == "limited" ]; then
        echo "[*] Parameter 'limited' found. Going for the limited RedELK experience." | tee -a $LOGFILE
    else
        echo "[*] No 'limited' parameter found. Going for the full RedELK installation including: " | tee -a $LOGFILE
        echo "- RedELK"
        echo "- Jupyter notebooks"
        echo "- BloodHound / Neo4j / Postgres"
    fi
    echo ""
    echo "5 Seconds to abort"
    echo ""
    sleep 5
}

sedescape() {
  echo $1 | sed -e 's/\([[\/.*]\|\]\)/\\&/g'
}

preinstallcheck() {
    echo "[*] Starting pre installation checks" | tee -a $LOGFILE

    # Checking if OS is Debian / APT based
    if [ ! -f  /etc/debian_version ]; then
        echo "[X] This system is not Debian/APT-based. RedELK installer only supports Debian/APT based systems."  | tee -a $LOGFILE
        echo "System is not Debian/APT based. Not supported. Exiting." | tee -a $LOGFILE
        exit 1
    fi

    # Check if installed: curl, jq, htpasswd, docker, docker-compose
    # install if not already installed
    if [ ! -x "$(command -v curl)" ] || [ ! -x "$(command -v jq)" ] || [ ! -x "$(command -v htpasswd)" ] || [ ! -x "$(command -v docker)" ] || [ ! -x "$(command -v docker-compose)" ]; then
        echo "[*] Updating apt"  | tee -a $LOGFILE
        apt -y update >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Error updating apt. Exiting. Please fix manually (Error Code: $ERROR)." | tee -a $LOGFILE
            exit 1
        fi

        # curl
        if [ ! -x "$(command -v curl)" ]; then
            echo "[*] Installing curl"  | tee -a $LOGFILE
            apt -y install curl >> $LOGFILE 2>&1
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echo "[X] Error installing curl via apt. Exiting. Please fix manually. (Error Code: $ERROR)." | tee -a $LOGFILE
                exit 1
            fi
        fi

        # jq
        if [ ! -x "$(command -v jq)" ]; then
            echo "[*] Installing jq"  | tee -a $LOGFILE
            apt -y install jq >> $LOGFILE 2>&1
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echo "[X] Error installing jq via apt. Exiting. Please fix manually. (Error Code: $ERROR)." | tee -a $LOGFILE
                exit 1
            fi
        fi

        # htpasswd
        if [ ! -x "$(command -v htpasswd)" ]; then
            echo "[*] Installing apache2-utils"  | tee -a $LOGFILE
            apt -y install apache2-utils >> $LOGFILE 2>&1
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echo "[X] Error installing apache2-utils via apt. Exiting. Please fix manually. (Error Code: $ERROR)." | tee -a $LOGFILE
                exit 1
            fi
        fi

        # docker
        if [ ! -x "$(command -v docker)" ]; then
            echo "[*] Installing docker"  | tee -a $LOGFILE
            apt -y install docker >> $LOGFILE 2>&1
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echo "[X] Error installing docker via apt. Exiting. Please fix manually. (Error Code: $ERROR)." | tee -a $LOGFILE
                exit 1
            fi
        fi

        # docker-compose
        if [ ! -x "$(command -v docker-compose)" ]; then
            echo "[*] Installing docker-compose"  | tee -a $LOGFILE
            apt -y install docker-compose >> $LOGFILE 2>&1
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echo "[X] Could not install docker-compose via apt. Please fix manually. (Error Code: $ERROR)." | tee -a $LOGFILE
                exit 1
            fi
        fi
    fi
}

memcheck() {
    # checking system memory and setting variables
    AVAILABLE_MEMORY=$(awk '/MemTotal/{printf "%.f", $2/1024}' /proc/meminfo)
    ERROR=$?
    echo "[!] We assume this host is dedicated for RedELK. All system memory found will be appointed to RedELK processes."
    echo "[*] Total system memory found: $AVAILABLE_MEMORY MB."
    if [ $ERROR -ne 0 ]; then
        echo "[X] Error getting memory configuration of this host. Exiting." | tee -a $LOGFILE
        if [ ${FIXEDMEMORY} == "yes" ]; then
            echo "[*] Fixed memory mode. Not exiting."  | tee -a $LOGFILE
        else
            exit 1
        fi
    fi

    # check for full or limited install and set memory
    if [ ${WHATTOINSTALL} = "limited" ]; then
        # Going for limited install. Only ES requiring significant memory.
        # Tuning memory to:
        # - 3GB for non-ES Dockers and host OS
        # - System memory minus 3GB is for ES, of which 50% of that is appointed to ES jvm heap. Rounded down.
        #
        if [ ${AVAILABLE_MEMORY} -le 3999 ]; then
            echo "[!] Less than recommended 4GB memory found - not recommended but yolo continuing" | tee -a $LOGFILE
            ES_MEMORY=512m # catch all value kept low
        elif [ ${AVAILABLE_MEMORY} -ge 4000 ] &&  [ ${AVAILABLE_MEMORY} -le 4999 ]; then
            echo "[*] 4-5GB memory found" | tee -a $LOGFILE
            ES_MEMORY=1g
        elif [ ${AVAILABLE_MEMORY} -ge 5000 ] &&  [ ${AVAILABLE_MEMORY} -le 5999 ]; then
            echo "[*] 5-6GB memory found" | tee -a $LOGFILE
            ES_MEMORY=1g
        elif [ ${AVAILABLE_MEMORY} -ge 6000 ] &&  [ ${AVAILABLE_MEMORY} -le 6999 ]; then
            echo "[*] 6-7GB memory found" | tee -a $LOGFILE
            ES_MEMORY=2g
        elif [ ${AVAILABLE_MEMORY} -ge 7000 ] &&  [ ${AVAILABLE_MEMORY} -le 7999 ]; then
            echo "[*] 7-8GB memory found" | tee -a $LOGFILE
            ES_MEMORY=2g
        elif [ ${AVAILABLE_MEMORY} -ge 8000 ] &&  [ ${AVAILABLE_MEMORY} -le 8999 ]; then
            echo "[*] 8-9GB memory found" | tee -a $LOGFILE
            ES_MEMORY=3g
        elif [ ${AVAILABLE_MEMORY} -ge 9000 ] &&  [ ${AVAILABLE_MEMORY} -le 9999 ]; then
            echo "[*] 9-10GB memory found" | tee -a $LOGFILE
            ES_MEMORY=3g
        elif [ ${AVAILABLE_MEMORY} -ge 10000 ] && [ ${AVAILABLE_MEMORY} -le 10999 ]; then
            echo "[*] 10-11GB memory found" | tee -a $LOGFILE
            ES_MEMORY=4g
        elif [ ${AVAILABLE_MEMORY} -ge 11000 ] && [ ${AVAILABLE_MEMORY} -le 11999 ]; then
            echo "[*] 11-12GB memory found" | tee -a $LOGFILE
            ES_MEMORY=4g
        elif [ ${AVAILABLE_MEMORY} -ge 12000 ] && [ ${AVAILABLE_MEMORY} -le 12999 ]; then
            echo "[*] 12-13GB memory found" | tee -a $LOGFILE
            ES_MEMORY=5g
        elif [ ${AVAILABLE_MEMORY} -ge 13000 ] && [ ${AVAILABLE_MEMORY} -le 13999 ]; then
            echo "[*] 13-14GB memory found" | tee -a $LOGFILE
            ES_MEMORY=5g
        elif [ ${AVAILABLE_MEMORY} -ge 14000 ] && [ ${AVAILABLE_MEMORY} -le 14999 ]; then
            echo "[*] 14-15GB memory found" | tee -a $LOGFILE
            ES_MEMORY=6g
        elif [ ${AVAILABLE_MEMORY} -ge 15000 ] && [ ${AVAILABLE_MEMORY} -le 15999 ]; then
            echo "[*] 15-16GB memory found" | tee -a $LOGFILE
            ES_MEMORY=6g
        elif [ ${AVAILABLE_MEMORY} -ge 16000 ] && [ ${AVAILABLE_MEMORY} -le 16999 ]; then
            echo "[*] 16-17GB memory found" | tee -a $LOGFILE
            ES_MEMORY=7g
        elif [ ${AVAILABLE_MEMORY} -ge 17000 ] && [ ${AVAILABLE_MEMORY} -le 17999 ]; then
            echo "[*] 17-18GB memory found" | tee -a $LOGFILE
            ES_MEMORY=7g
        elif [ ${AVAILABLE_MEMORY} -ge 18000 ] && [ ${AVAILABLE_MEMORY} -le 18999 ]; then
            echo "[*] 18-19GB memory found" | tee -a $LOGFILE
            ES_MEMORY=8g
        elif [ ${AVAILABLE_MEMORY} -ge 19000 ] && [ ${AVAILABLE_MEMORY} -le 19999 ]; then
            echo "[*] 19-20GB memory found" | tee -a $LOGFILE
            ES_MEMORY=8g
        elif [ ${AVAILABLE_MEMORY} -ge 20000 ]; then
            echo "[*] 20GB or more memory found" | tee -a $LOGFILE
            ES_MEMORY=9g
        fi
    else
    # Going for full install. Both ES and Neo4j requiring significant memory.
    # Tuning memory to:
    # - 4GB for non-ES Dockers and host OS
    # - Of remainign memory (system mem minus 4GB), 50% is appointed to NEO4j
    # - The other Remaining 50% is for ES. Here the 50% guideline of Elastic comes into play: 50% of that is for ES jvm heap. The other 50% for other non-heap ES processes. Rounded down.
    #
        SHOULDEXIT=false
        if [ ${AVAILABLE_MEMORY} -le 7999 ]; then
            echo "[X] Less than 8GB found. Not enough for full install. Consider 'limited' install. Exiting."
            SHOULDEXIT=true
        elif [ ${AVAILABLE_MEMORY} -ge 8000 ] &&  [ ${AVAILABLE_MEMORY} -le 8999 ]; then
            echo "[*] 8-9GB memory found" | tee -a $LOGFILE
            ES_MEMORY=1g
            NEO4J_MEMORY=2G
        elif [ ${AVAILABLE_MEMORY} -ge 9000 ] &&  [ ${AVAILABLE_MEMORY} -le 9999 ]; then
            echo "[*] 9-10GB memory found" | tee -a $LOGFILE
            ES_MEMORY=1g
            NEO4J_MEMORY=3G
        elif [ ${AVAILABLE_MEMORY} -ge 10000 ] && [ ${AVAILABLE_MEMORY} -le 10999 ]; then
            echo "[*] 10-11GB memory found" | tee -a $LOGFILE
            ES_MEMORY=2g
            NEO4J_MEMORY=3G
        elif [ ${AVAILABLE_MEMORY} -ge 11000 ] && [ ${AVAILABLE_MEMORY} -le 11999 ]; then
            echo "[*] 11-12GB memory found" | tee -a $LOGFILE
            ES_MEMORY=2g
            NEO4J_MEMORY=4G
        elif [ ${AVAILABLE_MEMORY} -ge 12000 ] && [ ${AVAILABLE_MEMORY} -le 12999 ]; then
            echo "[*] 12-13GB memory found" | tee -a $LOGFILE
            ES_MEMORY=2g
            NEO4J_MEMORY=4G
        elif [ ${AVAILABLE_MEMORY} -ge 13000 ] && [ ${AVAILABLE_MEMORY} -le 13999 ]; then
            echo "[*] 13-14GB memory found" | tee -a $LOGFILE
            ES_MEMORY=2g
            NEO4J_MEMORY=5G
        elif [ ${AVAILABLE_MEMORY} -ge 14000 ] && [ ${AVAILABLE_MEMORY} -le 14999 ]; then
            echo "[*] 14-15GB memory found" | tee -a $LOGFILE
            ES_MEMORY=3g
            NEO4J_MEMORY=5G
        elif [ ${AVAILABLE_MEMORY} -ge 15000 ] && [ ${AVAILABLE_MEMORY} -le 15999 ]; then
            echo "[*] 15-16GB memory found" | tee -a $LOGFILE
            ES_MEMORY=3g
            NEO4J_MEMORY=6G
        elif [ ${AVAILABLE_MEMORY} -ge 16000 ] && [ ${AVAILABLE_MEMORY} -le 16999 ]; then
            echo "[*] 16-17GB memory found" | tee -a $LOGFILE
            ES_MEMORY=3g
            NEO4J_MEMORY=6G
        elif [ ${AVAILABLE_MEMORY} -ge 17000 ] && [ ${AVAILABLE_MEMORY} -le 17999 ]; then
            echo "[*] 17-18GB memory found" | tee -a $LOGFILE
            ES_MEMORY=3g
            NEO4J_MEMORY=7G
        elif [ ${AVAILABLE_MEMORY} -ge 18000 ] && [ ${AVAILABLE_MEMORY} -le 18999 ]; then
            echo "[*] 18-19GB memory found" | tee -a $LOGFILE
            ES_MEMORY=4g
            NEO4J_MEMORY=7G
        elif [ ${AVAILABLE_MEMORY} -ge 19000 ] && [ ${AVAILABLE_MEMORY} -le 19999 ]; then
            echo "[*] 19-20GB memory found" | tee -a $LOGFILE
            ES_MEMORY=4g
            NEO4J_MEMORY=8G
        elif [ ${AVAILABLE_MEMORY} -ge 20000 ]; then
            echo "[*] 20GB or more memory found" | tee -a $LOGFILE
            ES_MEMORY=4g
            NEO4J_MEMORY=8G
        fi
    fi

    if [ "$SHOULDEXIT" = true ]; then
        if [ ${FIXEDMEMORY} == "yes" ]; then
            echo "[*] Fixed memory mode. Skipping memory check."  | tee -a $LOGFILE
            ES_MEMORY=1g
            NEO4J_MEMORY=1G
        else
            exit 1
        fi
    fi
}



if [[ $EUID -ne 0 ]]; then
  echo "[X] Not running as root. Exiting"
  exit 1
fi

if [ ${#} -ne 0 ] && [[ "$*" = *"dryrun"* ]]; then
    echo "[*] Dry run mode, only running pre-req checks and creating initial .env file."  | tee -a $LOGFILE
    DRYRUN="yes"
fi

if [ ${#} -ne 0 ] && [[ $* = *"fixedmemory"* ]]; then
    echo "[*] Fixed memory mode: skip memory check and appoint 1G to NEO4J."  | tee -a $LOGFILE
    FIXEDMEMORY="yes"
    ES_MEMORY=1g
    NEO4J_MEMORY=1G
fi

if [ ${#} -ne 0 ] && [[ "$*" == *"limited"* ]]; then
    WHATTOINSTALL="limited"
    DOCKERCONFFILE="redelk-limited.yml"
elif [ ${#} -ne 0 ] && [[ "$*" == *"dev"* ]]; then
    echo "[*] DEV MODE DEV MODE DEV MODE DEV MODE."  | tee -a $LOGFILE
    DEV="yes"
    DOCKERCONFFILE="redelk-dev.yml"
else
    DOCKERCONFFILE="redelk-full.yml"
fi

echo ""
memcheck
printinstallsummary
preinstallcheck

# DEV specific things
if [ $DEV == "yes" ]; then
    chown -R 1000 ./docker/redelk-base/redelkinstalldata
    chown -R 1000 ./docker/redelk-logstash/redelkinstalldata
fi

if [ ! -f ${DOCKERENVFILE} ]; then
    echo "[*] .env file doesn't exist yet, copying from .env.tmpl"  | tee -a $LOGFILE
    cp ${DOCKERENVTMPLFILE} ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could copy .env file from template (Error Code: $ERROR)."  | tee -a $LOGFILE
        exit 1
    fi
else
    echo "[*] .env file already exists, skipping copy from template" | tee -a $LOGFILE
fi

REDELKVERSION=$(cat ./VERSION)
echo "[*] Setting RedELK version in docker env file" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{REDELKVERSION\}\}/${REDELKVERSION}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set RedELK version in docker env file (Error Code: $ERROR)." | tee -a $LOGFILE
    exit 1
fi

# check if we need to create a kibana system user account
if (grep "{{CREDS_kibana_system}}" $DOCKERENVFILE > /dev/null); then
    CREDS_kibana_system=$(< /dev/urandom tr -dc _A-Za-z0-9 | head -c32)
    echo "[*] Setting kibana_system ES password" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{CREDS_kibana_system\}\}/${CREDS_kibana_system}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not set kibana_system ES password (Error Code: $ERROR)." | tee -a $LOGFILE
        exit 1
    fi
else
    echo "[*] kibana_system ES password already defined - skipping" | tee -a $LOGFILE
    CREDS_kibana_system=$(grep -E ^CREDS_kibana_system= .env|awk -F\= '{print $2}')
fi

# check if we need to create a logstash system user account
if (grep "{{CREDS_logstash_system}}" $DOCKERENVFILE > /dev/null); then
    CREDS_logstash_system=$(< /dev/urandom tr -dc _A-Za-z0-9 | head -c32)
    echo "[*] Setting logstash_system ES password" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{CREDS_logstash_system\}\}/${CREDS_logstash_system}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not set logstash_system ES password (Error Code: $ERROR)." | tee -a $LOGFILE
    fi
else
    echo "[*] logstash_system ES password already defined - skipping" | tee -a $LOGFILE
    CREDS_logstash_system=$(grep -E ^CREDS_logstash_system= .env|awk -F\= '{print $2}')
fi

# check if we need to create a redelk ingest account
if (grep "{{CREDS_redelk_ingest}}" $DOCKERENVFILE > /dev/null); then
    CREDS_redelk_ingest=$(< /dev/urandom tr -dc _A-Za-z0-9 | head -c32)
    echo "[*] Setting redelk_ingest ES password" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{CREDS_redelk_ingest\}\}/${CREDS_redelk_ingest}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not set redelk_ingest ES password (Error Code: $ERROR)." | tee -a $LOGFILE
    fi
else
    echo "[*] redlk_ingest ES password already defined - skipping" | tee -a $LOGFILE
    CREDS_redelk_ingest=$(grep -E ^CREDS_redelk_ingest= .env|awk -F\= '{print $2}')
fi

# check if we need to create a redelk user account
if (grep "{{CREDS_redelk}}" $DOCKERENVFILE > /dev/null); then
    CREDS_redelk=$(< /dev/urandom tr -dc _A-Za-z0-9 | head -c32)

    echo "[*] Setting redelk password in elasticsearch" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{CREDS_redelk\}\}/${CREDS_redelk}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not set redelk ES password (Error Code: $ERROR)." | tee -a $LOGFILE
    fi

    echo "[*] Setting redelk password in htaccess" | tee -a $LOGFILE
    htpasswd -b -m mounts/nginx-config/htpasswd.users.template redelk ${CREDS_redelk} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Error setting redelk password in htaccess (Error Code: $ERROR)." | tee -a $LOGFILE
    fi
else
    echo "[*] Redelk password in elasticsearch already defined - skipping" | tee -a $LOGFILE
    CREDS_redelk=$(grep -E ^CREDS_redelk= .env|awk -F\= '{print $2}')
fi

# check if we need to create a elastic user password
if (grep "{{ELASTIC_PASSWORD}}" $DOCKERENVFILE > /dev/null); then
    ELASTIC_PASSWORD=$(< /dev/urandom tr -dc _A-Za-z0-9 | head -c32)

    echo "[*] Setting elastic ES password in Docker template" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{ELASTIC_PASSWORD\}\}/${ELASTIC_PASSWORD}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Error setting elastic ES password in Docker template (Error Code: $ERROR)." | tee -a $LOGFILE
    fi

    echo "[*] Setting elastic ES password in redelk config.json" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{ELASTIC_PASSWORD\}\}/${ELASTIC_PASSWORD}/g" mounts/redelk-config/etc/redelk/config.json >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Error setting elastic ES password in redelk config.json (Error Code: $ERROR)." | tee -a $LOGFILE
    fi
    rm mounts/redelk-config/etc/redelk/config.json.bak
else
    echo "[*] Elastic ES password in docker template already defined - skipping" | tee -a $LOGFILE
    ELASTIC_PASSWORD=$(grep -E ^ELASTIC_PASSWORD= .env|awk -F\= '{print $2}')
fi

# check if we need to create the kibana encryption key
if (grep "{{KBN_XPACK_ENCRYPTEDSAVEDOBJECTS}}" $DOCKERENVFILE > /dev/null); then
    KBN_XPACK_ENCRYPTEDSAVEDOBJECTS=$(< /dev/urandom tr -dc _A-Za-z0-9 | head -c32)
    echo "[*] Setting Kibana encryption key" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{KBN_XPACK_ENCRYPTEDSAVEDOBJECTS\}\}/${KBN_XPACK_ENCRYPTEDSAVEDOBJECTS}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not set Kibana encryption key (Error Code: $ERROR)." | tee -a $LOGFILE
    fi
else
    echo "[*] Kibana encryption key in docker template already defined - skipping" | tee -a $LOGFILE
    KBN_XPACK_ENCRYPTEDSAVEDOBJECTS=$(grep -E ^KBN_XPACK_ENCRYPTEDSAVEDOBJECTS= .env|awk -F\= '{print $2}')
fi

echo "[*] Adjusting memory settings for Elasticsearch" | tee -a $LOGFILE
sed -E -i "s/^\-Xms.*$/\-Xms${ES_MEMORY}/g" mounts/elasticsearch-config/jvm.options.d/jvm.options 2>&1 && \
sed -E -i "s/^\-Xmx.*$/\-Xmx${ES_MEMORY}/g" mounts/elasticsearch-config/jvm.options.d/jvm.options >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not adjust ES memory settings (Error Code: $ERROR)." | tee -a $LOGFILE
fi

if [ ${WHATTOINSTALL} = "full" ]; then
    echo "[*] Adjusting memory settings for NEO4J" | tee -a $LOGFILE
    sed -E -i.bak3 "s/\{\{NEO4J_MEMORY\}\}/${NEO4J_MEMORY}/g" ${DOCKERENVFILE}
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not adjust NEO4J memory settings (Error Code: $ERROR)." | tee -a $LOGFILE
    fi

    # check if Neo4J password is already generated
    if (grep "{{NEO4J_PASSWORD}}" $DOCKERENVFILE > /dev/null); then
        NEO4J_PASSWORD=$(< /dev/urandom tr -dc _A-Za-z0-9 | head -c32)

        echo "[*] Setting neo4j password" | tee -a $LOGFILE
        sed -E -i.bak "s/\{\{NEO4J_PASSWORD\}\}/${NEO4J_PASSWORD}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Could not set neo4j password (Error Code: $ERROR)." | tee -a $LOGFILE
        fi
    else
        echo "[*] Neo4j password in docker template already defined - skipping" | tee -a $LOGFILE
        NEO4J_PASSWORD=$(grep -E ^NEO4J_AUTH= .env|awk -Fneo4j/ '{print $2}')
    fi
    # check if Neo4J password is already generated and set in bloodhound config as it can not be set through env.
    # https://github.com/SpecterOps/BloodHound/issues/9
    if (grep "{{NEO4J_PASSWORD}}" $BLOODHOUND_APP_CONFIG > /dev/null); then
        # do not regenerate the password as it should already be set
        echo "[*] Setting neo4j password" | tee -a $LOGFILE
        sed -E -i.bak "s/\{\{NEO4J_PASSWORD\}\}/${NEO4J_PASSWORD}/g" ${BLOODHOUND_APP_CONFIG} >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Could not set postgresql password (Error Code: $ERROR)." | tee -a $LOGFILE
        fi
    fi

    # check if Postgres password is already generated and set in Docker env.
    if (grep "{{PGSQL_PASSWORD}}" $DOCKERENVFILE > /dev/null); then
        POSTGRES_PASSWORD=$(< /dev/urandom tr -dc _A-Za-z0-9 | head -c32)

        echo "[*] Setting postgresql password" | tee -a $LOGFILE
        sed -E -i.bak "s/\{\{PGSQL_PASSWORD\}\}/${POSTGRES_PASSWORD}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Could not set postgresql password (Error Code: $ERROR)." | tee -a $LOGFILE
        fi
    else
        echo "[*] Postgresql password in docker template already defined - skipping" | tee -a $LOGFILE
        POSTGRES_PASSWORD=$(grep -E ^POSTGRES_PASSWORD= .env|awk -F= '{print $2}')
    fi
    # check if Postgres password is already set in bloodhound config as it can not be set through env.
    # https://github.com/SpecterOps/BloodHound/issues/9
    if (grep "{{PGSQL_PASSWORD}}" $BLOODHOUND_APP_CONFIG > /dev/null); then
        # do not regenerate the password as it should already be set
        echo "[*] Setting postgresql password" | tee -a $LOGFILE
        sed -E -i.bak "s/\{\{PGSQL_PASSWORD\}\}/${POSTGRES_PASSWORD}/g" ${BLOODHOUND_APP_CONFIG} >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Could not set postgresql password (Error Code: $ERROR)." | tee -a $LOGFILE
        fi
    fi

    # check if Bloodhound admin password is already generated and set in bloodhound app config  as it can not be set through env.
    # https://github.com/SpecterOps/BloodHound/issues/9
    if (grep "{{BLOODHOUND_PASSWORD}}" $BLOODHOUND_APP_CONFIG > /dev/null); then
        BLOODHOUND_PASSWORD=$(< /dev/urandom tr -dc _A-Za-z0-9 | head -c32)

        echo "[*] Setting bloodhound password" | tee -a $LOGFILE
        sed -E -i.bak "s/\{\{BLOODHOUND_PASSWORD\}\}/${BLOODHOUND_PASSWORD}/g" ${BLOODHOUND_APP_CONFIG} >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Could not set bloodhound password (Error Code: $ERROR)." | tee -a $LOGFILE
        fi
    else
        echo "[*] Bloodhound password in bloodhound config already defined - skipping" | tee -a $LOGFILE
        BLOODHOUND_PASSWORD=$(grep -E '"password":' ${BLOODHOUND_APP_CONFIG}|awk -F " \"" '{print $3}'|sed -e "s/\",//")
    fi

    
    # check if Bloodhound admin email is already generated and set in bloodhound app config  as it can not be set through env.
    # https://github.com/SpecterOps/BloodHound/issues/9
    if (grep "{{BLOODHOUND_ADMIN_EMAIL}}" $BLOODHOUND_APP_CONFIG > /dev/null); then
        BLOODHOUND_ADMIN_EMAIL=$(cat ./mounts/redelk-config/etc/redelk/config.json | jq -r .redelkserver_letsencrypt.le_email)

        echo "[*] Setting bloodhound password" | tee -a $LOGFILE
        sed -E -i.bak "s/\{\{BLOODHOUND_ADMIN_EMAIL\}\}/${BLOODHOUND_ADMIN_EMAIL}/g" ${BLOODHOUND_APP_CONFIG} >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Could not set bloodhound admin email (Error Code: $ERROR)." | tee -a $LOGFILE
        fi
    else
        echo "[*] Bloodhound admin e-mail in bloodhound config already defined - skipping" | tee -a $LOGFILE
        BLOODHOUND_ADMIN_EMAIL=$(grep -E '"email_address":' ${BLOODHOUND_APP_CONFIG}|awk -F " \"" '{print $3}'|sed -e "s/\"//")
    fi
fi

echo "[*] Setting permissions on redelk base cron job" | tee -a $LOGFILE
chmod 600 ./mounts/redelk-config/etc/cron.d/redelk >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set permissions on redelk base cron (Error Code: $ERROR)." | tee -a $LOGFILE
fi

echo "[*] Setting permissions on logstash configs" | tee -a $LOGFILE
chown -R 1000 ./mounts/logstash-config/* >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set permissions on logstash configs (Error Code: $ERROR)." | tee -a $LOGFILE
fi

echo "[*] Setting permissions on redelk logs" | tee -a $LOGFILE
chown -R 1000 ./mounts/redelk-logs && chmod 664 ./mounts/redelk-logs/* >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set permissions on redelk logs (Error Code: $ERROR)." | tee -a $LOGFILE
fi

echo "[*] Setting permissions on redelk www data" | tee -a $LOGFILE
chown -R 1000 ./mounts/redelk-www && chmod 755 ./mounts/redelk-www/* >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set permissions on redelk www data (Error Code: $ERROR)." | tee -a $LOGFILE
fi

echo "[*] Setting permissions on Jupyter notebook working dir" | tee -a $LOGFILE
chown -R 1000 ./mounts/jupyter-workbooks >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set permissions on Jupyter notebook working dir (Error Code: $ERROR)." | tee -a $LOGFILE
fi

echo "[*] Setting permissions on elastic config" | tee -a $LOGFILE
chown -R 1000 ./mounts/elasticsearch-config >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set permissions on elasticsearch configs (Error Code: $ERROR)." | tee -a $LOGFILE
fi

# Certificate things for nginx
# check if letsencrypt is enabled in the config file
DO_LETSENCRYPT=$(cat ./mounts/redelk-config/etc/redelk/config.json | jq -r .redelkserver_letsencrypt.enable_letsencrypt)
if [ $DO_LETSENCRYPT == "true" ]; then
    EXTERNAL_DOMAIN=$(cat ./mounts/redelk-config/etc/redelk/config.json | jq -r .redelkserver_letsencrypt.external_domain)
    echo "[*] Validating configured external domain name $EXTERNAL_DOMAIN" | tee -a $LOGFILE
    if [ `echo $EXTERNAL_DOMAIN|wc -w`  -eq 0 ] || [ `echo $EXTERNAL_DOMAIN | grep "\." > /dev/null ;echo $?` -eq 1 ] ; then
        echo "[X] Error. Let's encrypt domain name seems empty. Exiting." | tee -a $LOGFILE
        exit 1
    else
        echo "[*] Domain $EXTERNAL_DOMAIN seems valid. Continuing."  | tee -a $LOGFILE

        echo "[*] Setting external domain name in Docker env file" | tee -a $LOGFILE
        sed -E -i.bak "s/\{\{EXTERNAL_DOMAIN\}\}/${EXTERNAL_DOMAIN}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Could not set external domain name in Docker env file (Error Code: $ERROR)." | tee -a $LOGFILE
        fi

        LE_EMAIL=$(cat ./mounts/redelk-config/etc/redelk/config.json | jq -r .redelkserver_letsencrypt.le_email)
        echo "[*] Setting Let's Encrypt email in Docker env file" | tee -a $LOGFILE
        sed -E -i.bak "s/\{\{LE_EMAIL\}\}/${LE_EMAIL}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Could not set Let's Encrypt email in Docker env file (Error Code: $ERROR)." | tee -a $LOGFILE
        fi
    fi
else # letsencrypt not enabled, but we still need a cert for nginx. So we create a self sigend cert using the domain name from initial-setup certs config file
    EXTERNAL_DOMAIN=`grep -E "^DNS\.|^IP\." ./initial-setup-data/certs/config.cnf|awk -F\= '{print $2}'|tr -d " "|head -n1`
    echo "[*] Creating custom certificate for $EXTERNAL_DOMAIN "
    CERTPATH="mounts/certbot/conf/live/noletsencrypt"
    mkdir -p $CERTPATH >> $LOGFILE 2>&1 && \
    openssl req -x509 -nodes -newkey rsa:4096 -days 365 -keyout $CERTPATH/privkey.pem -out $CERTPATH/fullchain.pem -subj /CN=${EXTERNAL_DOMAIN} >> $LOGFILE 2>&1 && \
    chown -R 1000 $CERTPATH >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Error creating custom certificates (Error Code: $ERROR)." | tee -a $LOGFILE
    fi

    # after the cert is generated we set $EXTERNAL_DOMAIN and $LE_EMAIL to invalid values to have certbot fail on purpose
    EXTERNAL_DOMAIN="noletsencrypt"
    LE_EMAIL="noletsencrypt"
fi

# NGINX certificates vars
CERTS_DIR_NGINX_LOCAL=$(sedescape "./mounts/certbot/conf/")
CERTS_DIR_NGINX_CA_LOCAL=$(sedescape "./mounts/certs/ca/")
TLS_NGINX_CRT_PATH=$(sedescape "/etc/nginx/certs/live/${EXTERNAL_DOMAIN}/fullchain.pem")
TLS_NGINX_KEY_PATH=$(sedescape "/etc/nginx/certs/live/${EXTERNAL_DOMAIN}/privkey.pem")
TLS_NGINX_CA_PATH=$(sedescape "/etc/nginx/ca_certs/ca.crt")

echo "[*] Setting CERTS_DIR_NGINX_LOCAL" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{CERTS_DIR_NGINX_LOCAL\}\}/${CERTS_DIR_NGINX_LOCAL}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set CERTS_DIR_NGINX_LOCAL (Error Code: $ERROR)." | tee -a $LOGFILE
fi
echo "[*] Setting CERTS_DIR_NGINX_CA_LOCAL" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{CERTS_DIR_NGINX_CA_LOCAL\}\}/${CERTS_DIR_NGINX_CA_LOCAL}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set CERTS_DIR_NGINX_CA_LOCAL (Error Code: $ERROR)." | tee -a $LOGFILE
fi
echo "[*] Setting TLS_NGINX_CRT_PATH" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{TLS_NGINX_CRT_PATH\}\}/${TLS_NGINX_CRT_PATH}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set TLS_NGINX_CRT_PATH (Error Code: $ERROR)." | tee -a $LOGFILE
fi
echo "[*] Setting TLS_NGINX_KEY_PATH" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{TLS_NGINX_KEY_PATH\}\}/${TLS_NGINX_KEY_PATH}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set TLS_NGINX_KEY_PATH (Error Code: $ERROR)." | tee -a $LOGFILE
fi
echo "[*] Setting TLS_NGINX_CA_PATH" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{TLS_NGINX_CA_PATH\}\}/${TLS_NGINX_CA_PATH}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Could not set TLS_NGINX_CA_PATH (Error Code: $ERROR)." | tee -a $LOGFILE
fi

if [ ${WHATTOINSTALL} = "limited" ]; then
    echo "[*] Adjusting Nginx config file" | tee -a $LOGFILE
    sed -i 's/^\s*include conf.d\/full.location-conf;\s*$/    # include conf.d\/full.location-conf;/g' ./mounts/nginx-config/default.conf.template
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not adjust Nginx config (Error Code: $ERROR)." | tee -a $LOGFILE
    fi
    # commenting out the bloodhound location template
    sed -i 's/^\s*include conf.d\/full.bloodhound-conf;\s*$/    # include conf.d\/full.bloodhound-conf;/g' ./mounts/nginx-config/default.conf.template
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not adjust Nginx config (Error Code: $ERROR)." | tee -a $LOGFILE
    fi
else
    echo "[*] Adjusting Nginx config file" | tee -a $LOGFILE
    sed -i 's/^\s*#\s*include conf.d\/full.location-conf;\s*$/    include conf.d\/full.location-conf;/g' ./mounts/nginx-config/default.conf.template
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not adjust Nginx config (Error Code: $ERROR)." | tee -a $LOGFILE
    fi
    # re-enabling the bloodhound location template
    sed -i 's/^\s*#\s*include conf.d\/full.bloodhound-conf;\s*$/    include conf.d\/full.bloodhound-conf;/g' ./mounts/nginx-config/default.conf.template
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not adjust Nginx config (Error Code: $ERROR)." | tee -a $LOGFILE
    fi
fi

echo "[*] Linking docker-compose.yml to the docker file used" | tee -a $LOGFILE
if [ -f docker-compose.yml ]; then
    rm docker-compose.yml >> $LOGFILE 2>&1
fi
ln -s $DOCKERCONFFILE docker-compose.yml >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Error linking docker-compose.yml to the docker file used (Error Code: $ERROR)." | tee -a $LOGFILE
fi

echo "[*] Creating password file for easy reference" | tee -a $LOGFILE
echo "# passwords used by RedELK installation - NOT A CONFIG FILE! - passwords are defined in .env file" > redelk_passwords.cfg && \
echo "CredHtaccessUsername = \"redelk\"" >> redelk_passwords.cfg && \
echo "CredHtaccessPassword = \"$CREDS_redelk\"" >> redelk_passwords.cfg && \
echo "CredESUsername = \"elastic\"" >> redelk_passwords.cfg && \
echo "CredESPassword = \"$ELASTIC_PASSWORD\"" >> redelk_passwords.cfg && \
echo "CredNeo4jUsername = \"neo4j\"" >> redelk_passwords.cfg && \
echo "CredNeo4jPassword = \"$NEO4J_PASSWORD\"" >> redelk_passwords.cfg && \
echo "CredBloodhoundAdminEmail = \"$BLOODHOUND_ADMIN_EMAIL\"" >> redelk_passwords.cfg && \
echo "CredBloodhoundUsername = \"admin\"" >> redelk_passwords.cfg && \
echo "CredBloodhoundPassword = \"$BLOODHOUND_PASSWORD\"" >> redelk_passwords.cfg && \
echo "CredPostgresUsername = \"bloodhound\"" >> redelk_passwords.cfg && \
echo "CredPostgresPassword = \"$POSTGRES_PASSWORD\"" >> redelk_passwords.cfg
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Error creating password file for easy reference (Error Code: $ERROR)." | tee -a $LOGFILE
fi

echo "[*] Copying password file for use with jupyter notebooks" | tee -a $LOGFILE
cp redelk_passwords.cfg ./mounts/jupyter-workbooks/redelk_passwords.py >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echo "[X] Error copying password file for use with jupyter notebooks (Error Code: $ERROR)." | tee -a $LOGFILE
fi


if [ $DRYRUN == "no" ]; then

    echo "[*] Setting vm.max_map_count to 262144" | tee -a $LOGFILE
    sysctl -w vm.max_map_count=262144 >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Could not set vm.max_map_count (Error Code: $ERROR)." | tee -a $LOGFILE
        exit 1
    fi

    if ( ! grep -r "^vm.max_map_count" /etc/sysctl* > /dev/null ) ; then
        echo "[*] Making vm.max_map_count setting persistent" | tee -a $LOGFILE
        echo "vm.max_map_count=262144" >> /etc/sysctl.conf >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Could not make vm.max_map_count persistent (Error Code: $ERROR)." | tee -a $LOGFILE
            exit 1
        fi
    else
        echo "[!] WARNING : existing vm.max_map_count setting found in /etc/systctl.conf - yolo continuing" | tee -a $LOGFILE
    fi

    if [ $DO_LETSENCRYPT == "true" ]; then
        echo "[*] Running initial Let's Encrypt script" | tee -a $LOGFILE
        ./init-letsencrypt.sh $DOCKERCONFFILE $EXTERNAL_DOMAIN # >>$LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Error running initial Let's Encrypt script (Error Code: $ERROR)." | tee -a $LOGFILE
            #exit 1
        fi
    fi

    echo "[*] Building RedELK from $DOCKERCONFFILE file. Docker output below." | tee -a $LOGFILE
    echo ""
    docker-compose -f docker-compose.yml up --build -d # >>$LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echo "[X] Error building RedELK using docker-compose file $DOCKERCONFFILE (Error Code: $ERROR)." | tee -a $LOGFILE
        exit 1
    fi
    echo ""
fi

grep "* ERROR " redelk-install.log
ERROR=$?
if [ $ERROR -eq 0 ]; then
    echo "[X] There were errors while running this installer. Manually check the log file $LOGFILE. Exiting now."
    exit 1
fi

echo "" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
if [ $DRYRUN == "no" ]; then
    echo " Done with base setup of RedELK on ELK server" | tee -a $LOGFILE
    echo " You can now login to the following interfaces: " | tee -a $LOGFILE
    echo "   - Main RedELK Kibana interface on port 443 (user: redelk, pass:$CREDS_redelk)" | tee -a $LOGFILE
    if [ ${WHATTOINSTALL} != "limited" ]; then
        echo "   - Jupyter notebooks on /jupyter (user: redelk, pass:$CREDS_redelk)" | tee -a $LOGFILE
        echo "   - Bloodhound community edition on https port 8443 (user: admin, pass:$BLOODHOUND_PASSWORD)" | tee -a $LOGFILE
        echo "   - Neo4J Browser port 7474 (user: neo4j, pass:$NEO4J_PASSWORD)" | tee -a $LOGFILE
        echo "   - Neo4J using the BloodHound app on port 7687 (user: neo4j, pass:$NEO4J_PASSWORD)" | tee -a $LOGFILE
    fi
    echo "" | tee -a $LOGFILE
    echo "" | tee -a $LOGFILE
    echo "" | tee -a $LOGFILE
    echo " !!! WARNING" | tee -a $LOGFILE
    echo " !!! WARNING - IF YOU WANT FULL FUNCTIONALITY YOU ARE NOT DONE YET !!!" | tee -a $LOGFILE
    echo " !!! WARNING" | tee -a $LOGFILE
    echo ""
    echo " You should really:" | tee -a $LOGFILE
    echo "   - adjust the mounts/redelk-config/etc/cron.d/redelk file to include your teamservers" | tee -a $LOGFILE
    echo "   - adjust all config files in mounts/redelk-config/etc/redelk to include your specifics like VT API, email server details, etc" | tee -a $LOGFILE
    echo "   - adjust the .env file to match any specifics you need (e.g. using custom certificate, etc.)" | tee -a $LOGFILE
else
    echo "Done with dry-run checks and .env file creation." | tee -a $LOGFILE
    echo "You can now modify the .env file and then run the installer again without the 'dryrun' paramater" | tee -a $LOGFILE
fi
echo "" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
