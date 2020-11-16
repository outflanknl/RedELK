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
DOCKERCONFFILE="redelk-full.yml"
DOCKERENVFILE=".env"
DOCKERENVTMPLFILE=".env.tmpl"

printf "`date +'%b %e %R'` $INSTALLER - Starting installer\n" > $LOGFILE 2>&1
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

if [[ $EUID -ne 0 ]]; then
  echo "[X] Not running as root. Exiting"
  exit 1
fi

if [ ${#} -ne 0 ] && [ ${1} = "limited" ]; then
    echo "Parameter 'limited' found. Going for the limited RedELK experience." | tee -a $LOGFILE
    echo ""
    echo "5 Seconds to abort"
    echo ""
    sleep 5
    WHATTOINSTALL="limited"
    DOCKERCONFFILE="redelk-limited.yml"
elif [ ${#} -ne 0 ] && [ ${1} = "dev" ]; then
    echo ""
    echo "[*] DEV MODE DEV MODE DEV MODE DEV MODE."  | tee -a $LOGFILE
    echo ""
    DEV="yes"
    DOCKERCONFFILE="redelk-dev.yml"
elif [ ${#} -ne 0 ] && [ ${1} = "dryrun" ]; then
    echo ""
    echo "[*] Dry run mode, only running pre-req checks and creating initial .env file."  | tee -a $LOGFILE
    echo ""
    DRYRUN="yes"
else
    echo "No 'limited' parameter found. Going for the full RedELK installation including: " | tee -a $LOGFILE
    echo "- RedELK"
    echo "- Jupyter notebooks"
    echo "- BloodHound / Neo4j"
    echo ""
    echo "5 Seconds to abort"
    echo ""
    sleep 5
    DOCKERCONFFILE="redelk-full.yml"
fi

echoerror() {
    printf "`date +'%b %e %R'` $INSTALLER - ${RC} * ERROR ${EC}: $@\n" >> $LOGFILE 2>&1
}

install_docker(){
    echo "[*] Installing docker"
    if [ -x "$(command -v apt)" ]; then
        echo "[*] apt based system found, trying to install docker via apt" | tee -a $LOGFILE
        apt -y install docker >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echoerror "[X] Could not install docker via apt. Exiting. (Error Code: $ERROR)."
            exit 1
        fi
    else
        echo "[*] Trying to install docker via Docker convenience script" | tee -a $LOGFILE
        curl -fsSL get.docker.com -o get-docker.sh >> $LOGFILE 2>&1
        chmod +x get-docker.sh >> $LOGFILE 2>&1
        ./get-docker.sh >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echoerror "[X] Docker could not be installed. Exiting. (Error Code: $ERROR)."
            exit 1
        fi
    fi
}

install_docker_compose(){
    echo "[*] Installing docker-compose.."
    if [ -x "$(command -v apt)" ]; then
        echo "[*] apt based system found, trying to install docker via apt" | tee -a $LOGFILE
        apt -y install docker-compose >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echoerror "[X] Could not install docker-compose via apt.  (Error Code: $ERROR)."
            exit 1
        fi
    else
        echo "[*] Non apt based system found, trying to install docker via install script from Docker GitHub" | tee -a $LOGFILE
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
        curl -L https://github.com/docker/compose/releases/download/$COMPOSE_VERSION/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose >> $LOGFILE 2>&1
        chmod +x /usr/local/bin/docker-compose >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echoerror "[X] Could not install docker-compose (Error Code: $ERROR)."
            exit 1
        fi
    fi
}

preinstallcheck() {
    echo "[*] Starting pre installation checks" | tee -a $LOGFILE

    SHOULDEXIT=false

    # Checking if OS is Debian / APT based
    if [ ! -f  /etc/debian_version ]; then
        echo "[X] This system does not seem to be Debian/APT-based. RedELK installer only supports Debian/APT based systems."  | tee -a $LOGFILE
        echoerror "System is not Debian/APT based. Not supported. Exiting."
        exit 1
    fi

    # Check if curl is installed
    if [ ! -x "$(command -v curl)" ]; then
        echo "[X] Curl is not installed. Please fix manually. Exiting" | tee -a $LOGFILE
        exit 1
    fi

    # Check if jq is installed
    if [ ! -x "$(command -v jq)" ]; then
        echo "[X] jq is not installed. Please fix manually. Exiting" | tee -a $LOGFILE
        exit 1
    fi

    # Check if docker is installed
    if [ ! -x "$(command -v docker)" ]; then
        echo "[!] Docker is not installed. Please fix manually, or wait 5 seconds to auto-install with Docker convenience script" | tee -a $LOGFILE
        sleep 5
        install_docker
    fi

    # Check if docker-compose is installed
    if [ ! -x "$(command -v docker-compose)" ]; then
        echo "[!] Docker-compose is not installed. Please fix manually, or wait 5 seconds to auto-install with Docker GitHub install script" | tee -a $LOGFILE
        sleep 5
        install_docker_compose
    fi

    # checking system memory and setting variables
    AVAILABLE_MEMORY=$(awk '/MemAvailable/{printf "%.f", $2/1024}' /proc/meminfo)
    ERROR=$?
    echo "[*] Memory found available for RedELK: $AVAILABLE_MEMORY MB."
    if [ $ERROR -ne 0 ]; then
        echoerror "[X] Error getting memory configuration of this host. Exiting."
        exit 1
    fi

    # check for full or limited install
    if [ ${WHATTOINSTALL} = "limited" ]; then
        if [ ${AVAILABLE_MEMORY} -le 3999 ]; then
            echo "[!] Less than recommended 8GB memory found - yolo continuing" | tee -a $LOGFILE
            ES_MEMORY=1g
        elif [ ${AVAILABLE_MEMORY} -ge 4000 -a ${AVAILABLE_MEMORY} -le 7999 ]; then
            echo "[!] Less than recommended 8GB memory found - yolo continuing" | tee -a $LOGFILE
            ES_MEMORY=2g
        elif [ ${AVAILABLE_MEMORY} -ge 8000 ]; then
            echo "[*] 8GB or more memory found" | tee -a $LOGFILE
            ES_MEMORY=4g
        fi
    else # going for full install means in check in determine how much memory NEO4J and ES get
        if [ ${AVAILABLE_MEMORY} -le 7999 ]; then
            echo "[X] Not enough memory for full install (less than 8GB). Exiting."
            SHOULDEXIT=true
        elif [ ${AVAILABLE_MEMORY} -ge 8000 ] &&  [ ${AVAILABLE_MEMORY} -le 8999 ]; then
            echo "[*] 8-9GB memory found" | tee -a $LOGFILE
            ES_MEMORY=1g
            NEO4J_MEMORY=2G
        elif [ ${AVAILABLE_MEMORY} -ge 9000 ] && [ ${AVAILABLE_MEMORY} -le 9999 ]; then
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
            ES_MEMORY=3g
            NEO4J_MEMORY=4G
        elif [ ${AVAILABLE_MEMORY} -ge 13000 ] && [ ${AVAILABLE_MEMORY} -le 13999 ]; then
            echo "[*] 13-14GB memory found" | tee -a $LOGFILE
            ES_MEMORY=3g
            NEO4J_MEMORY=4500M
        elif [ ${AVAILABLE_MEMORY} -ge 14000 ] && [ ${AVAILABLE_MEMORY} -le 14999 ]; then
            echo "[*] 14-15GB memory found" | tee -a $LOGFILE
            ES_MEMORY=3g
            NEO4J_MEMORY=5G
        elif [ ${AVAILABLE_MEMORY} -ge 15000 ] && [ ${AVAILABLE_MEMORY} -le 15999 ]; then
            echo "[*] 15-16GB memory found" | tee -a $LOGFILE
            ES_MEMORY=4g
            NEO4J_MEMORY=5G
        elif [ ${AVAILABLE_MEMORY} -ge 16000 ]; then
            echo "[*] 16GB or more memory found" | tee -a $LOGFILE
            ES_MEMORY=5g
            NEO4J_MEMORY=5G
        fi
    fi

    if [ "$SHOULDEXIT" = true ]; then
        exit 1
    fi
}

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
        echoerror "[X] Could copy .env file from template (Error Code: $ERROR)."
        exit 1
    fi
else
    echo "[*] .env file already exists, skipping copy from template" | tee -a $LOGFILE
fi

REDELKVERSION=$(cat ./VERSION)
echo "[*] Setting RedELK version to deploy" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{REDELKVERSION\}\}/${REDELKVERSION}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set RedELK version to deploy (Error Code: $ERROR)."
    exit 1
fi

CREDS_kibana_system=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)
echo "[*] Setting kibana_system ES password" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{CREDS_kibana_system\}\}/${CREDS_kibana_system}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set kibana_system ES password (Error Code: $ERROR)."
    exit 1
fi

CREDS_logstash_system=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)
echo "[*] Setting logstash_system ES password" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{CREDS_logstash_system\}\}/${CREDS_logstash_system}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set logstash_system ES password (Error Code: $ERROR)."
fi

CREDS_redelk_ingest=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)
echo "[*] Setting redelk_ingest ES password" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{CREDS_redelk_ingest\}\}/${CREDS_redelk_ingest}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set redelk_ingest ES password (Error Code: $ERROR)."
fi

# check if we need to create a redelk user account
if (grep "{{CREDS_redelk}}" $DOCKERENVFILE > /dev/null); then
    CREDS_redelk=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)

    echo "[*] Setting redelk password in elasticsearch" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{CREDS_redelk\}\}/${CREDS_redelk}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "[X] Could not set redelk ES password (Error Code: $ERROR)."
    fi

    echo "[*] Installing apache2-utils for setting htaccess" | tee -a $LOGFILE
    apt -y install apache2-utils >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "[X] Error installing apache2-utils package (Error Code: $ERROR)."
    fi

    echo "[*] Setting redelk password in htaccess" | tee -a $LOGFILE
    htpasswd -b -m mounts/nginx-config/htpasswd.users redelk ${CREDS_redelk} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "[X] Error setitng redelk password in htaccess (Error Code: $ERROR)."
    fi
else
    echo "[*] Redelk password in elasticsearch already defined - skipping" | tee -a $LOGFILE
    CREDS_redelk=$(grep -E ^CREDS_redelk= .env|awk -F\= '{print $2}')
fi

# check if we need to create a elastic user password
if (grep "{{ELASTIC_PASSWORD}}" $DOCKERENVFILE > /dev/null); then
    ELASTIC_PASSWORD=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)

    echo "[*] Setting elastic ES password in Docker template" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{ELASTIC_PASSWORD\}\}/${ELASTIC_PASSWORD}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "[X] Error setting elastic ES password in Docker template (Error Code: $ERROR)."
    fi

    echo "[*] Setting elastic ES password in redelk config.json" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{ELASTIC_PASSWORD\}\}/${ELASTIC_PASSWORD}/g" mounts/redelk-config/etc/redelk/config.json >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "[X] Error setting elastic ES password in redelk config.json (Error Code: $ERROR)."
    fi
    rm mounts/redelk-config/etc/redelk/config.json.bak
else
    echo "[*] Elastic ES password in docker tempalte already defined - skipping" | tee -a $LOGFILE
   ELASTIC_PASSWORD=$(grep -E ^ELASTIC_PASSWORD= .env|awk -F\= '{print $2}')
fi

KBN_XPACK_ENCRYPTEDSAVEDOBJECTS=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)
echo "[*] Setting Kibana encryption key" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{KBN_XPACK_ENCRYPTEDSAVEDOBJECTS\}\}/${KBN_XPACK_ENCRYPTEDSAVEDOBJECTS}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set Kibana encryption key (Error Code: $ERROR)."
fi

echo "[*] Adjusting memory settings for ES" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{ES_MEMORY\}\}/${ES_MEMORY}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not adjust ES memory settings (Error Code: $ERROR)."
fi

if [ ${WHATTOINSTALL} = "full" ]; then
    echo "[*] Adjusting memory settings for NEO4J" | tee -a $LOGFILE
    sed -E -i.bak3 "s/\{\{NEO4J_MEMORY\}\}/${NEO4J_MEMORY}/g" ${DOCKERENVFILE}
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "[X] Could not adjust ES memory settings (Error Code: $ERROR)."
    fi

    NEO4J_PASSWORD=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)
    echo "[*] Setting neo4j password" | tee -a $LOGFILE
    sed -E -i.bak "s/\{\{NEO4J_PASSWORD\}\}/${NEO4J_PASSWORD}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "[X] Could not set neo4j password (Error Code: $ERROR)."
    fi
fi

EXTERNAL_DOMAIN=$(cat ./mounts/redelk-config/etc/redelk/config.json | jq -r .external_domain)
echo "[*] Setting external domain name" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{EXTERNAL_DOMAIN\}\}/${EXTERNAL_DOMAIN}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set external domain name (Error Code: $ERROR)."
fi

LE_EMAIL=$(cat ./mounts/redelk-config/etc/redelk/config.json | jq -r .le_email)
echo "[*] Setting Let's Encrypt email" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{LE_EMAIL\}\}/${LE_EMAIL}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set Let's Encrypt email (Error Code: $ERROR)."
fi

# NGINX certificates config

CERTS_DIR_NGINX_LOCAL="./mounts/certbot/conf/live/${EXTERNAL_DOMAIN}"
CERTS_DIR_NGINX_CA_LOCAL="./mounts/certs/ca/"
TLS_NGINX_CRT_PATH="/etc/nginx/certs/fullchain.pem"
TLS_NGINX_KEY_PATH="/etc/nginx/certs/privkey.pem"
TLS_NGINX_CA_PATH="/etc/nginx/ca_certs/ca.crt"
echo "[*] Setting CERTS_DIR_NGINX_LOCAL" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{CERTS_DIR_NGINX_LOCAL\}\}/${CERTS_DIR_NGINX_LOCAL}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set CERTS_DIR_NGINX_LOCAL (Error Code: $ERROR)."
fi
echo "[*] Setting CERTS_DIR_NGINX_CA_LOCAL" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{CERTS_DIR_NGINX_CA_LOCAL\}\}/${CERTS_DIR_NGINX_CA_LOCAL}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set CERTS_DIR_NGINX_CA_LOCAL (Error Code: $ERROR)."
fi
echo "[*] Setting TLS_NGINX_CRT_PATH" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{TLS_NGINX_CRT_PATH\}\}/${TLS_NGINX_CRT_PATH}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set TLS_NGINX_CRT_PATH (Error Code: $ERROR)."
fi
echo "[*] Setting TLS_NGINX_KEY_PATH" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{TLS_NGINX_KEY_PATH\}\}/${TLS_NGINX_KEY_PATH}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set TLS_NGINX_KEY_PATH (Error Code: $ERROR)."
fi
echo "[*] Setting TLS_NGINX_CA_PATH" | tee -a $LOGFILE
sed -E -i.bak "s/\{\{TLS_NGINX_CA_PATH\}\}/${TLS_NGINX_CA_PATH}/g" ${DOCKERENVFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set TLS_NGINX_CA_PATH (Error Code: $ERROR)."
fi

echo "[*] Setting permissions on logstash configs" | tee -a $LOGFILE
chown -R 1000 ./mounts/logstash-config/* >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set permissions on logsatsh configs (Error Code: $ERROR)."
fi

echo "[*] Setting permissions on redelk logs" | tee -a $LOGFILE
chown -R 1000 ./mounts/redelk-logs && chmod 664 ./mounts/redelk-logs/* >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set permissions on redelk logs (Error Code: $ERROR)."
fi

echo "[*] Setting permissions on Jupyter notebook work dir" | tee -a $LOGFILE
chown -R 1000 ./mounts/jupyter-workbooks >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set permissions on Jupyter notebook work dir (Error Code: $ERROR)."
fi

if [ $DRYRUN == "no" ]; then
  echo "[*] Running initial Let's Encrypt script" | tee -a $LOGFILE
  ./init-letsencrypt.sh # >>$LOGFILE 2>&1
  ERROR=$?
  if [ $ERROR -ne 0 ]; then
      echoerror "[X] Could not run initial Let's Encrypt script (Error Code: $ERROR)."
      #exit 1
  fi

  echo "[*] Building RedELK from $DOCKERCONFFILE file" | tee -a $LOGFILE
  docker-compose -f $DOCKERCONFFILE up --build -d # >>$LOGFILE 2>&1
  ERROR=$?
  if [ $ERROR -ne 0 ]; then
      echoerror "[X] Could not build RedELK using docker-compose file $DOCKERCONFFILE (Error Code: $ERROR)."
      exit 1
  fi
fi

grep "* ERROR " redelk-install.log
ERROR=$?
if [ $ERROR -eq 0 ]; then
    echo "[X] There were errors while running this installer. Manually check the log file $LOGFILE. Exiting now."
    exit 1
fi


echo "" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
if [ $DRYRUN == "no" ]; then
  echo " Done with base setup of RedELK on ELK server" | tee -a $LOGFILE
  echo " You can now login with on: " | tee -a $LOGFILE
  echo "   - Main RedELK Kibana interface on port 80 (default redelk:$CREDS_redelk)" | tee -a $LOGFILE
  if [ ${WHATTOINSTALL} != "limited" ]; then
      echo "   - Jupyter notebooks on /jupyter" | tee -a $LOGFILE
      echo "   - Neo4J Browser on /neo4jbrowser" | tee -a $LOGFILE
      echo "   - Neo4J using the BloodHound app on port 7687 (neo4j:BloodHound)" | tee -a $LOGFILE
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
  echo "You can now adapt the .env file and then run the installer again with 'full' or 'limited' options." | tee -a $LOGFILE
fi
echo "" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
