#!/bin/bash
#
# Part of RedELK
# Script to install RedELK on ELK server
#
# Author: Outflank B.V. / Marc Smeets
#

LOGFILE="redelk-install-doc.log"
INSTALLER="RedELK elkserver installer"
CWD=`pwd`
ELKVERSION="7.9.2"

printf "`date +'%b %e %R'` $INSTALLER - Starting installer\n" > $LOGFILE 2>&1
echo ""
echo ""
echo ""
echo "    ____            _  _____  _      _  __"
echo "   |  _ \  ___   __| || ____|| |    | |/ /"
echo "   | |_) |/ _ \ / _\` ||  _|  | |    | ' / "
echo "   |  _ <|  __/| (_| || |___ | |___ | . \ "
echo "   |_| \__\___| \____||_____||_____||_|\_\\"
echo ""
echo ""
echo "      DOCKER DOCKER DOCKER DOCKER DOCKER    "
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
    WHATTOINSTALL=limited
else
    echo "No 'limited' parameter found. Going for the full RedELK installation including: " | tee -a $LOGFILE
    echo "- RedELK"
    echo "- Jupyter notebooks"
    echo "- BloodHound / Neo4j"
    echo ""
    echo "5 Seconds to abort"
    echo ""
    sleep 5
    WHATTOINSTALL=full
fi

echoerror() {
    printf "`date +'%b %e %R'` $INSTALLER - ${RC} * ERROR ${EC}: $@\n" >> $LOGFILE 2>&1
}

install_docker(){
    echo "[*] Installing docker"
    if [ -x "$(command -v apt)"]; then
        echo "[*] apt based system found, trying to install docker via apt" | tee -a $LOGFILE
        apt -y install docker >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echoerror "[X] Could not install docker via apt (Error Code: $ERROR)."
            exit 1
        fi
    else
        echo "[*] Trying to install docker via Docke convenience script" | tee -a $LOGFILE
        curl -fsSL get.docker.com -o get-docker.sh >> $LOGFILE 2>&1
        chmod +x get-docker.sh >> $LOGFILE 2>&1
        ./get-docker.sh >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echo "[X] Docker could not be installed." | tee -a $LOGFILE
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
            echoerror "[X] Could not install docker-compose via apt (Error Code: $ERROR)."
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
        echoerror "System is not Debian/APT based. Not supported. Quitting."
        exit 1
    fi

    # Check if curl is installed
    if [ ! -x "$(command -v curl)" ]; then
        echo "[X] Curl is not installed. Please fix manually. Exiting" | tee -a $LOGFILE
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
    if [ $ERROR -ne 0 ]; then
        echo "[X] Error getting memory configuration of this host. Exiting." | tee -a $LOGFILE
        exit 1
    fi

    # check for full or limited install
    if [ ${WHATTOINSTALL} = "limited" ]; then
        DOCKERCONFFILE="docker-compose-limited.yml"
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
        DOCKERCONFFILE="docker-compose.yml"
        if [ ${AVAILABLE_MEMORY} -le 7999 ]; then
            echo "[X] Not enough memory for full install (less than 8GB). Quitting." | tee -a $LOGFILE
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

echo "[*] Adjusting memory settings for ES" | tee -a $LOGFILE
sed -E -i.bak "s/Xms1g/Xms${ES_MEMORY}/g" ./docker/${DOCKERCONFFILE} >> $LOGFILE 2>&1 && sed -E -i.bak2 "s/Xmx1g/Xmx${ES_MEMORY}/g" ./docker/${DOCKERCONFFILE} >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not adjust ES memory settings (Error Code: $ERROR)."
fi

if [ ${WHATTOINSTALL} = "full" ]; then
    echo "[*] Adjusting memory settings for NEO4J" | tee -a $LOGFILE
    sed -E -i.bak3 "s/_size=1G/_size=${NEO4J_MEMORY}/g" ./docker/${DOCKERCONFFILE}
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "[X] Could not adjust ES memory settings (Error Code: $ERROR)."
    fi
fi

echo "[*] Setting permissions on certs for logstash" | tee -a $LOGFILE
chown 1000 ./docker/redelk-logstash/live/config/certs/elkserver.crt && chown 1000 ./docker/redelk-logstash/live/config/certs/elkserver.key >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set permissions on certs for logsatsh (Error Code: $ERROR)."
fi

echo "[*] Setting permissions on redelk logs" | tee -a $LOGFILE
chown 1000 ./docker/redelk-base/live/redelklogs/* && chmod 664 ./docker/redelk-base/live/redelklogs/* >> $LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not set permissions on redelk logs (Error Code: $ERROR)."
fi


echo "[*] Building RedELK from $DOCKERCONFFILE file" | tee -a $LOGFILE
docker-compose -f ./docker/$DOCKERCONFFILE up --build -d # >>$LOGFILE 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Could not build RedELK using docker-compose file $DOCKERCONFFILE (Error Code: $ERROR)."
    exit 1
fi

grep "* ERROR " redelk-install-doc.log
ERROR=$?
if [ $ERROR -eq 0 ]; then
    echo "[X] There were errors while running this installer. Manually check the log file $LOGFILE. Exiting now."
    exit 1
fi


echo "" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
echo " Done with base setup of RedELK on ELK server" | tee -a $LOGFILE
echo " You can now login with on: " | tee -a $LOGFILE
echo "   - Main RedELK Kibana interface on port 80 (default redelk:redelk)" | tee -a $LOGFILE
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
echo "   - adjust the ./docker/redelk-base/live/config/etc/cron.d/redelk file to include your teamservers" | tee -a $LOGFILE
echo "   - adjust all config files in ./docker/redelk-base/live/config/etc/redelk to include your specifics like VT API, email server details, etc" | tee -a $LOGFILE
echo "   - reset default nginx credentials by adjusting the file ./docker/redelk-nginx/live/config/htpasswd.users. You can use the htpasswd tool from apache2-utils package" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE
