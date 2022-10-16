#!/bin/sh
#
# Part of RedELK
# Script to remove RedELK on elkserver
#
# Author: Outflank B.V. / Marc Smeets
#


echo ""
echo ""
echo "        !! USE AT OWN RISK !!         "
echo ""
echo " This script will rudimentarily remove"
echo " all kinds of things on your system."
echo ""
echo " Check the code before running. "
echo ""
echo " 5 sec to abort"
echo ""
sleep 5

echo "[-] Stopping all RedELK docker containers"
for i in $(docker ps -a|grep redelk|awk '{print $1}'); do docker stop $i; done

echo "[-] removing all RedELK docker containers"
for i in $(docker ps -a |grep redelk|awk '{print $1}'); do docker rm -f $i; done

echo "[-] Removing all RedELK docker images"
for i in $(docker image ls |grep redelk|awk '{print $3}'); do docker rmi -f $i; done

echo "[-] Removing all RedELK docker volumes"
for i in $(docker volume ls |grep redelk|awk '{print $2}'); do docker volume rm -f $i; done

echo "[-] Removing all not used docker networks"
docker network prune -f

echo "[*] Done. You can manually remove this directory as well if you like."
echo ""
