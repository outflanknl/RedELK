#/bin/bash
# Part of RedELK
#
# Watchdog script to check if services are still running
#
# Author: Outflank B.V. / Marc Smeets 
# 

#check if jupyter notebook is up
ps aux | egrep -i "(jupyter)"|grep -v "grep -E" > /dev/null 2>&1
ERROR=$?
if [ $ERROR -ne 0 ]; then
   echo "`date`  Jupyter Watchdog kicked in" >> /var/log/redelk/watchdog_services.log
   docker run -d -p 127.0.0.1:8888:8888 -v /usr/share/redelk/jupyter:/home/jovyan/work  jupyter/scipy-notebook start-notebook.sh --NotebookApp.token='' --NotebookApp.password='' --NotebookApp.allow_remote_access='True' --NotebookApp.allow_origin='*'
fi
