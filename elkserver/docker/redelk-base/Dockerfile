#
# Part of RedELK
# Dockerfile for RedELK base image
#
# Author: Outflank B.V. / Marc Smeets
#

FROM phusion/baseimage:18.04-1.0.0
LABEL maintainer="Outflank B.V. / Marc Smeets"
LABEL description="RedELK Base Image"

# Copy relevant install data
RUN mkdir -p /root/redelkinstalldata/
COPY ./redelkinstalldata/ /root/redelkinstalldata/

# Init script
RUN mkdir -p /etc/my_init.d
RUN cp /root/redelkinstalldata/42_redelk-base-docker-init.sh /etc/my_init.d/42_redelk-base-docker-init.sh
RUN chmod +x /etc/my_init.d/42_redelk-base-docker-init.sh

# copy relevant scripts to redelk script working dir
RUN mkdir -p /usr/share/redelk/bin
RUN cp -r /root/redelkinstalldata/scripts/* /usr/share/redelk/bin/
RUN chmod -R 775 /usr/share/redelk/bin/*

# Install required packages and python requirements
RUN DEBIAN_FRONTEND=noninteractive apt-get -qq update > /dev/null
RUN DEBIAN_FRONTEND=noninteractive apt-get -qq -y install rsync python3-pil python3-pip > /dev/null
RUN mkdir -p /usr/share/redelk/bin
RUN cp -r /root/redelkinstalldata/scripts/ /usr/share/redelk/bin/
RUN pip3 install -q -r /usr/share/redelk/bin/Chameleon/requirements.txt > /dev/null
RUN pip3 install -q elasticsearch pymsteams > /dev/null

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

CMD ["/sbin/my_init"]