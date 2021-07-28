#
# Part of RedELK
# Dockerfile for RedELK base image
#
# Authors:
# - Outflank B.V. / Marc Smeets
# - Lorenzo Bernardi
#

FROM phusion/baseimage:18.04-1.0.0
LABEL maintainer="Outflank B.V. / Marc Smeets"
LABEL description="RedELK Base"

# Install required packages
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install rsync python3-pil python3-pip python3-setuptools && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy relevant install data
RUN mkdir -p /root/redelkinstalldata/
COPY ./redelkinstalldata/ /root/redelkinstalldata/

# Init script
RUN mkdir -p /etc/my_init.d && \
    cp /root/redelkinstalldata/42_redelk-base-docker-init.sh /etc/my_init.d/42_redelk-base-docker-init.sh && \
    chmod +x /etc/my_init.d/42_redelk-base-docker-init.sh

# copy relevant scripts to redelk script working dir
RUN mkdir -p /usr/share/redelk/bin && \
    cp -r /root/redelkinstalldata/scripts/* /usr/share/redelk/bin/ && \
    chmod -R 775 /usr/share/redelk/bin/*

# Install python requirements
RUN pip3 install -r /usr/share/redelk/bin/Chameleon/requirements.txt && \
    pip3 install -r /usr/share/redelk/bin/requirements.txt

CMD ["/sbin/my_init"]
