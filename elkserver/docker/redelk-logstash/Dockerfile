#
# Part of RedELK
# Dockerfile for RedELK Logstash image
#
# Author: Outflank B.V. / Marc Smeets
#

FROM docker.elastic.co/logstash/logstash:7.9.2
LABEL maintainer="Outflank B.V. / Marc Smeets"
LABEL description="RedELK Logstash"

# Create relevant directories
RUN mkdir -p /usr/share/logstash/redelk-main/conf.d
RUN mkdir -p /usr/share/logstash/redelk-main/certs

# Move files to proper locations
COPY --chown=logstash:logstash ./redelkinstalldata/config/pipelines.yml /usr/share/logstash/config/pipelines.yml
COPY --chown=logstash:logstash ./redelkinstalldata/redelk-main/conf.d/. /usr/share/logstash/redelk-main/conf.d/
COPY --chown=logstash:logstash ./redelkinstalldata/redelk-main/scripts/. /usr/share/logstash/redelk-main/scripts/
