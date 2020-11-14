#
# Part of RedELK
# Dockerfile for RedELK Kibana image
#
# Authors:
# - Outflank B.V. / Marc Smeets
# - Lorenzo Bernardi
#

FROM docker.elastic.co/kibana/kibana:7.10.0
LABEL maintainer="Outflank B.V. / Marc Smeets"
LABEL description="RedELK Kibana"

RUN /usr/share/kibana/bin/kibana-plugin install https:/github.com/fastlorenzo/redelk-kibana-app/releases/download/v0.1-beta.3/redelk-v0.1-beta.3.zip
