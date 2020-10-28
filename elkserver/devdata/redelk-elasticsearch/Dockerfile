#
# Part of RedELK
# Dockerfile for RedELK elasticsearch image
#
# Author: Outflank B.V. / Marc Smeets
# Contributor: Lorenzo Bernardi / @fastlorenzo
#

FROM docker.elastic.co/elasticsearch/elasticsearch:7.9.2
LABEL maintainer="Outflank B.V. / Marc Smeets"
LABEL description="RedELK Elasticsearch Notebooks"

RUN yum install openssl -y

COPY --chown=elasticsearch:elasticsearch ./redelkinstalldata/init-elasticsearch.sh /usr/local/bin/init-elasticsearch.sh
COPY --chown=elasticsearch:elasticsearch ./redelkinstalldata/redelk-entrypoint.sh /usr/local/bin/redelk-entrypoint.sh
COPY --chown=elasticsearch:elasticsearch ./redelkinstalldata/instances.yml /usr/share/elasticsearch/config/instances.yml

ENTRYPOINT ["/tini", "--", "/usr/local/bin/redelk-entrypoint.sh"]
CMD ["eswrapper"]