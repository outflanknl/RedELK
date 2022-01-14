#
# Part of RedELK
# Dockerfile for RedELK elasticsearch image
#
# Authors:
# - Outflank B.V. / Marc Smeets
# - Lorenzo Bernardi
#

FROM docker.elastic.co/elasticsearch/elasticsearch:7.16.3
LABEL maintainer="Outflank B.V. / Marc Smeets"
LABEL description="RedELK Elasticsearch"

RUN apt-get install -y openssl

COPY --chown=elasticsearch:elasticsearch ./redelkinstalldata/init-elasticsearch.sh /usr/local/bin/init-elasticsearch.sh
COPY --chown=elasticsearch:elasticsearch ./redelkinstalldata/redelk-entrypoint.sh /usr/local/bin/redelk-entrypoint.sh
COPY --chown=elasticsearch:elasticsearch ./redelkinstalldata/instances.yml /usr/share/elasticsearch/config/instances.yml

RUN chmod 755 /usr/local/bin/init-elasticsearch.sh /usr/local/bin/redelk-entrypoint.sh

ENTRYPOINT ["/bin/tini", "--", "/usr/local/bin/redelk-entrypoint.sh"]
CMD ["eswrapper"]
