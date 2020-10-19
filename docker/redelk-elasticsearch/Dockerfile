FROM docker.elastic.co/elasticsearch/elasticsearch:7.9.2

RUN yum install openssl -y

COPY init-elasticsearch.sh /usr/local/bin/init-elasticsearch.sh
COPY redelk-entrypoint.sh /usr/local/bin/redelk-entrypoint.sh
COPY instances.yml /usr/share/elasticsearch/config/instances.yml

ENV ES_URL https://localhost:9200
ENV CERTS_DIR /usr/share/elasticsearch/config/certificates

ENTRYPOINT ["/tini", "--", "/usr/local/bin/redelk-entrypoint.sh"]
CMD ["eswrapper"]
