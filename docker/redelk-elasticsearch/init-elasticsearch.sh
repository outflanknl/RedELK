#!/usr/bin/env bash

if [[ ! -f $CERTS_DIR/bundle.zip ]]; then
  echo "Generating RedELK certificates"
  bin/elasticsearch-certutil cert --silent --pem --in /usr/share/elasticsearch/config/instances.yml -out $CERTS_DIR/bundle.zip;
  unzip $CERTS_DIR/bundle.zip -d $CERTS_DIR;
fi;
chown -R 1000:0 $CERTS_DIR

READY=1
while [[ $READY -ne 0 ]]; do
  echo "Waiting for Elasticsearch to be up"
  curl $ES_URL/ --cacert $CERTS_DIR/ca/ca.crt -s -u elastic:$ELASTIC_PASSWORD >/dev/null 2>&1
  READY=$?
  sleep 1
done

echo "[ ] Setting password for user kibana_system"
curl -XPOST $ES_URL/_security/user/kibana_system/_password --cacert $CERTS_DIR/ca/ca.crt -s -uelastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' --data "{\"password\":\"$CREDS_kibana_system\"}"

echo "[ ] Setting password for user logstash_system"
curl -XPOST $ES_URL/_security/user/logstash_system/_password --cacert $CERTS_DIR/ca/ca.crt -s -uelastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' --data "{\"password\":\"$CREDS_logstash_system\"}"

echo "[ ] Creating redelk_ingest role"
curl -XPOST  $ES_URL/_security/role/redelk_ingest --cacert $CERTS_DIR/ca/ca.crt -s -uelastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' --data-binary @- << EOF
{
  "cluster": ["monitor","cluster:admin/xpack/monitoring/bulk","manage_ilm"],
  "indices": [
    {
      "names": ["rtops*","redirtraffic*","credentials-*","bluecheck-*","email-*","implantsdb","auditbeat*","filebeat*","packetbeat*","apm*","heartbeat*","nagioscheckbeat*","metricbeat*"],
      "privileges": ["create","read","write","monitor","index","manage","delete","manage_ilm"]
    }
  ],
  "run_as":[]
}
EOF

echo "[ ] Creating redelk_ingest user"
curl -XPOST  $ES_URL/_security/user/redelk_ingest --cacert $CERTS_DIR/ca/ca.crt -s -uelastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' --data-binary @- << EOF
{
  "password": "$CREDS_redelk_ingest",
  "roles": ["redelk_ingest"],
  "full_name": "RedELK Ingest"
}
EOF
