#!/usr/bin/env bash
#
# Part of RedELK
# Init script for RedELK elasticsearch image
#
# Authors:
#   - Outflank B.V. / Marc Smeets
#   - Lorenzo Bernardi (@fastlorenzo)
#

if [[ ! -f $CERTS_DIR_ES/bundle.zip ]]; then
  echo "[*] Generating RedELK certificates"
  bin/elasticsearch-certutil cert --silent --pem --in /usr/share/elasticsearch/config/instances.yml -out $CERTS_DIR_ES/bundle.zip;
  unzip $CERTS_DIR_ES/bundle.zip -d $CERTS_DIR_ES;
fi;
if [[ ! -f $CERTS_DIR_ES/redelk-logstash/redelk-logstash.pkcs8.key ]]; then
  echo "[*] Converting logstash private key to pkcs8"
  openssl pkcs8 -in $CERTS_DIR_ES/redelk-logstash/redelk-logstash.key -topk8 -nocrypt -out $CERTS_DIR_ES/redelk-logstash/redelk-logstash.pkcs8.key
fi
chown -R 1000:0 $CERTS_DIR_ES
chmod u+rwX,g+rX,o-rwx $CERTS_DIR_ES
READY=1
while [[ $READY -ne 0 ]]; do
  echo "[*] Waiting for Elasticsearch to be up"
  curl $ES_URL/ --cacert $CERTS_DIR_ES/ca/ca.crt -s -u elastic:$ELASTIC_PASSWORD >/dev/null 2>&1
  READY=$?
  sleep 1
done

echo "[*] Setting password for user kibana_system"
curl -XPOST $ES_URL/_security/user/kibana_system/_password --cacert $CERTS_DIR_ES/ca/ca.crt -s -uelastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' --data "{\"password\":\"$CREDS_kibana_system\"}"
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Error setting password for user kibana_system (Error Code: $ERROR)."
fi

echo "[*] Setting password for user logstash_system"
curl -XPOST $ES_URL/_security/user/logstash_system/_password --cacert $CERTS_DIR_ES/ca/ca.crt -s -uelastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' --data "{\"password\":\"$CREDS_logstash_system\"}"
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Error setting password for user logstash_system (Error Code: $ERROR)."
fi

echo "[*] Creating redelk_ingest role"
curl -XPOST  $ES_URL/_security/role/redelk_ingest --cacert $CERTS_DIR_ES/ca/ca.crt -s -uelastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' --data-binary @- << EOF
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
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Error creating redelk_ingest role (Error Code: $ERROR)."
fi

echo "[*] Creating redelk_ingest user"
curl -XPOST  $ES_URL/_security/user/redelk_ingest --cacert $CERTS_DIR_ES/ca/ca.crt -s -uelastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' --data-binary @- << EOF
{
  "password": "$CREDS_redelk_ingest",
  "roles": ["redelk_ingest"],
  "full_name": "RedELK Ingest"
}
EOF
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Error creating redelk_ingest user (Error Code: $ERROR)."
fi

echo "[*] Creating redelk user"
curl -XPOST  $ES_URL/_security/user/redelk --cacert $CERTS_DIR_ES/ca/ca.crt -s -uelastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' --data-binary @- << EOF
{
  "password": "$CREDS_redelk",
  "roles": ["superuser"],
  "full_name": "RedELK Operator"
}
EOF
ERROR=$?
if [ $ERROR -ne 0 ]; then
    echoerror "[X] Error creating redelk user (Error Code: $ERROR)."
fi
