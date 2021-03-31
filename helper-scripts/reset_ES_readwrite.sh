#!/bin/bash
echo "Got ya, YOLO removing read only"

source /root/elkserver/.env
docker exec -it redelk-elasticsearch curl --user redelk:${CREDS_redelk} -k -X PUT "https://localhost:9200/_all/_settings" -H 'Content-Type: application/json' -d'{ "index.blocks.read_only_allow_delete" : false } }'
