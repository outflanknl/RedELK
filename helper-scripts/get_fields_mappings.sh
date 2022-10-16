#!/bin/bash
# Part of RedELK
# Helper script to read out Kibana settings and dump the field names, EStype and Kibana type in a Markup table

function QueryES() {
    curl --user ${KIBANACREDS} -k -s -X GET "https://${KIBANAIP}:5601/api/saved_objects/index-pattern/${type}" -H 'kbn-xsrf: true' | jq -r '(.attributes.fields | fromjson)[] | select(.name | startswith("_")|not)| select(.name | startswith("@")|not)|"| " + .name + "   | " + (.esTypes|tostring) + "   | " + .type + "   |        |"'| tr -d '["]' >> $outfile
}

echo "[*] Trying to auto determine the IP address of the redelk-kibana docker container."
KIBANAIP=`docker inspect redelk-kibana|grep \"IPAddress\"\:|grep -v '\"\"'|tr -d " ",|awk -F\: '{print $2}'|tr -d \"`
echo "[*] Found IP address: $KIBANAIP"
echo "[*] Trying to auto determine the credentials for accessing Kibana."
KIBANACREDS="redelk:`grep CREDS_redelk=  ../elkserver/.env|awk -F\= '{print $2}'`"
echo "[*] Found credentials: $KIBANACREDS"

# index redirtraffic
type=redirtraffic
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname                   |   ES type    |   Kibana type  |   Comment                                     | " > $outfile
echo "| ----------------------------- | ------------ | -------------- | --------------------------------------------- | " >> $outfile
QueryES

# index rtops
type=rtops
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname                   |   ES type    |   Kibana type  |   Comment                                     | " > $outfile
echo "| ----------------------------- | ------------ | -------------- | --------------------------------------------- | " >> $outfile
QueryES

# index bluecheck
type=bluecheck
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname                   |   ES type    |   Kibana type  |   Comment                                     | " > $outfile
echo "| ----------------------------- | ------------ | -------------- | --------------------------------------------- | " >> $outfile
QueryES

# index credentials
type=credentials
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname                   |   ES type    |   Kibana type  |   Comment                                     | " > $outfile
echo "| ----------------------------- | ------------ | -------------- | --------------------------------------------- | " >> $outfile
QueryES

# index bluecheck
type=bluecheck
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname                   |   ES type    |   Kibana type  |   Comment                                     | " > $outfile
echo "| ----------------------------- | ------------ | -------------- | --------------------------------------------- | " >> $outfile
QueryES

# index email
type=email
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname                   |   ES type    |   Kibana type  |   Comment                                     | " > $outfile
echo "| ----------------------------- | ------------ | -------------- | --------------------------------------------- | " >> $outfile
QueryES

# index implantsdb
type=implantsdb
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname                   |   ES type    |   Kibana type  |   Comment                                     | " > $outfile
echo "| ----------------------------- | ------------ | -------------- | --------------------------------------------- | " >> $outfile
QueryES
