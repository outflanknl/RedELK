#!/bin/bash
# Part of RedELK 
# Helper script to read out Kibana settings and dump the field names, EStype and Kibana type in a Markup table


# index redirtraffic
type=redirtraffic
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname  |  ES field type   | Kibana field type    |  Comment  |" > $outfile
echo "| --- | --- | --- | --- |" >> $outfile
curl -s -X GET "localhost:5601/api/saved_objects/index-pattern/${type}" -H 'kbn-xsrf: true' | jq -r '(.attributes.fields | fromjson)[] | select(.name | startswith("_")|not)| select(.name | startswith("@")|not)|"|   " + .name + "   |   " + (.esTypes|tostring) + "   |   " + .type + "   |        |"'| tr -d '["]' >> $outfile


# index rtops
type=rtops
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname  |  ES field type   | Kibana field type    |  Comment  |" > $outfile
echo "| --- | --- | --- | --- |" >> $outfile
curl -s -X GET "localhost:5601/api/saved_objects/index-pattern/${type}" -H 'kbn-xsrf: true' | jq -r '(.attributes.fields | fromjson)[] | select(.name | startswith("_")|not)| select(.name | startswith(    "@")|not)|"|   " + .name + "   |   " + (.esTypes|tostring) + "   |   " + .type + "   |        |"'| tr -d '["]' >> $outfile

# index bluecheck
type=bluecheck
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname  |  ES field type   | Kibana field type    |  Comment  |" > $outfile
echo "| --- | --- | --- | --- |" >> $outfile
curl -s -X GET "localhost:5601/api/saved_objects/index-pattern/${type}" -H 'kbn-xsrf: true' | jq -r '(.attributes.fields | fromjson)[] | select(.name | startswith("_")|not)| select(.name | startswith(    "@")|not)|"|   " + .name + "   |   " + (.esTypes|tostring) + "   |   " + .type + "   |        |"'| tr -d '["]' >> $outfile

# index credentials
type=credentials
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname  |  ES field type   | Kibana field type    |  Comment  |" > $outfile
echo "| --- | --- | --- | --- |" >> $outfile
curl -s -X GET "localhost:5601/api/saved_objects/index-pattern/${type}" -H 'kbn-xsrf: true' | jq -r '(.attributes.fields | fromjson)[] | select(.name | startswith("_")|not)| select(.name | startswith(    "@")|not)|"|   " + .name + "   |   " + (.esTypes|tostring) + "   |   " + .type + "   |        |"'| tr -d '["]' >> $outfile

# index bluecheck
type=bluecheck
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname  |  ES field type   | Kibana field type    |  Comment  |" > $outfile
echo "| --- | --- | --- | --- |" >> $outfile
curl -s -X GET "localhost:5601/api/saved_objects/index-pattern/${type}" -H 'kbn-xsrf: true' | jq -r '(.attributes.fields | fromjson)[] | select(.name | startswith("_")|not)| select(.name | startswith(    "@")|not)|"|   " + .name + "   |   " + (.esTypes|tostring) + "   |   " + .type + "   |        |"'| tr -d '["]' >> $outfile

# index email
type=email
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname  |  ES field type   | Kibana field type    |  Comment  |" > $outfile
echo "| --- | --- | --- | --- |" >> $outfile
curl -s -X GET "localhost:5601/api/saved_objects/index-pattern/${type}" -H 'kbn-xsrf: true' | jq -r '(.attributes.fields | fromjson)[] | select(.name | startswith("_")|not)| select(.name | startswith(    "@")|not)|"|   " + .name + "   |   " + (.esTypes|tostring) + "   |   " + .type + "   |        |"'| tr -d '["]' >> $outfile

# index implantsdb
type=implantsdb
outfile=redelk_fieldnames_${type}.md
echo "|   Fieldname  |  ES field type   | Kibana field type    |  Comment  |" > $outfile
echo "| --- | --- | --- | --- |" >> $outfile
curl -s -X GET "localhost:5601/api/saved_objects/index-pattern/${type}" -H 'kbn-xsrf: true' | jq -r '(.attributes.fields | fromjson)[] | select(.name | startswith("_")|not)| select(.name | startswith(    "@")|not)|"|   " + .name + "   |   " + (.esTypes|tostring) + "   |   " + .type + "   |        |"'| tr -d '["]' >> $outfile
