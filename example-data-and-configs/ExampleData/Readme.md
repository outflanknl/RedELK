# Example data #
The files in this directory are the logs from the lab used in the blog post [RedELK Part 3](https://outflank.nl/blog/2020/04/07/redelk-part-3-achieving-operational-oversight/).

You can use the files in this directory to play along with the blog post, and to have some example data in your RedELK installation.

There are two ways of importing the data. Both ways require that you have got a RedELK server up and running (you successfully ran the install-redelk.sh installer).

WARNING - both methods are not fully tested. Create an issue when this goes wrong and you aren't able to troubleshoot yourself.

## Method 1 - import ES data
You need the files `redelk_elasticsearch-backup.tgz` and `cslogs.tgz`.

On the RedELK server run:
* Extract the cslogs.tgz to /var/www/html
* Extract the redelk_elasticsearch-backup.tgz to /
* echo "path.repo: [\"/elasticsearch-backup\"]" >> /etc/elasticsearch/elasticsearch.yml
* service elasticsearch restart
* Register the new repository in ES - answer should be {"acknowledged":true}

`curl -X PUT "localhost:9200/_snapshot/redelkdemo" -H 'Content-Type: application/json' -d'
{
   "type": "fs",
   "settings": {
       "compress" : true,
       "location": "/elasticsearch-backup"
   }
}'`
* Start restore - can take some time but answer should be {"acknowledged":true}
`curl -X POST "localhost:9200/_snapshot/redelkdemo/snapshot-number-one/_restore" -H 'Content-Type: application/json' -d'
{
  "indices": "rtops-*,redirtraffic-*,beacondb",
  "ignore_unavailable": true,
  "include_global_state": true
}'`


## Method 2 - using filebeat
In this method you will need the files `c2server1_cobaltstrike.zip`, `c2server2_cobaltstrike.zip`, `redira1_access-redelk.log` and `redirb1_haproxy.log`.
You will also need to have the same offensive systems created - or be more experienced with filebeat and know how to import data using the right tags.

Place files on systems as following:
* On redira1: `redira1_access-redelk.log` as `/var/log/apache2/access-redelk.log`
* On redirb1: `redirb1_haproxy.log` as `/var/log/haproxy.log`
* On c2server1: extract `c2server1_cobaltstrike.zip` to `/root/cobaltstrike`
* On c2server2: extract `c2server2_cobaltstrike.zip` to `/root/cobaltstrike`
* Run each RedELK installer script as would normally do
