#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
from modules.helpers import *
from elasticsearch import helpers
from config import enrich
from time import time
import traceback
import logging
import requests
import copy
import datetime
import uuid

info = {
    'version': 0.1,
    'name': 'Enrich redirtraffic lines with tor exit nodes',
    'alarmmsg': '',
    'description': 'This script enriches redirtraffic documents with data from tor exit nodes',
    'type': 'redelk_enrich',
    'submodule': 'enrich_tor'
}


class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        self.tor_exitlist_url = 'https://check.torproject.org/torbulkexitlist'
        # Re-query after 1 hour by default
        self.cache = enrich[info['submodule']]['cache'] if info['submodule'] in enrich else 3600

    def run(self):
        ret = initial_alarm_result
        ret['info'] = info
        # Keep fields, mutations and groupby empty as we don't need them for an enrich script
        ret['fields'] = []
        ret['groupby'] = []
        ret['mutations'] = []

        try:
            # First check the last sync time
            now = datetime.datetime.utcnow()
            last_sync = self.get_last_sync()
            ival = datetime.timedelta(seconds=self.cache)
            last_sync_max = now - ival

            should_sync = last_sync < last_sync_max

            if should_sync:
                self.logger.info('Tor cache expired, fetching latest exit nodes list. Will skip enrichment (will be run next time)')
                iplist = self.sync_tor_exitnodes()
            else:
                iplist = self.get_es_tor_exitnodes()

            if iplist:
                hits = self.enrich_tor(iplist)
                ret['hits']['hits'] = hits
                ret['hits']['total'] = len(hits)
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            self.logger.exception(e)
            pass
        self.logger.info('finished running module. result: %s hits' % ret['hits']['total'])
        return(ret)

    def sync_tor_exitnodes(self):
        try:
            # 1. Get tor exit nodes
            r = requests.get(self.tor_exitlist_url)
            iplist_tor = r.text.split('\n')
            iplist_tor.remove('')

            # 2. Delete existing nodes
            es.delete_by_query(index='iplist-*', body={'query':{'bool':{'filter':{'term':{'list':'tor'}}}}})

            # 3. Add new data (index=l['_index'], id=l['_id'], body={'doc': l['_source']})
            now = datetime.datetime.utcnow().isoformat()
            iplist_docs = [
                {
                    "_id": uuid.uuid4(),
                    "_source": {
                        "ip": ip,
                        "source": "enrich",
                        "@timestamp": now,
                        "last_updated": now,
                        "list": "tor"
                    }
                }
                for ip in iplist_tor
            ]
            helpers.bulk(es, iplist_docs, index='iplist-tor')
            self.logger.info('Successfuly updated iplist tor exit nodes')
            return(iplist_tor)

        except Exception as e:
            self.logger.error('Failed updating iplist tor exit nodes: %s' % e)
            self.logger.exception(e)
            return(False)

    def enrich_tor(self, iplist):
        # Get all lines in redirtraffic that have not been enriched with 'enrich_iplist' or 'enrich_tor'
        query = 'NOT tags:%s AND NOT tags:enrich_iplist' % info['submodule']
        notEnriched = getQuery(query, size=10000, index='redirtraffic-*')

        # For each IP, check if it is in tor exit node data
        hits = []
        for ne in notEnriched:
            ip = getValue('_source.source.ip', ne)
            if ip in iplist:
                hits.append(ne)

        return(hits)

    def get_es_tor_exitnodes(self):
        q = {'query':{'bool':{'filter':{'term':{'list':'tor'}}}}}
        res = rawSearch(q, index='iplist-*')

        if not res:
            return []

        iplist = []
        for ipdoc in res['hits']['hits']:
            ip = getValue('_source.ip', ipdoc)
            iplist.append(ip)

        return(iplist)

    def get_last_sync(self):
        # Get greynoise data from ES if less than 1 day old
        q = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "term": {
                                "list": "tor"
                            }
                        }
                    ]
                }
            }
        }

        res = rawSearch(q, index='iplist-*')

        self.logger.debug(res)

        # Return the latest hit or False if not found
        if res and len(res['hits']['hits']) > 0:
            dt_str = getValue('_source.@timestamp', res['hits']['hits'][0])
            dt = datetime.datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S.%f')
            return(dt)
        else:
            return(datetime.datetime.fromtimestamp(0))
