#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
from modules.helpers import get_initial_alarm_result, es, get_value, raw_search, get_last_run
from elasticsearch import helpers
from config import enrich
import traceback
import logging
import requests
import datetime

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
        ret = get_initial_alarm_result()
        ret['info'] = info

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
            iplist_es = []
            for ip in iplist_tor:
                if ip != '':
                    iplist_es.append('%s/32' % ip)

            # 2. Delete existing nodes
            es.delete_by_query(index='redelk-*', body={'query': {'bool': {'filter': {'term': {'iplist.name': 'tor'}}}}})

            # 3. Add new data (index=l['_index'], id=l['_id'], body={'doc': l['_source']})
            now = datetime.datetime.utcnow().isoformat()
            iplist_doc = [
                {
                    '_source': {
                        'iplist': {
                            'ip': ip,
                            'source': 'enrich',
                            'name': 'tor'
                        },
                        '@timestamp': now
                    }
                }
                for ip in iplist_es
            ]

            helpers.bulk(es, iplist_doc, index='redelk-iplist-tor')
            self.logger.info('Successfuly updated iplist tor exit nodes')
            return(iplist_tor)

        except Exception as e:
            self.logger.error('Failed updating iplist tor exit nodes: %s' % e)
            self.logger.exception(e)
            return(False)

    def enrich_tor(self, iplist):
        # Get all lines in redirtraffic that have not been enriched with 'enrich_iplist' or 'enrich_tor'
        # Filter documents that were before the last run time of enrich_iplist (to avoid race condition)
        iplist_lastrun = get_last_run('enrich_iplists')
        query = {
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {
                    'filter': [
                        {
                            'range':  {
                                '@timestamp': {
                                    'lte': iplist_lastrun.isoformat()
                                }
                            }
                        }
                    ],
                    'must_not': [
                        {'match': {'tags': info['submodule']}}
                    ]
                }
            }
        }
        res = raw_search(query, index='redirtraffic-*')
        if res is None:
            notEnriched = []
        else:
            notEnriched = res['hits']['hits']

        # For each IP, check if it is in tor exit node data
        hits = []
        for ne in notEnriched:
            ip = get_value('_source.source.ip', ne)
            if ip in iplist:
                hits.append(ne)

        return(hits)

    def get_es_tor_exitnodes(self):
        q = {'query': {'bool': {'filter': {'term': {'iplist.name': 'tor'}}}}}
        res = raw_search(q, index='redelk-*')

        if not res:
            return []

        iplist = []
        for ipdoc in res['hits']['hits']:
            ip = get_value('_source.iplist.ip', ipdoc)
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
                                "iplist.name": "tor"
                            }
                        }
                    ]
                }
            }
        }

        res = raw_search(q, index='redelk-*')

        self.logger.debug(res)

        # Return the latest hit or False if not found
        if res and len(res['hits']['hits']) > 0:
            dt_str = get_value('_source.@timestamp', res['hits']['hits'][0])
            dt = datetime.datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S.%f')
            return(dt)
        else:
            return(datetime.datetime.fromtimestamp(0))
