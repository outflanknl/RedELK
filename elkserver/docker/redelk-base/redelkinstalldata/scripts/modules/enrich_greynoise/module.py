#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
from modules.helpers import get_initial_alarm_result, get_value, raw_search, es, get_last_run
from config import enrich
from time import time
import traceback
import logging
import requests
import copy

info = {
    'version': 0.1,
    'name': 'Enrich redirtraffic lines with greynoise data',
    'alarmmsg': '',
    'description': 'This script enriches redirtraffic documents with data from Greynoise',
    'type': 'redelk_enrich',
    'submodule': 'enrich_greynoise'
}


class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        self.greynoise_url = 'http://api.greynoise.io:8888/v1/query/ip'
        # Re-query after 1 day by default
        self.cache = enrich[info['submodule']]['cache'] if info['submodule'] in enrich else 86400

    def run(self):
        ret = get_initial_alarm_result()
        ret['info'] = info
        try:
            hits = self.enrich_greynoise()
            ret['hits']['hits'] = hits
            ret['hits']['total'] = len(hits)
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            self.logger.exception(e)
            pass
        self.logger.info('finished running module. result: %s hits' % ret['hits']['total'])
        return(ret)

    def enrich_greynoise(self):
        # Get all lines in redirtraffic that have not been enriched with 'enrich_greynoise'
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

        # Created a dict grouped by IP address (from source.ip)
        ips = {}
        for ne in notEnriched:
            ip = get_value('_source.source.ip', ne)
            if ip in ips:
                ips[ip].append(ne)
            else:
                ips[ip] = [ne]

        hits = []
        # For each IP, get the greynoise data
        for ip in ips:
            # Get data from redirtraffic if within interval
            lastESData = self.get_last_es_data(ip)

            if not lastESData:
                greynoiseData = self.get_greynoise_data(ip)
            else:
                greynoiseData = get_value('_source.greynoise', lastESData)

            # If no greynoise data found, skip the IP
            if not greynoiseData:
                continue

            for doc in ips[ip]:
                # Fields to copy: greynoise.*
                res = self.add_greynoise_data(doc, greynoiseData)
                if res:
                    hits.append(res)

        return(hits)

    # Get the data from greynoise for the IP
    def get_greynoise_data(self, ip):
        try:
            data = {'ip': ip}
            gnData = requests.post(self.greynoise_url, data=data)
            r = {}
            r['full_data'] = gnData.json()
            tempOS = {}
            tempName = {}
            tempIntention = {}
            if 'records' in r['full_data']:
                for record in r['full_data']['records']:
                    tempOS[record['metadata']['os']] = 0
                    tempName[record['name']] = 0
                    tempIntention[record['intention']] = 0
                # SORT RESULTS
                r['full_data']['records'] = sorted(r['full_data']['records'],
                                                   key=lambda k: k['first_seen'], reverse=False)
                r['first_seen'] = r['full_data']['records'][0]['first_seen']
                r['full_data']['records'] = sorted(r['full_data']['records'],
                                                   key=lambda k: k['last_updated'], reverse=True)
                r['last_result'] = r['full_data']['records'][0]
                r['OS_list'] = list(tempOS.copy().keys())
                r['Name_list'] = list(tempName.copy().keys())
            r['ip'] = ip
            r['query_timestamp'] = int(time())
            r['status'] = r['full_data'].get('status', None)
            x = copy.deepcopy(r)
            x.pop('full_data')
            return(x)
        except Exception as e:
            self.logger.error('Error getting greynoise IP %s' % ip)
            self.logger.exception(e)
            return False

    def get_last_es_data(self, ip):
        # Get greynoise data from ES if less than 1 day old
        q = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range":  {
                                "greynoise.query_timestamp": {
                                    "gte": "now-%ss" % self.cache,
                                    "lte": "now"
                                }
                            }
                        },
                        {
                            "term": {
                                "tags": "enrich_greynoise"
                            }
                        },
                        {
                            "term": {
                                "host.ip": ip
                            }
                        }
                    ]
                }
            }
        }

        res = raw_search(q, index='redirtraffic-*')

        self.logger.debug(res)

        # Return the latest hit or False if not found
        if res and len(res['hits']['hits']) > 0:
            return(res['hits']['hits'][0])
        else:
            return(False)

    # Add greynoise data to the doc
    def add_greynoise_data(self, doc, data):
        doc['_source.greynoise'] = data

        try:
            es.update(index=doc['_index'], id=doc['_id'], body={'doc': doc['_source']})
            return(doc)
        except Exception as e:
            stackTrace = traceback.format_exc()
            self.logger.error('Error adding greynoise data to document %s: %s' % (doc['_id'], stackTrace))
            self.logger.exception(e)
            return(False)
