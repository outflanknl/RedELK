#!/usr/bin/python3
"""
Part of RedELK

This script enriches redirtraffic documents with data from Greynoise

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""

import copy
import logging
import traceback
from time import time

import requests
from config import enrich
from modules.helpers import (es, get_initial_alarm_result, get_last_run,
                             get_value, raw_search)

info = {
    'version': 0.1,
    'name': 'Enrich redirtraffic lines with greynoise data',
    'alarmmsg': '',
    'description': 'This script enriches redirtraffic documents with data from Greynoise',
    'type': 'redelk_enrich',
    'submodule': 'enrich_greynoise'
}


class Module():
    """ Enrich redirtraffic lines with greynoise data """
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        self.greynoise_url = 'http://api.greynoise.io:8888/v1/query/ip'
        # Re-query after 1 day by default
        self.cache = enrich[info['submodule']]['cache'] if info['submodule'] in enrich else 86400

    def run(self):
        """ run the enrich module """
        ret = get_initial_alarm_result()
        ret['info'] = info
        try:
            hits = self.enrich_greynoise()
            ret['hits']['hits'] = hits
            ret['hits']['total'] = len(hits)
        # pylint: disable=broad-except
        except Exception as error:
            stack_trace = traceback.format_exc()
            ret['error'] = stack_trace
            self.logger.exception(error)
        self.logger.info('finished running module. result: %s hits', ret['hits']['total'])
        return ret

    def enrich_greynoise(self):
        """ Get all lines in redirtraffic that have not been enriched with 'enrich_greynoise'
        Filter documents that were before the last run time of enrich_iplist (to avoid race condition) """
        iplist_lastrun = get_last_run('enrich_iplists')
        es_query = {
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
        es_result = raw_search(es_query, index='redirtraffic-*')
        if es_result is None:
            not_enriched_results = []
        else:
            not_enriched_results = es_result['hits']['hits']

        # Created a dict grouped by IP address (from source.ip)
        ips = {}
        for not_enriched in not_enriched_results:
            # pylint: disable=invalid-name
            ip = get_value('_source.source.ip', not_enriched)
            if ip in ips:
                ips[ip].append(not_enriched)
            else:
                ips[ip] = [not_enriched]

        hits = []
        # For each IP, get the greynoise data
        # pylint: disable=invalid-name
        for ip in ips:
            # Get data from redirtraffic if within interval
            last_es_data = self.get_last_es_data(ip)

            if not last_es_data:
                greynoise_data = self.get_greynoise_data(ip)
            else:
                greynoise_data = get_value('_source.greynoise', last_es_data)

            # If no greynoise data found, skip the IP
            if not greynoise_data:
                continue

            for doc in ips[ip]:
                # Fields to copy: greynoise.*
                es_result = self.add_greynoise_data(doc, greynoise_data)
                if es_result:
                    hits.append(es_result)

        return hits

    def get_greynoise_data(self, ip_address):
        """ Get the data from greynoise for the IP """
        try:
            data = {'ip': ip_address}
            gn_data = requests.post(self.greynoise_url, data=data)
            result = {}
            result['full_data'] = gn_data.json()
            temp_os = {}
            temp_name = {}
            temp_intention = {}
            if 'records' in result['full_data']:
                for record in result['full_data']['records']:
                    temp_os[record['metadata']['os']] = 0
                    temp_name[record['name']] = 0
                    temp_intention[record['intention']] = 0
                # SORT RESULTS
                result['full_data']['records'] = sorted(result['full_data']['records'],
                                                   key=lambda k: k['first_seen'], reverse=False)
                result['first_seen'] = result['full_data']['records'][0]['first_seen']
                result['full_data']['records'] = sorted(result['full_data']['records'],
                                                   key=lambda k: k['last_updated'], reverse=True)
                result['last_result'] = result['full_data']['records'][0]
                result['OS_list'] = list(temp_os.copy().keys())
                result['Name_list'] = list(temp_name.copy().keys())
            result['ip'] = ip_address
            result['query_timestamp'] = int(time())
            result['status'] = result['full_data'].get('status', None)
            cleaned_result = copy.deepcopy(result)
            cleaned_result.pop('full_data')
            return cleaned_result
        # pylint: disable=broad-except
        except Exception as error:
            self.logger.error('Error getting greynoise IP %s', ip_address)
            self.logger.exception(error)
            return False

    def get_last_es_data(self, ip_address):
        """ Get greynoise data from ES if less than 1 day old """
        es_query = {
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
                                "host.ip": ip_address
                            }
                        }
                    ]
                }
            }
        }

        es_results = raw_search(es_query, index='redirtraffic-*')

        self.logger.debug(es_results)

        # Return the latest hit or False if not found
        if es_results and len(es_results['hits']['hits']) > 0:
            return es_results['hits']['hits'][0]
        else:
            return False

    def add_greynoise_data(self, doc, data):
        """ Add greynoise data to the doc """
        doc['_source.greynoise'] = data

        try:
            es.update(index=doc['_index'], id=doc['_id'], body={'doc': doc['_source']})
            return doc
        # pylint: disable=broad-except
        except Exception as error:
            stack_trace = traceback.format_exc()
            self.logger.error('Error adding greynoise data to document %s: %s', doc['_id'], stack_trace)
            self.logger.exception(error)
            return False
