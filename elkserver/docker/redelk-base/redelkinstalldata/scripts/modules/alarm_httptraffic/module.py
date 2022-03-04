#!/usr/bin/python3
"""
Part of RedELK

This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on redirectors

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging

from modules.helpers import get_initial_alarm_result, get_value, raw_search

info = {
    'version': 0.1,
    'name': 'HTTP Traffic module',
    'alarmmsg': 'UNKNOWN IP TO C2_ backend',
    'description': 'This check queries for IP\'s that aren\'t listed in any iplist* but do talk to c2* paths on redirectors',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_httptraffic'
}


class Module():
    """ HTTP Traffic module """
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

    def run(self):
        """ Run the alarm module """
        ret = get_initial_alarm_result()
        ret['info'] = info
        ret['fields'] = ['agent.hostname', 'source.ip', 'source.cdn.ip', 'source.geo.country_name', 'source.as.organization.name', 'redir.frontend.name', 'redir.backend.name', 'infra.attack_scenario', 'tags', 'redir.timestamp']
        ret['groupby'] = ['source.ip']
        alarmed_ips = self.get_alarmed_ips()
        report = self.alarm_check(alarmed_ips)
        ret['hits']['hits'] = report
        ret['hits']['total'] = len(report)
        self.logger.info('finished running module. result: %s hits', ret['hits']['total'])
        return ret

    def get_alarmed_ips(self):  # pylint: disable=no-self-use
        """ Returns all previous IPs that have been alarmed already """
        es_query = {
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {
                    'filter': [
                        {
                            'range':  {
                                '@timestamp': {
                                    'gte': 'now-1y'
                                }
                            }
                        },
                        {'match': {'tags': info['submodule']}}
                    ]
                }
            }
        }
        res = raw_search(es_query, index='redirtraffic-*')
        if res is None:
            alarmed_hits = []
        else:
            alarmed_hits = res['hits']['hits']

        # Created a dict grouped by IP address (from source.ip)
        ips = {}
        for alarmed_hit in alarmed_hits:
            # pylint: disable=invalid-name
            ip = get_value('_source.source.ip', alarmed_hit)
            if ip in ips:
                ips[ip].append(alarmed_hit)
            else:
                ips[ip] = [alarmed_hit]

        return ips

    def alarm_check(self, alarmed_ips):  # pylint: disable=no-self-use
        """ This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on redirectors """
        es_query = {
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {
                    'filter': [
                        {'match': {'tags': 'enrich_iplists'}}
                    ],
                    'must': {
                        'query_string': {
                            'fields': ['redir.backend.name'],
                            'query': 'c2*'
                        }
                    },
                    'must_not': [{
                            'query_string': {
                                'fields': ['tags'],
                                'query': 'iplist_*'
                            }
                        },
                        {'match': {'tags': info['submodule']}}
                    ]
                }
            }
        }
        res = raw_search(es_query, index='redirtraffic-*')
        if res is None:
            not_enriched_hits = []
        else:
            not_enriched_hits = res['hits']['hits']

        # Created a dict grouped by IP address (from source.ip)
        ips = {}
        for not_enriched in not_enriched_hits:
            # pylint: disable=invalid-name
            ip = get_value('_source.source.ip', not_enriched)
            if ip in ips:
                ips[ip].append(not_enriched)
            else:
                ips[ip] = [not_enriched]

        hits = []

        # Now we check if the IPs have already been alarmed in the past timeframe defined in the config
        # pylint: disable=invalid-name
        for ip, ip_val in ips.items():
            # Not alarmed yet, process it
            if ip not in alarmed_ips:
                hits += ip_val

        # Return the array of new IP documents to be alarmed
        return hits
