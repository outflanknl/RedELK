#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
from modules.helpers import get_initial_alarm_result, getValue, rawSearch
import traceback
import logging

info = {
    'version': 0.1,
    'name': 'HTTP Traffic module',
    'alarmmsg': 'UNKNOWN IP TO C2_ backend',
    'description': 'This check queries for IP\'s that aren\'t listed in any iplist* but do talk to c2* paths on redirectors',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_httptraffic'
}


class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        pass

    def run(self):
        ret = get_initial_alarm_result()
        ret['info'] = info
        ret['fields'] = ['agent.hostname', 'source.ip', 'source.nat.ip', 'source.geo.country_name', 'source.as.organization.name', 'redir.frontend.name', 'redir.backend.name', 'infra.attack_scenario', 'tags', 'redir.timestamp']
        ret['groupby'] = ['source.ip']
        try:
            alarmed_ips = self.get_alarmed_ips()
            report = self.alarm_check(alarmed_ips)
            ret['hits']['hits'] = report
            ret['hits']['total'] = len(report)
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            self.logger.exception(e)
            pass
        self.logger.info('finished running module. result: %s hits' % ret['hits']['total'])
        return(ret)

    # Returns all previous IPs that have been alarmed already
    def get_alarmed_ips(self):
        query = {
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
        res = rawSearch(query, index='redirtraffic-*')
        if res is None:
            alarmed = []
        else:
            alarmed = res['hits']['hits']

        # Created a dict grouped by IP address (from source.ip)
        ips = {}
        for al in alarmed:
            ip = getValue('_source.source.ip', al)
            if ip in ips:
                ips[ip].append(al)
            else:
                ips[ip] = [al]

        return(ips)

    def alarm_check(self, alarmed_ips):
        # This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on redirectors
        query = {
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {
                    'filter': [
                        {'match': {'tags': 'enrich_iplists'}}
                    ],
                    'must': {
                        'query_string': {
                            'fields': ['redir.backend.name'],
                            'query': 'c2-*'
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
        res = rawSearch(query, index='redirtraffic-*')
        if res is None:
            notEnriched = []
        else:
            notEnriched = res['hits']['hits']

        # Created a dict grouped by IP address (from source.ip)
        ips = {}
        for ne in notEnriched:
            ip = getValue('_source.source.ip', ne)
            if ip in ips:
                ips[ip].append(ne)
            else:
                ips[ip] = [ne]

        hits = []

        # Now we check if the IPs have already been alarmed in the past timeframe defined in the config
        for ip in ips:
            # Not alarmed yet, process it
            if ip not in alarmed_ips:
                hits += ips[ip]

        # Return the array of new IP documents to be alarmed
        return(hits)
