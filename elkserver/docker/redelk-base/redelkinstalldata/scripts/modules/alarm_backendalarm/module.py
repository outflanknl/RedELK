#!/usr/bin/python3
"""
Part of RedELK

This check queries for calls to backends that have alarm in their name

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging

from modules.helpers import get_initial_alarm_result, get_query

info = {
    'version': 0.1,
    'name': 'backend alarm module',
    'alarmmsg': 'TRAFFIC TO ANY BACKEND WITH THE WORD ALARM IN THE NAME',
    'description': 'This check queries for calls to backends that have alarm in their name',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_backendalarm'
}


class Module():
    """ backend alarm module
    This check queries for calls to backends that have alarm in their name
    """
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

    def run(self):
        """ Run the alarm module """
        ret = get_initial_alarm_result()
        ret['info'] = info
        ret['fields'] = ['@timestamp', 'source.ip', 'http.headers.useragent', 'source.cdn.ip', 'redir.frontend.name', 'redir.backend.name', 'infra.attack_scenario']
        ret['groupby'] = ['source.ip', 'http.headers.useragent']
        report = self.alarm_check()
        ret['hits']['hits'] = report['hits']
        ret['hits']['total'] = len(report['hits'])
        self.logger.info('finished running module. result: %s hits', ret['hits']['total'])
        return ret

    # pylint: disable=no-self-use
    def alarm_check(self):
        """ This check queries for calls to backends that have *alarm* in their name """
        es_query = f'redir.backend.name:*alarm* AND NOT tags:{info["submodule"]}'
        es_results = get_query(es_query, 10000)
        report = {
            'hits': es_results
        }
        return report
