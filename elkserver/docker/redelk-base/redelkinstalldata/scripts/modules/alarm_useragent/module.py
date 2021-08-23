#!/usr/bin/python3
"""
Part of RedELK

This check queries for UA\'s that are listed in any blacklist_useragents.conf and do talk to c2* paths on redirectors

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging
import traceback

from modules.helpers import get_initial_alarm_result, get_query

info = {
    'version': 0.1,
    'name': 'User-agent module',
    'alarmmsg': 'VISIT FROM BLACKLISTED USERAGENT TO C2_*',
    'description': 'This check queries for UA\'s that are listed in any blacklist_useragents.conf and do talk to c2* paths on redirectors',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_useragent'
}


class Module():
    """ User-agent module """
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

    def run(self):
        """ Run the alarm module """
        ret = get_initial_alarm_result()
        ret['info'] = info
        ret['fields'] = ['agent.hostname', '@timestamp', 'source.ip', 'http.headers.useragent', 'source.nat.ip', 'redir.frontend.name', 'redir.backend.name', 'infra.attack_scenario']
        ret['groupby'] = ['source.ip', 'http.headers.useragent']
        try:
            report = self.alarm_check()
            ret['hits']['hits'] = report['hits']
            ret['hits']['total'] = len(report['hits'])
        # pylint: disable=broad-except
        except Exception as error:
            stack_trace = traceback.format_exc()
            ret['error'] = stack_trace
            self.logger.exception(error)
        self.logger.info('finished running module. result: %s hits', ret['hits']['total'])
        return ret

    def alarm_check(self): # pylint: disable=no-self-use
        """ This check queries for UA's that are listed in any blacklist_useragents.conf and do talk to c2* paths on redirectors
        We will dig trough ALL data finding specific IP related lines and tag them reading the useragents we trigger on. """
        file_name = '/etc/redelk/rogue_useragents.conf'
        with open(file_name) as file:
            content = file.readlines()
        ua_list = []
        for line in content:
            if not line.startswith('#'):
                ua_list.append(line.strip())
        keywords = ua_list
        es_subquery = ''
        # add keywords (UA's) to query
        for keyword in keywords:
            if es_subquery == '':
                es_subquery = '(http.headers.useragent:%s' % keyword
            else:
                es_subquery = es_subquery + ' OR http.headers.useragent:%s' % keyword
        es_subquery = es_subquery + ') '
        # q = "%s AND redir.backendname:c2* AND tags:enrich_* AND NOT tags:alarm_* "%qSub
        es_query = '%s AND redir.backend.name:c2* AND NOT tags:alarm_useragent' % es_subquery

        es_results = get_query(es_query, 10000)
        report = {}
        report['hits'] = es_results
        return report
