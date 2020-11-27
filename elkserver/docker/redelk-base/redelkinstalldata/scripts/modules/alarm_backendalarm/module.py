#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
from modules.helpers import *
import traceback
import logging

info = {
    'version': 0.1,
    'name': 'backend alarm module',
    'alarmmsg': 'TRAFFIC TO ANY BACKEND WITH THE WORD ALARM IN THE NAME',
    'description': 'This check queries for calls to backends that have alarm in their name',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_backendalarm'
}


class Module():
    def __init__(self):
        #print("class init")
        pass

    def run(self):
        ret = initial_alarm_result
        ret['info'] = info
        ret['fields'] = ['@timestamp','source.ip','http.headers.useragent','source.nat.ip','redir.frontend.name','redir.backend.name','infra.attack_scenario']
        ret['groupby'] = ['source.ip','http.headers.useragent']
        try:
            report = self.alarm_check()
            ret['hits']['hits'] = report['hits']
            ret['mutations'] = report['mutations']
            ret['hits']['total'] = len(report['hits'])
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            self.logger.exception(e)
            pass
        self.logger.info('finished running module. result: %s hits' % ret['hits']['total'])
        return(ret)

    def alarm_check(self):
        # This check queries for calls to backends that have *alarm* in their name\n
        q = "redir.backend.name:*alarm* AND NOT tags:%s"%(info['submodule'])
        i = countQuery(q)
        if i >= 10000:
            i = 10000
        r = getQuery(q, i)
        if type(r) != type([]):
            r = []
        report = {}
        report['mutations'] = {}
        report['hits'] = r
        return(report)
