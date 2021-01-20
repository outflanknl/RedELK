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
    'name': 'HTTP Traffic module',
    'alarmmsg': 'UNKNOWN IP TO C2_ backend',
    'description': 'This check queries for IP\'s that aren\'t listed in any iplist* but do talk to c2* paths on redirectors',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_httptraffic'
}

class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        #print("class init")
        pass

    def run(self):
        ret = initial_alarm_result
        ret['info'] = info
        ret['fields'] = ['agent.hostname','source.ip', 'source.nat.ip', 'source.geo.country_name', 'source.as.organization.name', 'redir.frontend.name', 'redir.backend.name', 'infra.attack_scenario', 'tags', 'redir.timestamp']
        ret['groupby'] = ['source.ip']
        try:
            report = self.alarm_check()
            ret['hits']['hits'] = report['hits']
            ret['mutations'] = report['mutations'] # for this alarm this is an empty list
            ret['hits']['total'] = len(report['hits'])
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            self.logger.exception(e)
            pass
        self.logger.info('finished running module. result: %s hits' % ret['hits']['total'])
        return(ret)

    def alarm_check(self):
        # This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on redirectors\n
        q = "NOT tags:iplist_* AND redir.backend.name:c2* AND NOT tags:alarm_httptraffic AND tags:enriched_*"
        i = countQuery(q)
        if i >= 10000:
            i = 10000
        r = getQuery(q, i) # need to query 'until' now - 5min as we're relying on enrichment here!
        self.logger.debug('hits[%d]:%s' % (i,r))
        UniqueIPs = {}
        if type(r) != type([]):
            r = [] # TODO: dirty bugfix, replace with error handling!
        for l in r:
            sip = getValue('_source.source.ip', l)
            if sip not in UniqueIPs:
                UniqueIPs[sip] = {}
            if 'times_seen' in UniqueIPs[sip]:
                UniqueIPs[sip]['times_seen'] += 1
            else:
                UniqueIPs[sip]['times_seen'] = 1
        with open("/tmp/ALARMED_alarm_check1.ips", "a") as f:
            for ip in UniqueIPs:
                f.write("%s\n" % ip)
        report = {}
        report['hits'] = r
        report['mutations'] = {}
        return(report)
