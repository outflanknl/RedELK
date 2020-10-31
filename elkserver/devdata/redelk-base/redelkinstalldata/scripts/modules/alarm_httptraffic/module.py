#!/usr/bin/python3
#
# Part of RedELK
#
# Author: Outflank B.V. / Mark Bergman / @xychix
# Contributor: Lorenzo Bernardi / @fastlorenzo
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
        #print("class init")
        pass

    def run(self):
        ret = initial_alarm_result
        ret['info'] = info
        ret['fields'] = ['source.ip', 'source.nat.ip', 'source.geo.country_name', 'source.as.organization.name', 'redir.frontend.name', 'redir.backend.name', 'infra.attack_scenario', 'tags', 'redir.timestamp']
        ret['groupby'] = ['source.ip']
        try:
            report = self.alarm_check1()
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

    def alarm_check1(self):
        # This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on redirectors\n
        q = "NOT tags:iplist_* AND redir.backend.name:c2* AND NOT tags:ALARMED_* AND tags:enrich_*"
        i = countQuery(q)
        if i >= 10000:
            i = 10000
        r = getQuery(q, i) # need to query 'until' now - 5min as we're relying on enrichment here!
        report = {}
        report['alarm'] = False
        # if i > 0: report['alarm'] = True #if the query gives 'new ip's we hit on them
        report['fname'] = "alarm_check1"
        report['name'] = "Unkown IP to C2"
        report['description'] = "This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on redirectors\n"
        report['query'] = q
        UniqueIPs = {}
        if type(r) != type([]):
            r = [] # TODO: dirty bugfix, replace with error handling!
        for ip in r:
            if 'times_seen' in UniqueIPs[sip]:
                UniqueIPs[sip]['times_seen'] += 1
            else:
                UniqueIPs[sip]['times_seen'] = 1
        report['results'] = UniqueIPs
        with open("/tmp/ALARMED_alarm_check1.ips", "a") as f:
            for ip in UniqueIPs:
                f.write("%s\n" % ip)
        report['hits'] = r
        report['mutations'] = {}
        return(report)
