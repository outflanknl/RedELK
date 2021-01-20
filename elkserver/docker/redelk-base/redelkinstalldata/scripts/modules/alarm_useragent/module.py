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
    'name': 'User-agent module',
    'alarmmsg': 'VISIT FROM BLACKLISTED USERAGENT TO C2_*',
    'description': 'This check queries for UA\'s that are listed in any blacklist_useragents.conf and do talk to c2* paths on redirectors',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_useragent'
}


class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        #print("class init")
        pass

    def run(self):
        ret = initial_alarm_result
        ret['info'] = info
        ret['fields'] = ['agent.hostname','@timestamp','source.ip','http.headers.useragent','source.nat.ip','redir.frontend.name','redir.backend.name','infra.attack_scenario']
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
        # This check queries for UA's that are listed in any blacklist_useragents.conf and do talk to c2* paths on redirectors\n
        # We will dig trough ALL data finding specific IP related lines and tag them
        # reading the useragents we trigger on.
        fname = "/etc/redelk/rogue_useragents.conf"
        with open(fname) as f:
            content = f.readlines()
        uaList = []
        for line in content:
            if not line.startswith('#'):
                ua = line.strip()
                uaList.append(line.strip())
        keywords = uaList
        qSub = ""
        #add keywords (UA's) to query
        for keyword in keywords:
            if qSub == "":
                qSub = "(http.headers.useragent:%s" % keyword
            else:
                qSub = qSub + " OR http.headers.useragent:%s" % keyword
        qSub = qSub + ") "
        #q = "%s AND redir.backendname:c2* AND tags:enrich_* AND NOT tags:alarm_* "%qSub
        q = "%s AND redir.backend.name:c2* AND NOT tags:alarm_useragent" % qSub
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
