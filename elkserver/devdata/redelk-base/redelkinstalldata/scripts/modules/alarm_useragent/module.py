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
    'name': 'User-agent module',
    'alarmmsg': 'VISIT FROM BLACKLISTED USERAGENT TO C2_*',
    'description': 'This check queries for UA\'s that are listed in any blacklist_useragents.conf and do talk to c2* paths on redirectors',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_useragent'
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


    def run(self):
        ret = {}
        alarmLines = []
        results = {}
        try:
            report = self.alarm_check3()
            alarmLines = report.get('alarmLines', [])
            results = report.get('results', [])
            # TODO before returning we might have to set an tag on our resultset so we alarm only once. (maybe a tag per alarm?  "ALARMED_%s"%report['fname'] migt do)
            setTags("ALARMED_%s" % info['submodule'], alarmLines)
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            pass
        ret['info'] = info
        ret['hits'] = {}
        ret['hits']['hits'] = alarmLines
        ret['hits']['total'] = len(alarmLines)
        ret['results'] = results
        print("[a] finished running module %s . result: %s hits"%(ret['info']['name'],ret['hits']['total']))
        #print(ret)
        return(ret)

    def alarm_check(self):
        # This check queries for UA's that are listed in any blacklist_useragents.conf and do talk to c2* paths on redirectors\n
        # We will dig trough ALL data finding specific IP related lines and tag them
        fname = "/etc/redelk/rogue_useragents.conf"
        with open(fname) as f:
            content = f.readlines()
        uaList = []
        for line in content:
            if not line.startswith('#'):
                ua = line.strip()
                uaList.append(line.strip())
        keywords = uaList
        # IF NO KEYWORDS EXIT
        # print(keywords)
        qSub = ""
        for keyword in keywords:
            if qSub == "":
                qSub = "(http.headers.useragent:%s" % keyword
            else:
                qSub = qSub + " OR http.headers.useragent:%s" % keyword
        qSub = qSub + ") "
        #q = "%s AND redir.backendname:c2* AND tags:enrich_* AND NOT tags:ALARMED_* "%qSub
        q = "%s AND redir.backend.name:c2* AND NOT tags:ALARMED_* " % qSub
        i = countQuery(q)
        #print("[q] querying %s"%q)
        if i >= 10000:
            i = 10000
        r = getQuery(q, i)
        UniqueLINEs = {}
        if type(r) != type([]):
            r = []
        report = {}
        report['mutations'] = {}
        report['hits'] = r
        return(report)
