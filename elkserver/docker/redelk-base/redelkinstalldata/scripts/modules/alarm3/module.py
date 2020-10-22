#!/usr/bin/python3
#
# Part of RedELK
#
# Author: Outflank B.V. / Mark Bergman / @xychix
# Contributor: Lorenzo Bernardi / @fastlorenzo
#
from modules.helpers import *
import traceback

info = {
    'version': 0.1,
    'name': 'alarm3 module',
    'alarmmsg': 'VISIT FROM BLACKLISTED USERAGENT TO C2_*',
    'description': 'This check queries for UA\'s that are listed in any blacklist_useragents.conf and do talk to c2* paths on redirectors',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm3'
}


class Module():
    def __init__(self):
        #print("class init")
        pass

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

    def alarm_check3(self):
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
        report = {}
        report['alarm'] = False
        # if i > 0: report['alarm'] = True #if the query gives 'new lines's we hit on them
        report['fname'] = "alarm_check3"
        report['name'] = "Blacklisted UA to C2"
        report['description'] = "This check queries for UA's that are blacklisted in blacklist_useragents.conf and do talk to c2* paths on redirectors\n"
        report['query'] = q
        UniqueLINEs = {}
        if type(r) != type([]):
            r = []
        rAlarmed = []
        for line in r:
            rAlarmed.append(line)
            l = getValue('_source.source.ip', line)
            if getValue('_source.source.ip', line) not in UniqueLINEs:
                UniqueLINEs[l] = {}
            UniqueLINEs[l]['http.request.body.content'] = getValue('_source.http.request.body.content', line)
            UniqueLINEs[l]['source.ip'] = getValue('_source.source.ip', line)
            UniqueLINEs[l]['source.nat.ip'] = getValue('_source.source.nat.ip', line)
            UniqueLINEs[l]['country_name'] = getValue('_source.source.geo.country_name', line)
            UniqueLINEs[l]['ISP'] = getValue('_source.source.as.organization.name', line)
            UniqueLINEs[l]['redir.frontend.name'] = getValue('_source.redir.frontend.name', line)
            UniqueLINEs[l]['redir.backend.name'] = getValue('_source.redir.backend.name', line)
            UniqueLINEs[l]['infra.attack_scenario'] = getValue('_source.infra.attack_scenario', line)
            UniqueLINEs[l]['tags'] = getValue('_source.tags', line)
            UniqueLINEs[l]['redir.timestamp'] = getValue('_source.redir.timestamp', line)
            report['alarm'] = True
            print("[A] alarm set in %s" % report['fname'])
            if 'times_seen' in UniqueLINEs[l]:
                UniqueLINEs[l]['times_seen'] += 1
            else:
                UniqueLINEs[l]['times_seen'] = 1
        report['results'] = UniqueLINEs
        # TODO before returning we might have to set an tag on our resultset so we alarm only once. (maybe a tag per alarm?    "ALARMED_%s"%report['fname'] migt do)
        setTags("ALARMED_%s" % report['fname'], rAlarmed)
        report['alarmLines'] = rAlarmed
        return(report)
