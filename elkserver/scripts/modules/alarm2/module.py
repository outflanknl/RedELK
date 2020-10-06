#!/usr/bin/python3
#
# Part of RedELK
#
# Author: Outflank B.V. / Mark Bergman / @xychix
# Contributor: Lorenzo Bernardi / @fastlorenzo
#
from modules.helpers import *
from iocsources import ioc_vt as vt
from iocsources import ioc_ibm as ibm
from iocsources import ioc_hybridanalysis as ha
import traceback

info = {
    'version': 0.1,
    'name': 'alarm2 module',
    'alarmmsg': 'MD5 HASH SEEN ONLINE',
    'description': 'This check queries public sources given a list of md5 hashes.',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm2'
}


class Module():
    def __init__(self):
        pass
        #print("class init")

    def run(self):
        ret = {}
        alarmLines = []
        results = {}
        try:
            report = self.alarm_check2()
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

    def alarm_check2(self):
        # This check queries public sources given a list of md5 hashes. If a hash was seen we set an alarm\n
        q = "c2.log.type:ioc AND NOT tags:ALARMED_*"
        report = {}
        report['alarm'] = False
        report['fname'] = "alarm_check2"
        report['name'] = "Test IOC's against public sources"
        report['description'] = "This check queries public sources given a list of md5 hashes. If a hash was seen we set an alarm\n"
        report['query'] = q
        iocs = []
        # FIRST WE GET ALL IOC's
        i = countQuery(q, index="rtops-*")
        if i >= 10000:
            i = 10000
        r = getQuery(q, i, index="rtops-*")
        if type(r) != type([]):
            r = []
        for l in r:
            if getValue('_source.ioc.type', l) == 'file':
                # arr = l['_source']['c2message'].split()
                # l['_source']['ioc_bytesize'] = arr[3]
                # l['_source']['ioc_hash'] = arr[2]
                # l['_source']['ioc_path'] = arr[5]
                # l['_source']['ioc_type'] = arr[1][:-1]
                iocs.append(l)
        # #THEN WE GET MANUALLY ADDED IOC's
        # #Looks like a duplicate from above
        # q = "c2.log.type:ioc AND NOT tags:ALARMED_*"
        # i = countQuery(q,index="rtops-*")
        # r = getQuery(q,i,index="rtops-*")
        # if type(r) != type([]) : r = []
        # for l in r:
        #   if l['_source']['c2message'].startswith("[indicator] file:"):
        #     arr = l['_source']['c2message'].split()
        #     l['_source']['ioc_bytesize'] = arr[3]
        #     l['_source']['ioc_hash'] = arr[2]
        #     l['_source']['ioc_path'] = arr[5]
        #     l['_source']['ioc_type'] = arr[1][:-1]
        #     iocs.append(l)
        # we now have an array with all IOCs
        md5d = {}
        md5s = []
        for ioc in iocs:
            h = getValue('_source.file.hash.md5', ioc)
            if h in md5d:
                md5d[h].append(ioc)
            else:
                md5d[h] = [ioc]
        for key in md5d:
            md5s.append(key)
        # we now have an aray with unique md5's to go test
        # INSERT CODE
        reportI = {}
        # ioc VirusTotal
        t = vt.VT()
        t.test(md5s)
        reportI['VirusTotal'] = t.report
        # ioc IBM x-force
        i = ibm.IBM()
        i.test(md5s)
        reportI['IBM X-Force'] = i.report
        # ioc Hybrid Analysis
        h = ha.HA()
        h.test(md5s)
        reportI['Hybrid Analysis'] = h.report
        # print(pprint(report))
        alarm = False
        report['results'] = {}
        alarmedHashes = []
        for engine in reportI.keys():
            for hash in reportI[engine].keys():
                if type(reportI[engine][hash]) == type({}):
                    if reportI[engine][hash]['result'] == "newAlarm":
                        alarmedHashes.append(hash)
                        reportI[engine][hash]['alarm'] = True
                        #reportI['alarm'] = True
                        alarm = True
                        print("[A] alarm set in %s" % report['fname'])
                        alarmItem = {}
                        alarmItem = []
                        report['results'][hash] = {}
                        if 'engine' not in report['results'][hash]:
                            report['results'][hash]['engine'] = []
                        report['results'][hash]['engine'].append(engine)
                        # find all filenames
                        fnameList = []
                        for fileI in md5d[hash]:
                            fnameList.append(getValue('_source.file.hash.md5', fileI))
                        report['results'][hash]['fileNames'] = fnameList
                        #print("[newAlarm] - %s reports %s"%(engine,hash))
        # TODO ### REBUILD REPORT  #### TODO
        # list of results, each has atleast an 'alarm' boolean in order to allow parent to find alarmworthy items
        # before returning we might have to set an tag on our resultset so we alarm only once. (maybe a tag per alarm?  "ALARMED_%s"%report['fname'] migt do)
        alarmed_set = []
        for l in r:
            if getValue('_source.ioc.type', l) == 'file':
                h = getValue('_source.file.hash.md5', l)
                if h in alarmedHashes:
                    alarmed_set.append(l)
        report['alarmLines'] = alarmed_set
        return(report)
