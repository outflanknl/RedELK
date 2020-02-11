#!/usr/bin/python3
#
# Part of RedELK
# Script to check if there are alarms to be sent
#
# Author: Outflank B.V. / Mark Bergman / @xychix
#

from elasticsearch import Elasticsearch
import json
import sys
import datetime
import config
import socket
es  = Elasticsearch()

from datetime import datetime
from datetime import timedelta

def pprint(r):
 s = json.dumps(r, indent=2, sort_keys=True)
 return(s)

def getQuery(query,size="5000",index="redirtraffic-*"):
  #NOT tags:enriched_v01 AND NOT cslogtype:beacon_newbeacon AND cslogtype:beacon_*
  q3 = {'query': {'query_string': {'query': query }}}
  r3 = es.search(index=index, body=q3, size=size)
  if(r3['hits']['total'] == 0):
    return(None)
  return(r3['hits']['hits'])

def countQuery(query,index="redirtraffic-*"):
  #NOT tags:enriched_v01 AND NOT cslogtype:beacon_newbeacon AND cslogtype:beacon_*
  q3 = {'query': {'query_string': {'query': query }}}
  r3 = es.search(index=index, body=q3, size=0)
  return(r3['hits']['total'])

def setTags(tag,lst):
  for l in lst:
    l["_source"]['tags'].append(tag)
    r = es.update(index=l['_index'],doc_type=l['_type'],id=l['_id'],body={'doc':l['_source']})
    #sys.stdout.write('.')
    #sys.stdout.flush()

class alarm():
  def __init__(self,subject="Alarms from RedElk"):
    self.subject = subject
    self.body = ""
    self.alarm = False
    self.checkDict = {}
    try:
      self.checkDict['alarm_check1'] = self.alarm_check1()
      if self.checkDict['alarm_check1']['alarm'] == True:
        self.alarm = True
    except:
      print("error in 1")
      self.checkDict['alarm_check1'] = {'error','oops, something went south....'}
      self.alarm = True
    try:
      self.checkDict['alarm_check2'] = self.alarm_check2()
      if self.checkDict['alarm_check2']['alarm'] == True:
        self.alarm = True
    except:
      print("error in 2")
      self.checkDict['alarm_check2'] = {'error','oops, something went south....'}
      self.alarm = True
    try:
      self.checkDict['alarm_check3'] = self.alarm_check3()
      if self.checkDict['alarm_check3']['alarm'] == True:
        self.alarm = True
    except:
      print("error in 3")
      self.checkDict['alarm_check3'] = {'error','oops, something went south....'}
      self.alarm = True

  def alarm_check1(self):
    ## This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on redirectors\n
    q = "NOT tags:iplist_* AND redir.backendname:c2* AND NOT tags:ALARMED_* AND tags:enrich_*"
    i = countQuery(q)
    if i >= 10000: i = 10000
    r = getQuery(q,i)
    report = {}
    report['alarm'] = False
    #if i > 0: report['alarm'] = True #if the query gives 'new ip's we hit on them
    report['fname'] = "alarm_check1"
    report['name'] = "Unkown IP to C2"
    report['description'] = "This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on redirectors\n"
    report['query'] = q
    UniqueIPs = {}
    if type(r) != type([]) : r = []
    rAlarmed = []
    for ip in r:
      #give enrichment 5 minutes to catch up.
      nowDelayed = datetime.utcnow() - timedelta(minutes=5)
      d = ip['_source']['@timestamp']
      timestamp = datetime.strptime(d, '%Y-%m-%dT%H:%M:%S.%fZ')
      #if timestamp > nowDelayed:
      #  print("item to new %s < %s"%(timestamp,nowDelayed))
      if timestamp < nowDelayed:
        #print("[D] %s < %s"%(timestamp,nowDelayed))
        #print("[D]%s"% ip['_id'])
        rAlarmed.append(ip)
        if ip['_source']['redirtraffic.sourceip'] not in UniqueIPs:
          UniqueIPs[ip['_source']['redirtraffic.sourceip']] = {}
        if 'redirtraffic.httprequest' in line['_source']:
          UniqueLINEs[line['_source']['redirtraffic.sourceip']]['redirtraffic.httprequest'] = line['_source']['redirtraffic.httprequest']
        if 'redirtraffic.sourceip' in line['_source']:
          UniqueLINEs[line['_source']['redirtraffic.sourceip']]['redirtraffic.sourceip'] = line['_source']['redirtraffic.sourceip']
        if 'timezone' in ip['_source']['geoip']:
          UniqueIPs[ip['_source']['redirtraffic.sourceip']]['timezone'] = ip['_source']['geoip']['timezone']
        if 'as_org' in ip['_source']['geoip']:
          UniqueIPs[ip['_source']['redirtraffic.sourceip']]['ISP'] = ip['_source']['geoip']['as_org']
        if 'redir.frontendname' in ip['_source']:
          UniqueIPs[ip['_source']['redirtraffic.sourceip']]['redir.frontendname'] = ip['_source']['redir.frontendname']
        if 'redirtraffic.request' in ip['_source']:
          UniqueIPs[ip['_source']['redirtraffic.sourceip']]['redirtraffic.request'] = ip['_source']['redirtraffic.request']
        if 'attackscenario' in ip['_source']:
          UniqueIPs[ip['_source']['redirtraffic.sourceip']]['attackscenario'] = ip['_source']['attackscenario']
        if 'tags' in ip['_source']:
          UniqueIPs[ip['_source']['redirtraffic.sourceip']]['tags'] = ip['_source']['tags']
        if 'redirtraffic.timestamp' in ip['_source']:
          UniqueIPs[ip['_source']['redirtraffic.sourceip']]['redirtraffic.timestamp'] = ip['_source']['redirtraffic.timestamp']
        report['alarm'] = True
        print("[A] alarm set in %s"%report['fname'])
        if 'times_seen' in UniqueIPs[ip['_source']['redirtraffic.sourceip']]: UniqueIPs[ip['_source']['redirtraffic.sourceip']]['times_seen'] += 1
        else: UniqueIPs[ip['_source']['redirtraffic.sourceip']]['times_seen'] = 1
    report['results'] = UniqueIPs
    with open("/tmp/ALARMED_alarm_check1.ips","a") as f: 
      for ip in UniqueIPs:
        f.write("%s\n"%ip) 
    # TODO before returning we might have to set an tag on our resultset so we alarm only once. (maybe a tag per alarm?  "ALARMED_%s"%report['fname'] migt do)
    setTags("ALARMED_%s"%report['fname'],rAlarmed)
    return(report)

  def alarm_check2(self):
    ## This check queries public sources given a list of md5 hashes. If a hash was seen we set an alarm\n
    q = "cslogtype:ioc AND NOT tags:ALARMED_*"
    report = {}
    report['alarm'] = False
    report['fname'] = "alarm_check2"
    report['name'] = "Test IOC's against public sources"
    report['description'] = "This check queries public sources given a list of md5 hashes. If a hash was seen we set an alarm\n"
    report['query'] = q
    iocs = []
    #FIRST WE GET ALL IOC's
    i = countQuery(q,index="rtops-*")
    if i >= 10000: i = 10000
    r = getQuery(q,i,index="rtops-*")
    if type(r) != type([]) : r = []
    for l in r:
      if l['_source']['csmessage'].startswith("[indicator] file:"):
        arr = l['_source']['csmessage'].split()
        l['_source']['ioc_bytesize'] = arr[3]
        l['_source']['ioc_hash'] = arr[2]
        l['_source']['ioc_path'] = arr[5]
        l['_source']['ioc_type'] = arr[1][:-1]
        iocs.append(l)
    #THEN WE GET MANUALLY ADDED IOC's
    q = "cslogtype:ioc AND NOT tags:ALARMED_*"
    i = countQuery(q,index="rtops-*")
    r = getQuery(q,i,index="rtops-*")
    if type(r) != type([]) : r = []
    for l in r:
      if l['_source']['csmessage'].startswith("[indicator] file:"):
        arr = l['_source']['csmessage'].split()
        l['_source']['ioc_bytesize'] = arr[3]
        l['_source']['ioc_hash'] = arr[2]
        l['_source']['ioc_path'] = arr[5]
        l['_source']['ioc_type'] = arr[1][:-1]
        iocs.append(l)
    #we now have an array with all IOCs
    md5d = {}
    md5s = []
    for ioc in iocs:
      if ioc['_source']['ioc_hash'] in md5d:
        md5d[ioc['_source']['ioc_hash']].append(ioc)
      else:
        md5d[ioc['_source']['ioc_hash']] = [ioc]
    for key in md5d:
      md5s.append(key)
    #we now have an aray with unique md5's to go test
    ## INSERT CODE
    reportI = {}
    ### ioc VirusTotal
    from iocsources import ioc_vt as vt
    t = vt.VT()
    t.test(md5s)
    reportI['VirusTotal'] = t.report
    ### ioc IBM x-force
    from iocsources import ioc_ibm as ibm
    i = ibm.IBM()
    i.test(md5s)
    reportI['IBM X-Force'] = i.report
    ### ioc_vt
    from iocsources import ioc_hybridanalysis as ha
    h = ha.HA()
    h.test(md5s)
    reportI['Hybrid Analysis'] = h.report
    #print(pprint(report))
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
            print("[A] alarm set in %s"%report['fname'])
            alarmItem = {}
            alarmItem = []
            report['results'][hash] = {}
            if 'engine' not in report['results'][hash]:
              report['results'][hash]['engine'] = []
            report['results'][hash]['engine'].append(engine)
            #find all filenames
            fnameList = []
            for fileI in md5d[hash]:
              fnameList.append(fileI['_source']['ioc_name'])
            report['results'][hash]['fileNames'] = fnameList
            #print("[newAlarm] - %s reports %s"%(engine,hash))
    #TODO ### REBUILD REPORT  #### TODO
    # list of results, each has atleast an 'alarm' boolean in order to allow parent to find alarmworthy items
    # before returning we might have to set an tag on our resultset so we alarm only once. (maybe a tag per alarm?  "ALARMED_%s"%report['fname'] migt do)
    alarmed_set = []
    for l in r:
      if l['_source']['csmessage'].startswith("[indicator] file:"):
        if l['_source']['ioc_hash'] in alarmedHashes:
          alarmed_set.append(l)
    setTags("ALARMED_%s"%report['fname'],alarmed_set)
    return(report)

  def alarm_check3(self):
    ## This check queries for UA's that are listed in any blacklist_useragents.conf and do talk to c2* paths on redirectors\n
    # We will dig trough ALL data finding specific IP related lines and tag them
    fname = "/etc/redelk/rogue_useragents.conf"
    with open(fname) as f:
      content = f.readlines()
    with open(fname) as f:
      content = f.readlines()
    uaList = []
    for line in content:
      if not line.startswith('#'):
        ua = line.strip()
        uaList.append(line.strip())
    keywords = uaList
    # IF NO KEYWORDS EXIT
    #print(keywords)
    qSub = ""
    for keyword in keywords:
      if qSub == "":
        qSub = "(redirtraffic.headeruseragent:%s"%keyword
      else:
        qSub = qSub + " OR redirtraffic.headeruseragent:%s"%keyword
    qSub = qSub + ") "
    #q = "%s AND redir.backendname:c2* AND tags:enrich_* AND NOT tags:ALARMED_* "%qSub
    q = "%s AND redir.backendname:c2* AND NOT tags:ALARMED_* "%qSub
    i = countQuery(q)
    #print("[q] querying %s"%q)
    if i >= 10000: i = 10000
    r = getQuery(q,i)
    report = {}
    report['alarm'] = False
    #if i > 0: report['alarm'] = True #if the query gives 'new lines's we hit on them
    report['fname'] = "alarm_check3"
    report['name'] = "Blacklisted UA to C2"
    report['description'] = "This check queries for UA's that are blacklisted in blacklist_useragents.conf and do talk to c2* paths on redirectors\n"
    report['query'] = q
    UniqueLINEs = {}
    if type(r) != type([]) : r = []
    rAlarmed = []
    for line in r:
      rAlarmed.append(line)
      if line['_source']['redirtraffic.sourceip'] not in UniqueLINEs:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']] = {}
      if 'redirtraffic.httprequest' in line['_source']:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']]['redirtraffic.httprequest'] = line['_source']['redirtraffic.httprequest']
      if 'redirtraffic.sourceip' in line['_source']:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']]['redirtraffic.sourceip'] = line['_source']['redirtraffic.sourceip']
      if 'timezone' in line['_source']['geoip']:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']]['timezone'] = line['_source']['geoip']['timezone']
      if 'as_org' in line['_source']['geoip']:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']]['ISP'] = line['_source']['geoip']['as_org']
      if 'redir.frontendname' in line['_source']:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']]['redir.frontendname'] = line['_source']['redir.frontendname']
      if 'redirtraffic.request' in line['_source']:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']]['redirtraffic.request'] = line['_source']['redirtraffic.request']
      if 'attackscenario' in line['_source']:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']]['attackscenario'] = line['_source']['attackscenario']
      if 'tags' in line['_source']:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']]['tags'] = line['_source']['tags']
      if 'redirtraffic.timestamp' in line['_source']:
        UniqueLINEs[line['_source']['redirtraffic.sourceip']]['redirtraffic.timestamp'] = line['_source']['redirtraffic.timestamp']
      report['alarm'] = True
      print("[A] alarm set in %s"%report['fname'])
      if 'times_seen' in UniqueLINEs[line['_source']['redirtraffic.sourceip']]: UniqueLINEs[line['_source']['redirtraffic.sourceip']]['times_seen'] += 1
      else: UniqueLINEs[line['_source']['redirtraffic.sourceip']]['times_seen'] = 1
    report['results'] = UniqueLINEs
    # TODO before returning we might have to set an tag on our resultset so we alarm only once. (maybe a tag per alarm?  "ALARMED_%s"%report['fname'] migt do)
    setTags("ALARMED_%s"%report['fname'],rAlarmed)
    return(report)

if __name__ == '__main__':
  a = alarm()
  fontsize = 13
  mail = """
  <html><head><style type="text/css">
  #normal {
      font-family: Tahoma, Geneva, sans-serif;
      font-size: 16px;
      line-height: 24px;
  }
  </style>
  </head><body>
  """
  count = 0
  subjectPostPend = ""
  #print(a.checkDict)
  try:
    for k,v in a.checkDict.items():
      for item,itemData in v['results'].items():
        count = count + 1
        mail = mail + "<p style=\"font-size:%spx\">Alarm on item %s while \"%s\"</p>\n"%(fontsize,item,v['name'])
        mail = mail + "<p style=\"color:#770000; font-size:%spx\">%s</p>\n"%(fontsize-3,pprint(itemData))
        mail = mail + "<table>"
        for itemDataK,ItemDataV in itemData.items():
          mail = mail + "<tr><td style=\"font-size:%spx\">%s</td<><td style=\"font-size:%spx\">%s</td></tr>"%(fontsize-3,itemDataK,fontsize-3,ItemDataV)
        mail = mail + "</table>"
        subjectPostPend = " | %s"%v['name']
  except:
    pass
  mail = mail + "</body></html>\n"
  if count >= 1:
    from SendMail import *
    smtpResp = SendMail(config.toAddrs,mail,"Alarm from %s %s"%(socket.gethostname(),subjectPostPend))
    #for to in config.toAddrs:
    #  print("[a] mail to %s from %s"%(to,config.toAddrs))
    #  smtpResp = SendMail(to,mail,"Alarm from RedELK")
    print("[A] we had %s alarm lines"%count)
  else:
    print("[ ] no alarms")
