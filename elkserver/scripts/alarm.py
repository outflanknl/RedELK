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
import traceback
import re
from connectors import msteams, email

es  = Elasticsearch()

from datetime import datetime
from datetime import timedelta

def pprint(r):
 s = json.dumps(r, indent=2, sort_keys=True)
 return(s)

def getValue(path, source):
    p = path.split('.')
    if p[0] in source:
        if len(p) > 1:
            return getValue('.'.join(p[1:]), source[p[0]])
        else:
            if p[0] == 'ip':
                return source[p[0]][0]
            else:
                return source[p[0]]
    else:
        return None

def getQuery(query,size="5000",index="redirtraffic-*"):
  q3 = {'query': {'query_string': {'query': query }}}
  r3 = es.search(index=index, body=q3, size=size)
  if(r3['hits']['total']['value'] == 0):
    return(None)
  return(r3['hits']['hits'])

def countQuery(query,index="redirtraffic-*"):
  q3 = {'query': {'query_string': {'query': query }}}
  r3 = es.search(index=index, body=q3, size=0)
  return(r3['hits']['total']['value'])

def setTags(tag,lst):
  for l in lst:
    l['_source']['tags'].append(tag)
    r = es.update(index=l['_index'],id=l['_id'],body={'doc':l['_source']})
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
    except Exception as e:
      print("error in 1: %s" % e)
      traceback.print_exc()
      self.checkDict['alarm_check1'] = {'error','oops, something went south....'}
      self.alarm = True
    try:
      self.checkDict['alarm_check2'] = self.alarm_check2()
      if self.checkDict['alarm_check2']['alarm'] == True:
        self.alarm = True
    except Exception as e:
      print("error in 2: %s" % e)
      traceback.print_exc()
      self.checkDict['alarm_check2'] = {'error','oops, something went south....'}
      self.alarm = True
    try:
      self.checkDict['alarm_check3'] = self.alarm_check3()
      if self.checkDict['alarm_check3']['alarm'] == True:
        self.alarm = True
    except Exception as e:
      print("error in 3: %s" % e)
      traceback.print_exc()
      self.checkDict['alarm_check3'] = {'error','oops, something went south....'}
      self.alarm = True

  def alarm_check1(self):
    ## This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on redirectors\n
    q = "NOT tags:iplist_* AND redir.backend.name:c2* AND NOT tags:ALARMED_* AND tags:enrich_*"
    i = countQuery(q)
    if i >= 10000: i = 10000
    r = getQuery(q,i)
    report = {}
    report['alarm'] = False
    #if i > 0: report['alarm'] = True #if the query gives 'new ip's we hit on them
    report['fname'] = "alarm_check1"
    report['name'] = "Unknown IP to C2"
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
        sip = getValue('_source.source.ip', ip)
        if sip not in UniqueIPs:
          UniqueIPs[sip] = {}

        UniqueIPs[sip]['HTTP Query'] = getValue('_source.http.request.body.content', ip)
        UniqueIPs[sip]['Source IP'] = sip
        UniqueIPs[sip]['CDN IP'] = getValue('_source.source.nat.ip', ip)
        UniqueIPs[sip]['Source domain name'] = getValue('_source.source.domain', ip)
        UniqueIPs[sip]['ISP'] = getValue('_source.source.geo.as.organization.name', ip)
        UniqueIPs[sip]['Country'] = getValue('_source.source.geo.country_iso_code', ip)
        UniqueIPs[sip]['Region'] = getValue('_source.source.geo.region_name', ip)
        UniqueIPs[sip]['City'] = getValue('_source.source.geo.city_name', ip)
        UniqueIPs[sip]['Redirector frontend'] = getValue('_source.redir.frontend.name', ip)
        UniqueIPs[sip]['Redirector backend'] = getValue('_source.redir.backend.name', ip)
        UniqueIPs[sip]['Redirector timestamp'] = getValue('_source.redir.timestamp', ip)
        UniqueIPs[sip]['User-Agent'] = getValue('_source.useragent', ip)
        UniqueIPs[sip]['HTTP Host header'] = getValue('_source.http.headers.host', ip)
        UniqueIPs[sip]['Attack scenario'] = getValue('_source.infra.attack_scenario', ip)
        UniqueIPs[sip]['Tags'] = getValue('_source.tags', ip)
        report['alarm'] = True
        print("[A] alarm set in %s"%report['fname'])
        if 'times_seen' in UniqueIPs[sip]: UniqueIPs[sip]['times_seen'] += 1
        else: UniqueIPs[sip]['times_seen'] = 1
    report['results'] = UniqueIPs
    with open("/tmp/ALARMED_alarm_check1.ips","a") as f:
      for ip in UniqueIPs:
        f.write("%s\n"%ip)
    # TODO before returning we might have to set an tag on our resultset so we alarm only once. (maybe a tag per alarm?  "ALARMED_%s"%report['fname'] migt do)
    setTags("ALARMED_%s"%report['fname'],rAlarmed)
    return(report)

  def alarm_check2(self):
    ## This check queries public sources given a list of md5 hashes. If a hash was seen we set an alarm\n
    q = "c2.log.type:ioc AND NOT tags:ALARMED_*"
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
    #we now have an array with all IOCs
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
    ### ioc Hybrid Analysis
    from iocsources import ioc_hybridanalysis as ha
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
            print("[A] alarm set in %s"%report['fname'])
            alarmItem = {}
            alarmItem = []
            report['results'][hash] = {}
            if 'engine' not in report['results'][hash]:
              report['results'][hash]['engine'] = []
            report['results'][hash]['engine'].append(engine)
            #find all filenames
            fnameList = []
            count = 0
            for fileI in md5d[hash]:
              report['results'][hash]['%d file name' % count] = getValue('_source.file.name', fileI)
              report['results'][hash]['%d host name' % count] = getValue('_source.host.name', fileI)
              report['results'][hash]['%d host IP' % count] = getValue('_source.host.ip', fileI)
              report['results'][hash]['%d user name' % count] = getValue('_source.user.name', fileI)
              count += 1
              fnameList.append(getValue('_source.file.name', fileI))
            report['results'][hash]['fileNames'] = fnameList
            #print("[newAlarm] - %s reports %s"%(engine,hash))
    #TODO ### REBUILD REPORT  #### TODO
    # list of results, each has atleast an 'alarm' boolean in order to allow parent to find alarmworthy items
    # before returning we might have to set an tag on our resultset so we alarm only once. (maybe a tag per alarm?  "ALARMED_%s"%report['fname'] migt do)
    alarmed_set = []
    for l in r:
      if getValue('_source.ioc.type', l) == 'file':
        h = getValue('_source.file.hash.md5', l)
        if h in alarmedHashes:
          alarmed_set.append(l)
    setTags("ALARMED_%s" % report['fname'], alarmed_set)
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
        qSub = "(http.headers.useragent:%s"%keyword
      else:
        qSub = qSub + " OR http.headers.useragent:%s"%keyword
    qSub = qSub + ") "
    #q = "%s AND redir.backendname:c2* AND tags:enrich_* AND NOT tags:ALARMED_* "%qSub
    q = "%s AND redir.backend.name:c2* AND NOT tags:ALARMED_* "%qSub
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
      print("[A] alarm set in %s"%report['fname'])
      if 'times_seen' in UniqueLINEs[l]: UniqueLINEs[l]['times_seen'] += 1
      else: UniqueLINEs[l]['times_seen'] = 1
    report['results'] = UniqueLINEs
    # TODO before returning we might have to set an tag on our resultset so we alarm only once. (maybe a tag per alarm?  "ALARMED_%s"%report['fname'] migt do)
    setTags("ALARMED_%s"%report['fname'],rAlarmed)
    return(report)

  #def alarm_check4(self):
    # TODO check domains in index bluecheck- and report when any of following categories are found:
    # abortion, adult, adware, alcohol, anonym, botnet, c2, command and control, compromised, controlled, copyright, crime, criminal, cryptocurrency, discrimination, early warning, extreme, file sharing, freeware, gambling, gore, gruesome, hacking, hate, illegal, intolerance, keyloggers, lottery, malicious, malnets, malware, marijuana, mature, military, moderated, nudity, p2p, phishing, piracy, placeholders, political, pornography, proxy, questionable, scam, sects, sex, shareware, spam, spyware, suspicious, tabacco, unwanted, usenet, violence, warez, weapons

  #def alarm_check5(self):
    # todo check ips in /etc/redelk/iplist_blueteams.conf and see if they appear anywhere in our trafficlogs


if __name__ == '__main__':
  a = alarm()
  count = 0
  try:
    for k,v in a.checkDict.items():
      for item,itemData in v['results'].items():
        count = count + 1
  except:
    pass
  if count > 0:
    if config.msTeamsWebhookURL:
      msteams.SendTeamsAlarm(a)
    if config.smtpSrv:
      email.SendEmailAlarm(a)
    print("[A] we had %s alarm lines" % count)
  else:
    print("[ ] no alarms")
