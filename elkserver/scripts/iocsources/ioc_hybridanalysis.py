#!/usr/bin/env python
import requests
import hashlib, os
import shelve
import time
import json
import config

V = config.Verbosity
interval = config.interval
tempDir = config.tempDir

class HA():
  def __init__(self):
    version = "0.1"
    self.load()
    self.debug = []
    self.report = {}
    self.report['source'] = "Hybrid Analysis"
  #
  def load(self):
    self.d = shelve.open('%s/hybridanalysis.shelve'%tempDir, writeback=True)
    if 'hashdict' not  in self.d:
      self.d['hashdict'] = {}
    self.hd = self.d['hashdict']
  #
  def scansAvailable(self):
    #this function must determine the number of scans de last X time to ensure we stay within rate limiting
    return(True)
  #
  def HAreport(self,hashlist):
    r = []
    headers = { "accept": "application/json",
            "user-agent" : "Falcon Sandbox",
            "api-key" : config.HybridAnalysisAPIKEY,
            "Content-Type" : "application/x-www-form-urlencoded"}
    payload = []
    for h in hashlist:
      payload.append(('hashes[]',h))
    u = "https://www.hybrid-analysis.com/api/v2/search/hashes?_timestamp=%s"%int(time.time())
    response = requests.post(u,headers=headers,data=payload)
    json_response = {}
    if response.status_code == 200:
      json_response['results'] = response.json()
      json_response['status_code'] = response.status_code
    else:
      json_response['status_code'] = response.status_code
    return(json_response)
  #
  def test(self,list):
    l = list
    qlist = []
    qlist1h = []
    now = time.time()
    now1h = now - interval
    for md5 in l:
      self.report[md5] = {}
      self.report[md5]['result'] = ""
      fname = "unknown"
      #test if md5 already in hashdict
      if md5 not in self.hd :
        self.hd[md5] = {'filenames':[fname],'seen':None,'lasttested':None}
      if fname not in self.hd[md5]['filenames']:
        self.hd[md5]['filenames'].append(fname)
      if not self.hd[md5]['seen']:
        if not self.hd[md5]['lasttested']:
          qlist.append(md5)
        elif self.hd[md5]['lasttested'] < now1h:
          #add to -1h list
          qlist1h.append(md5)
      else:
        self.report[md5]['result'] = 'previousAlarm'
        self.report[md5]['record'] = self.hd[md5]
        if V > 1: print("[2] %s %s already submitted to HA on %s"%(md5,self.hd[md5]['filenames'],self.hd[md5]['seen']))
    if V > 5: print("[6] testing %s"%((qlist+qlist1h)[:16]))
    if len( (qlist+qlist1h)[:16] ) > 0:
      if V > 8: print("[9] %s completely new files left, will take %s rounds"%( len(qlist), len(qlist)/16 ))
      if V > 8: print("[9] %s files left which haven't been tested for an hour "%( len(qlist1h) ))
      toTestList = (qlist+qlist1h)[:16]
      r = self.HAreport(toTestList)
      for md5 in toTestList:
        self.hd[md5]['seen'] = now
      ### here we neeed to work with the HA response_code
      #Looping over individual results
      if 'results' not in r: r['results'] = []  #dirty hack.
      self.debug.append(r)
      for res in r['results']:
        if V > 8: print("[9] status code %s"%r['status_code'])
        if 'md5' in res: #We have json response!
          self.debug.append(res)
          md5 = res['md5']
          self.report[md5] = {'report':res}
          #Valid or not, file is seen!
          self.hd[md5]['lasttested'] = now
          # Seen ALARM regardless of outcome
          self.hd[md5]['report'] = res
          self.hd[md5]['seen'] = now
          if V >= 1: print("[1] %s %s submitted to Hybrid Analysis on %s"%(md5,self.hd[md5]['filenames'],self.hd[md5]['seen']) )
          self.report[md5]['result'] = 'newAlarm'
    else:
      if V > 8: print("[9] nothing to do")
  #
  def close():
    self.d['hashdict'] = self.hd
    self.d.close()
