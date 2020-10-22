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

class IBM():
  def __init__(self):
    version = "0.1"
    self.load()
    self.debug = []
    self.report = {}
    self.report['source'] = "IBM X-Force"
  #
  def load(self):
    self.d = shelve.open('%s/ibm.shelve'%tempDir, writeback=True)
    if 'hashdict' not  in self.d:
      self.d['hashdict'] = {}
    self.hd = self.d['hashdict']
  #
  def scansAvailable(self):
    #this function must determine the number of scans de last X time to ensure we stay within rate limiting
    return(True)
  #
  def IBMreport(self,hashlist):
    r = []
    headers = {"Authorization":config.ibm_BasicAuth}
    for h in hashlist:
      response = requests.get("https://api.xforce.ibmcloud.com/malware/%s"%h,headers=headers)
      if response.status_code == 200:
        json_response = response.json()
        json_response['query_hash'] = h
      else:
        json_response = {}
        json_response['query_hash'] = h
      r.append([response.status_code , json_response])
    return(r)
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
        if V > 1: print("[2] %s %s already submitted to IBM on %s"%(md5,self.hd[md5]['filenames'],self.hd[md5]['seen']))
    if V > 5: print("[6] testing %s"%((qlist+qlist1h)[:16]))
    if len( (qlist+qlist1h)[:16] ) > 0:
      if V > 8: print("[9] %s completely new files left, will take %s rounds"%( len(qlist), len(qlist)/16 ))
      if V > 8: print("[9] %s files left which haven't been tested for an hour "%( len(qlist1h) ))
      r = self.IBMreport((qlist+qlist1h)[:16])
      ### here we neeed to work with the IBM response_code
      #Looping over individual results
      for res in r:
        if V > 8: print("[9] status code %s"%res[0])
        if res[1] != None: #We have json response!
          report = res[1]
          self.debug.append(res)
          md5 = report['query_hash']
          if 'malware' in report:
            #We have a malware ALARM
            self.hd[md5]['lasttested'] = now
            # Seen ALARM regardless of outcome
            self.hd[md5]['report'] = report
            self.hd[md5]['seen'] = now
            if V >= 1: print("[1] %s %s submitted to IBM on %s"%(md5,self.hd[md5]['filenames'],self.hd[md5]['seen']) )
            self.report[md5]['result'] = 'newAlarm'
            self.report[md5]['record'] = self.hd[md5]
          elif 'error' in report:
            #Malware likely not Seeen:
            self.hd[md5]['lasttested'] = now
            self.report[md5]['result'] = 'clean'
          else:
            #Unexpected out or 404 which means clean
            if V >= 1: print("[1] WEIRD OUTCOME from IBM on %s => %s"%(md5,json.dumps(report) ) )
            self.hd[md5]['lasttested'] = now
            self.report[md5]['result'] = 'clean'
    else:
      if V > 8: print("[9] nothing to do")
  #
  def close():
    self.d['hashdict'] = self.hd
    self.d.close()
