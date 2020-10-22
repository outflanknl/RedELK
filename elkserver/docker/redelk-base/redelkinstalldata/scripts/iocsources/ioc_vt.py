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

class VT():
  def __init__(self):
    version = "0.1"
    self.load()
    self.debug = []
    self.report = {}
    self.report['source'] = "Virus Total"
  #
  def load(self):
    self.d = shelve.open('%s/vt.shelve'%tempDir, writeback=True)
    if 'hashdict' not  in self.d:
      self.d['hashdict'] = {}
    self.hd = self.d['hashdict']
  #
  def scansAvailable(self):
    #this function must determine the number of scans de last X time to ensure we stay within rate limiting
    return(True)
  #
  def virustotalReport(self,hashlist):
    params = {'apikey': config.vt_apikey, 'resource': hashlist}
    headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "python"
      }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
      params=params, headers=headers)
    if response.status_code == 200:
      json_response = response.json()
    else:
      json_response = None
    return(response.status_code,json_response)
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
        self.hd[md5] = {'filenames':[fname],'seenAtVT':None,'lasttested':None}
      if fname not in self.hd[md5]['filenames']:
        self.hd[md5]['filenames'].append(fname)
      if not self.hd[md5]['seenAtVT']:
        if not self.hd[md5]['lasttested']:
          qlist.append(md5)
          if V > 1: print("[2]  adding %s to qlist"%(md5))
        elif self.hd[md5]['lasttested'] < now1h:
          #add to -1h list
          if V > 1: print("[2]  adding %s to qlist1h"%(md5))
          qlist1h.append(md5)
      else:
        self.report[md5]['result'] = 'previousAlarm'
        self.report[md5]['record'] = self.hd[md5]
        if V > 1: print("[2] %s %s already submitted to AV on %s"%(md5,self.hd[md5]['filenames'],self.hd[md5]['seenAtVT']))
    if V > 5: print("[6] testing %s"%((qlist+qlist1h)[:4]))
    if len( (qlist+qlist1h)[:4] ) > 0:
      if V > 8: print("[9] %s completely new files left, will take %s rounds"%( len(qlist), len(qlist)/4 ))
      if V > 8: print("[9] %s files left which haven't been tested for an hour "%( len(qlist1h) ))
      r = self.virustotalReport(",".join((qlist+qlist1h)[:4]))
      res = r[1]
      if V > 8: print("[9] status code %s"%r[0])
      if type(res) != type([]):
        res = [res] #dirty?
        if V > 8: print("[9] just emties resultlist is was %s"%r[1])
      if len(res) > 0:  # yeah really bad, no time now
        for report in res:
          self.debug.append(res)
          try:
            md5 = report['resource']
            self.hd[md5]['lasttested'] = now
            if report['response_code'] != 0:
              # Seen ALARM regardless of outcome
              self.hd[md5]['report'] = report
              self.hd[md5]['seenAtVT'] = report['scan_date']
              if V >= 1: print("[1] %s %s submitted to AV on %s"%(md5,self.hd[md5]['filenames'],self.hd[md5]['seenAtVT']) )
              self.report[md5]['result'] = 'newAlarm'
              self.report[md5]['record'] = self.hd[md5]
            else:
              self.report[md5]['result'] = 'clean'
          except:
            print("[e] Error in %s"%r[1])
    else:
      if V > 8: print("[9] nothing to do")
  #
  def close():
    self.d['hashdict'] = self.hd
    self.d.close()
