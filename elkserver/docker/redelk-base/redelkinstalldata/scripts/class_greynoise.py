#
# Part of RedELK
# Script to start enrichment process of data in elasticsearch
#
# Author: Outflank B.V. / Mark Bergman / @xychix
#

import requests
import json
from datetime import datetime
from time import time
import shelve

import config
tempDir = config.tempDir

def pprint(r):
 print(json.dumps(r, indent=2, sort_keys=True))

class greynoise():
    def __init__(self):
        self.debug = []
        self.load()
    #
    def load(self):
        self.d = shelve.open('%s/greynoise.shelve'%tempDir, writeback=True)
        if 'hashdict' not  in self.d:
            self.d['hashdict'] = {}
        self.greynoiseCache = self.d['hashdict']
    #
    def queryIp(self,ip):
        if ip in self.greynoiseCache:
            now = int(time()) #Timestamp in seconds
            if self.greynoiseCache[ip]['query_timestamp'] > now - (24*3600):
                #record is less than one day old, return
                return(self.greynoiseCache[ip])
        return(self.queryIpAPI(ip))
    #
    def queryIpAPI(self,ip):
        data = {'ip':ip}
        url = 'http://api.greynoise.io:8888/v1/query/ip'
        greynoise = requests.post(url,data=data)
        r = {}
        r['full_data'] = greynoise.json()
        tempOS = {}
        tempName = {}
        tempIntention = {}
        if 'records' in r['full_data']:
         for record in r['full_data']['records']:
          tempOS[ record['metadata']['os'] ] = 0
          tempName[ record['name'] ] = 0
          tempIntention[ record['intention'] ] = 0
         ### SORT RESULTS
         r['full_data']['records'] = sorted(r['full_data']['records'],  key=lambda k: k['first_seen'], reverse=False)
         r['first_seen'] = r['full_data']['records'][0]['first_seen']
         r['full_data']['records'] = sorted(r['full_data']['records'],  key=lambda k: k['last_updated'], reverse=True)
         r['last_result'] = r['full_data']['records'][0]
         r['OS_list'] = list(tempOS.copy().keys())
         r['Name_list'] = list(tempName.copy().keys())
        r['ip'] = ip
        r['query_timestamp'] = int(time())
        r['status'] = r['full_data'].get('status',None)
        self.debug.append(r)
        x = r.copy()
        n = x.pop('full_data')
        self.greynoiseCache[ip] = x
        return(x)

def test():
 g = greynoise()
 r = g.queryIp('197.231.221.211')
 x = r.copy()
 n = x.pop('full_data')
 pprint(x)

 from random import randint as ri
 def getRandomResult():
  run = True
  while(run):
   ip = "%s.%s.%s.%s"%(ri(1,255),ri(1,255),ri(1,255),ri(1,255))
   r = {}
   x = {}
   if ip in greynoiceCache:
    r = g.queryIp(ip)
   else:
    r = g.queryIp(ip)
    x = r.copy()
    n = x.pop('full_data')
    greynoiceCache[ip] = x
   if 'last_result' in x:
    print("### %s"%ip)
    pprint(x)
    run = False
   return()
