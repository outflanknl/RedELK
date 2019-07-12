#!/usr/bin/python3
#
# Part of RedELK
# Script to start enrichment process of data in elasticsearch
#
# Author: Outflank B.V. / Mark Bergman / @xychix
#

from elasticsearch import Elasticsearch
import json
import sys
import datetime
es  = Elasticsearch()

def pprint(r):
 print(json.dumps(r, indent=2, sort_keys=True))

import socket
def isIP(addr):
  try:
    socket.inet_aton(addr)
    # legal
    return(True)
  except socket.error:
    # Not legal
    return(False)

#### code for enrich_V1 tags
def getInitialBeaconLine(l1):
  q2 = {'query': {'query_string': {'query': 'FILLME'}}}
  q2['query']['query_string']['query'] = "beacon_id:\"%s\" AND cslogtype:beacon_newbeacon AND beat.name:%s"%(l1['_source']['beacon_id'],l1["_source"]['beat']['name'])
  r2 = es.search(index="rtops-*", body=q2)
  b = r2['hits']['hits'][0]
  #now we have a beacon
  return(b)

def enrichAllLinesWithBeacon(l1,b):
  tagsSet = 0
  #query for all not enriched lines make new L1 lines
  q3 = {'query': {'query_string': {'query': 'FILLME'}}}
  q3['query']['query_string']['query'] = "beacon_id:\"%s\" AND beat.name:%s AND NOT tags:enriched_v01"%(l1['_source']['beacon_id'],l1["_source"]['beat']['name'])
  r3 = es.search(index="rtops-*", body=q3)
  for l1 in r3['hits']['hits']:
    l1["_source"]['tags'].append("enriched_v01")
    for field in ["target_hostname","target_ipext","target_os","target_osversion","target_pid","target_user"]:
      try:
        l1["_source"][field] = b["_source"][field]
      except:
        pass
    es.update(l1['_index'],l1['_type'],id=l1['_id'],body={'doc':l1['_source']})
    tagsSet = tagsSet + 1
    #sys.stdout.write('.')
    #sys.stdout.flush()
  return(tagsSet)

def getSet():
  #NOT tags:enriched_v01 AND NOT cslogtype:beacon_newbeacon AND cslogtype:beacon_*
  q3 = {'query': {'query_string': {'query': 'NOT tags:enriched_v01 AND NOT cslogtype:beacon_newbeacon AND (cslogtype:beacon_* OR cslogtype:ioc) AND NOT source:*unknown*'}}}
  r3 = es.search(index="rtops-*", body=q3)
  if(r3['hits']['total'] == 0):
    return(None)
  return(r3['hits']['hits'])

def enrichV1():
  tagsSet = 0
  doneList = []
  run = True
  while(run):
    doneList = []
    Set = getSet()
    if Set == None:
      run = False
      break
    else:
      for line in Set:
        try:
          id = line['_source']['beacon_id']
        except:
          break
        if line['_source']['beacon_id'] not in doneList:
          b = getInitialBeaconLine(line)
          #sys.stdout.write('\n %s :'%b['_source']['beacon_id'])
          #sys.stdout.flush()
          tagsSet = tagsSet + enrichAllLinesWithBeacon(line,b)
          doneList.append(b['_source']['beacon_id'])
  return(tagsSet)

def queryFromConfig(line,index="beacondb"):
 lineA = line.split(';')
 q = lineA[0]
 f1 = lineA[1]
 f2 = lineA[2]
 f3 = lineA[3]
 q3 = {'query': {'query_string': {'query': 'FILLME'}}}
 query =  "NOT (tags:sandboxes_v02 OR tags:testsystems_v02) AND (target_user:%s %s target_hostname:%s %s target_ipint:%s)"%(f1,q,f2,q,f3)
 q3['query']['query_string']['query'] = query
 #print(query)
 r3 = es.search(index=index, body=q3)
 #print("found %s items"%len(r3['hits']['hits']))
 return(r3['hits']['hits'])

def queryBIG_OR(array,field,index,prefix="",postfix=""):
  sep = prefix
  query = ""
  for item in array:
    query = query + " %s %s:%s" % (sep, field,item)
    sep = "OR"
  query = query + postfix
  #print(query)
  q3 = {'query': {'query_string': {'query': 'FILLME'}}}
  q3['query']['query_string']['query'] = query
  r3 = es.search(index=index, body=q3)
  return(r3['hits']['hits'])

def setTags(tag,lst):
  for l in lst:
    l["_source"]['tags'].append(tag)
    r = es.update(l['_index'],l['_type'],id=l['_id'],body={'doc':l['_source']})
    #sys.stdout.write('.')
    #sys.stdout.flush()

def readConfigLines(fname):
  with open(fname) as f:
    content = f.readlines()
    content = [x.strip() for x in content]
    out = []
    for line in content:
      if not line.startswith('#'):
        if line.count(';') is 3:
          ip = line.strip()
          if isIP(ip):
            out.append(line.strip())
    return(out)

def findIPLines(fname,tag):
  # We will dig trough ALL data finding specific IP related lines and tag them
  with open(fname) as f:
    content = f.readlines()
  ipList = []
  for line in content:
   if not line.startswith('#'):
     ip = line.strip()
     if isIP(ip):
       ipList.append(line.strip())
  run = True
  tagsSet = 0
  ipListList = []
  while len(ipList) > 0:
    ipListList.append(ipList[:250])
    ipList = ipList[250:]
  for ipL in ipListList:
    if len(ipL) < 1: run=False
    while(run):
      r = queryBIG_OR(ipL,"src_ip","redirhaproxy-*","NOT tags:%s AND ("%tag,")")
      if len(r) > 0:
        tagsSet = tagsSet + len(r)
        setTags(tag,r)
      else:
        run = False
  return(tagsSet)

#section build for greynoise, in essence loop over all items in index that don't have tag X set
def findUntaggedLines(tag,size=1000,index="redirhaproxy-*"):
  query = "NOT tags:%s"%tag
  q3 = {'query': {'query_string': {'query': 'FILLME'}}}
  q3['query']['query_string']['query'] = query
  r3 = es.search(index=index, body=q3, size=size)
  #print("Query %s"%q3)
  #print("items retreived %s"%len(r3['hits']['hits']))
  return(r3['hits']['hits'])

def enrich_greynoiseSet(handler):
  tag = "enrich_greynoise"
  set = findUntaggedLines(tag)
  cRes = 0
  for l in set:
    l["_source"]['tags'].append(tag)
    try:
      ip = l["_source"]["src_ip"]
      l["_source"]["greynoise"] = handler.queryIp(ip)
    except:
      pass
    r = es.update(l['_index'],l['_type'],id=l['_id'],body={'doc':l['_source']})
    cRes += 1
  return(cRes)

def enrich_greynoise():
  from class_greynoise import greynoise
  g = greynoise()
  run = True
  nTotal = 0
  while(run):
    nRes = enrich_greynoiseSet(g)
    nTotal = nRes + nTotal
    if nRes == 0: run = False
  return(nTotal)
#end section

def findTaggedLines(tag,size=1000,index="redirhaproxy-*"):
  query = "tags:%s"%tag
  q3 = {'query': {'query_string': {'query': 'FILLME'}}}
  q3['query']['query_string']['query'] = query
  r3 = es.search(index=index, body=q3, size=size)
  return(r3['hits']['hits'])

def deleteTag(tag,size=1000,index="redirhaproxy-*"):
  run = True
  totals = 0
  while(run):
    set = findTaggedLines(tag,size,index)
    cRes = len(set)
    if cRes == 0: run = False
    for l in set:
      newSet = []
      for t in l["_source"]['tags']:
        if t != tag: newSet.append(t)
      l["_source"]['tags'] = newSet
      r = es.update(l['_index'],l['_type'],id=l['_id'],body={'doc':l['_source']})
  return(totals)

####
if __name__ == '__main__':
  tagsSet = 0
  tagsSet = enrichV1()
  print("Summary: date: %s, tagsSet: %s, Function:enrichV1"%(datetime.datetime.now(),tagsSet))

  testsystems = readConfigLines('/etc/redelk/known_testsystems.conf')
  tagsSet = 0
  for item in testsystems:
    numRes = 3
    while numRes > 0:
      #sys.stdout.write('.')
      #sys.stdout.flush()
      r=queryFromConfig(item,"beacondb")
      setTags('testsystems_v02',r)
      r2=queryFromConfig(item,"rtops-*")
      setTags('testsystems_v02',r2)
      numRes = len(r) + len(r2)
      tagsSet = tagsSet + numRes
  print("Summary: date: %s, tagsSet: %s, Function:testsystems"%(datetime.datetime.now(),tagsSet))

  sandboxes = readConfigLines('/etc/redelk/known_sandboxes.conf')
  tagsSet = 0
  for item in sandboxes:
    numRes = 3
    while numRes > 0:
      #sys.stdout.write('.')
      #sys.stdout.flush()
      r=queryFromConfig(item,"beacondb")
      setTags('sandboxes_v02',r)
      r2=queryFromConfig(item,"rtops-*")
      setTags('sandboxes_v02',r2)
      numRes = len(r) + len(r2)
      tagsSet = tagsSet + numRes
  print("Summary: date: %s, tagsSet: %s, Function:sandboxes"%(datetime.datetime.now(),tagsSet))

  ipList = '/etc/redelk/torexitnodes.conf'
  tagsSet = 0
  tagsSet = findIPLines(ipList,"torexitnodes_v01")
  print("Summary: date: %s, tagsSet: %s, Function:torexitnodes"%(datetime.datetime.now(),tagsSet))

  ipList = '/etc/redelk/iplist_redteam.conf'
  tagsSet = 0
  tagsSet = findIPLines(ipList,"iplist_redteam_v01")
  print("Summary: date: %s, tagsSet: %s, Function:iplist_redteam"%(datetime.datetime.now(),tagsSet))

  ipList = '/etc/redelk/iplist_customer.conf'
  tagsSet = 0
  tagsSet = findIPLines(ipList,"iplist_customer_v01")
  print("Summary: date: %s, tagsSet: %s, Function:iplist_customer"%(datetime.datetime.now(),tagsSet))

  ipList = '/etc/redelk/iplist_unknown.conf'
  tagsSet = 0
  tagsSet = findIPLines(ipList,"iplist_unknown_v01")
  print("Summary: date: %s, tagsSet: %s, Function:iplist_unknown"%(datetime.datetime.now(),tagsSet))

  tagsSet = 0
  tagsSet = enrich_greynoise()
  print("Summary: date: %s, tagsSet: %s, Function:enrich_greynoise"%(datetime.datetime.now(),tagsSet))
