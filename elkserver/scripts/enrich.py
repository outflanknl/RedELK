#!/usr/bin/python3
#
# Part of RedELK
# Script to start enrichment process of data in elasticsearch
#
# Author: Outflank B.V. / Mark Bergman / @xychix
#
# License : BSD3
#
from elasticsearch import Elasticsearch
import json
import sys
import datetime
import time
from time import sleep
es  = Elasticsearch()

qSize = 10000

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
  r2 = es.search(index="rtops-*", size=qSize,body=q2)
  b = r2['hits']['hits'][0]
  #now we have a beacon
  return(b)

def enrichAllLinesWithBeacon(l1,b):
  tagsSet = 0
  #query for all not enriched lines make new L1 lines
  q3 = {'query': {'query_string': {'query': 'FILLME'}}}
  q3['query']['query_string']['query'] = "beacon_id:\"%s\" AND beat.name:%s AND NOT tags:enriched_v01"%(l1['_source']['beacon_id'],l1["_source"]['beat']['name'])
  r3 = es.search(index="rtops-*", size=qSize, body=q3)
  for l1 in r3['hits']['hits']:
    l1["_source"]['tags'].append("enriched_v01")
    for field in ["target_hostname","target_ipext","target_os","target_osversion","target_pid","target_user"]:
      try:
        l1["_source"][field] = b["_source"][field]
      except:
        pass
    es.update(index=l1['_index'],doc_type=l1['_type'],id=l1['_id'],body={'doc':l1['_source']})
    tagsSet = tagsSet + 1
    #sys.stdout.write('.')
    #sys.stdout.flush()
  return(tagsSet,r3['hits']['total'])

def getSet():
  #NOT tags:enriched_v01 AND NOT cslogtype:beacon_newbeacon AND cslogtype:beacon_*
  q3 = {'query': {'query_string': {'query': 'NOT tags:enriched_v01 AND NOT cslogtype:beacon_newbeacon AND (cslogtype:beacon_* OR cslogtype:ioc) AND NOT source:*unknown*'}}}
  r3 = es.search(index="rtops-*", size=qSize, body=q3)
  if(r3['hits']['total'] == 0):
    return(None,0)
  return(r3['hits']['hits'],r3['hits']['total'])

def enrichV1():
  tagsSet = 0
  doneList = []
  run = True
  while(run):
    doneList = []
    Set,rT = getSet()
    if Set == None:
      run = False
      break
    else:
      #we have some rtop-* lines that should be enriched.
      for line in Set:
        try:
          id = line['_source']['beacon_id']
        except:
          break
        if line['_source']['beacon_id'] not in doneList:
          b = getInitialBeaconLine(line)
          #sys.stdout.write('\n %s :'%b['_source']['beacon_id'])
          #sys.stdout.flush()
          newTags,rT2  = enrichAllLinesWithBeacon(line,b)
          tagsSet = tagsSet + newTags
          doneList.append(b['_source']['beacon_id'])
      #we might need a sleep here in order to allow ES to solve it's stuff. We could also just stop running as we would be restarted in a minute...
      #sleep(60)
      run = False # decided to never loop, cron will restart anyhows
  return(tagsSet,rT)

def queryFromConfig(line,index="beacondb"):
 lineA = line.split(';')
 q = lineA[0]
 f1 = lineA[1]
 f2 = lineA[2]
 f3 = lineA[3]
 q3 = {'query': {'query_string': {'query': 'FILLME'}}}
 query =  "NOT (tags:sandboxes_v01 OR tags:testsystems_v01) AND (target_user:%s %s target_hostname:%s %s target_ipint:%s)"%(f1,q,f2,q,f3)
 q3['query']['query_string']['query'] = query
 #print(query)
 r3 = es.search(index=index, size=qSize, body=q3)
 #print("found %s items"%len(r3['hits']['hits']))
 return(r3['hits']['hits'],r3['hits']['total'])

def queryBIG_OR(array,field,index,prefix="",postfix=""):
  sep = prefix
  query = ""
  for item in array:
    query = query + " %s %s:%s" % (sep, field,item)
    sep = "OR"
  query = query + postfix
  #print(index)
  #print(query)
  q3 = {'query': {'query_string': {'query': 'FILLME'}}}
  q3['query']['query_string']['query'] = query
  #print(query)
  r3 = es.search(index=index, size=qSize, body=q3)
  return(r3['hits']['hits'],r3['hits']['total'])

def setTags(tag,lst):
  for l in lst:
    l["_source"]['tags'].append(tag)
    r = es.update(index=l['_index'],doc_type =l['_type'],id=l['_id'],body={'doc':l['_source']})
    #sys.stdout.write('.')
    #sys.stdout.flush()

def buildQueryBIG_OR(array,field,index,prefix="",postfix="",fuzzy=False):
  sep = prefix
  query = ""
  for item in array:
    if fuzzy:
      query = query + " %s %s:*%s*" % (sep, field,item)
    else:
      query = query + " %s %s:%s" % (sep, field,item)
    sep = "OR"
  query = query + postfix
  return(query)

def setTagByQuery(query,tag,index="redirtraffic-*"):
  q3 = {'query': {'query_string': {'query': query }}}
  q3['script'] = {"inline": "ctx._source.tags.add(params.tag)","lang": "painless","params":{"tag":tag}}
  #return(q3)
  #pprint(q3)
  r3 = es.update_by_query(index=index, body=q3, size=-1, timeout="10m", wait_for_completion="false")
  taskStatus = None
  if 'task' in r3:
    taskId = r3['task']
    waitMore = True
    while(waitMore == True):
      taskStatus = es.tasks.get(taskId)
      if taskStatus['completed'] == True:
        waitMore = False
      else:
        print("[i] wating for task %s"%taskId)
        sleep(1)
  else:
  	return(None)
  r = 0
  if 'response' in taskStatus:   
    if 'updated' in taskStatus['response']:
      r =  taskStatus['response']['updated']
  return(r,r)

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

def findIPLines(fname,tag,field="redirtraffic.sourceip",fuzzy=False):
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
  r = 0
  rT = 0
  ipListList = []
  while len(ipList) > 0:
    ipListList.append(ipList[:250])
    ipList = ipList[250:]
  ListsCNT = len(ipListList)
  ListCNT = 1
  for ipL in ipListList:
    if len(ipL) > 0:
      print("[D] running an ip %s/%x"%(ListCNT,ListsCNT))
      ListCNT = ListCNT + 1
      query = buildQueryBIG_OR(ipL,field,"redirtraffic-*","NOT tags:%s AND ("%tag,")")
      r,rT = setTagByQuery(query,tag)
  return(r,rT)

#section build for greynoise, in essence loop over all items in index that don't have tag X set
def findUntaggedLines(tag,size=qSize,index="redirtraffic-*"):
  query = "NOT tags:%s"%tag
  q3 = {'query': {'query_string': {'query': 'FILLME'}}}
  q3['query']['query_string']['query'] = query
  r3 = es.search(index=index, body=q3, size=size)
  print("Query %s"%q3)
  print("items retreived %s"%len(r3['hits']['hits']))
  return(r3['hits']['hits'],r3['hits']['total'])

def enrich_greynoiseSet(handler):
  tag = "enrich_greynoise"
  Set,rT = findUntaggedLines(tag)
  cRes = 0
  for l in Set:
    l["_source"]['tags'].append(tag)
    try:
      ip = l["_source"]["redirtraffic.sourceip"]
      l["_source"]["greynoise"] = handler.queryIp(ip)
    except:
      pass
    r = es.update(index=l['_index'],doc_type=l['_type'],id=l['_id'],body={'doc':l['_source']})
    cRes += 1
  return(cRes,rT)

def enrich_greynoise():
  from class_greynoise import greynoise
  g = greynoise()
  run = True
  nTotal = 0
  rTt = 0
  while(run):
    nRes,rT = enrich_greynoiseSet(g)
    nTotal = nRes + nTotal
    rTt = rTt + rT
    if nRes == 0: 
      run = False
    else:
      #we might need a sleep here in order to allow ES to solve it's stuff. We could also just stop running as we would be restarted in a minute...
      #sleep(60)
      run = False # decided to never loop, cron will restart anyhows 
  return(nTotal,rTt)
#end section

def findTaggedLines(tag,size=qSize,index="redirtraffic-*"):
  query = "tags:%s"%tag
  q3 = {'query': {'query_string': {'query': 'FILLME'}}}
  q3['query']['query_string']['query'] = query
  r3 = es.search(index=index, body=q3, size=size)
  return(r3['hits']['hits'],r3['hits']['total'])

def deleteTag(tag,size=qSize,index="redirtraffic-*"):
  run = True
  totals = 0
  while(run):
    Set,rT = findTaggedLines(tag,size,index)
    cRes = len(Set)
    if cRes == 0: 
      run = False
    else:
      #we might need a sleep here in order to allow ES to solve it's stuff. We could also just stop running as we would be restarted in a minute...
      #sleep(60)
      run = False # decided to never loop, cron will restart anyhows 
    for l in Set:
      newSet = []
      for t in l["_source"]['tags']:
        if t != tag: newSet.append(t)
      l["_source"]['tags'] = newSet
      r = es.update(index=l['_index'],doc_type =l['_type'],id=l['_id'],body={'doc':l['_source']})
      totals = totals + 1
  return(totals)

####
if __name__ == '__main__':
  testsystems = readConfigLines('/etc/redelk/known_testsystems.conf')
  tagsSet = 0
  rTt = 0
  for item in testsystems:
    numRes = 0
    #while numRes > 0:
    #sys.stdout.write('.')
    #sys.stdout.flush()
    r,rT=queryFromConfig(item,"beacondb")
    setTags('testsystems_v01',r)
    r2,rT2=queryFromConfig(item,"rtops-*")
    setTags('testsystems_v01',r2)
    numRes = len(r) + len(r2)
    tagsSet = tagsSet + numRes
    rTt = rTt +rT + rT2
    #time.sleep(10) #allow ES to process all updated before requerying
  print("Summary: date: %s, tagsSet: %s, Function:testsystems (total to tag is %s)"%(datetime.datetime.now(),tagsSet,rTt))

  sandboxes = readConfigLines('/etc/redelk/known_sandboxes.conf')
  tagsSet = 0
  rTt = 0
  for item in sandboxes:
    numRes = 0
    r,rT=queryFromConfig(item,"beacondb")
    setTags('sandboxes_v01',r)
    r2,rT2=queryFromConfig(item,"rtops-*")
    setTags('sandboxes_v01',r2)
    numRes = len(r) + len(r2)
    tagsSet = tagsSet + numRes
    rTt = rTt +rT + rT2
  print("Summary: date: %s, tagsSet: %s, Function:sandboxes (total to tag is %s)"%(datetime.datetime.now(),tagsSet,rTt))

  ipList = '/etc/redelk/torexitnodes.conf'
  tagsSet = 0
  tagsSet,rT = findIPLines(ipList,"torexitnodes_v01")
  print("Summary: date: %s, tagsSet: %s, Function:torexitnodes (total to tag is %s)"%(datetime.datetime.now(),tagsSet,rT))

  ipList = '/etc/redelk/iplist_redteam.conf'
  tagsSet = 0
  tagsSet,rT = findIPLines(ipList,"iplist_redteam_v01")
  print("Summary: date: %s, tagsSet: %s, Function:iplist_redteam (total to tag is %s)"%(datetime.datetime.now(),tagsSet,rT))

  ipList = '/etc/redelk/iplist_customer.conf'
  tagsSet = 0
  tagsSet,rT = findIPLines(ipList,"iplist_customer_v01")
  print("Summary: date: %s, tagsSet: %s, Function:iplist_customer (total to tag is %s)"%(datetime.datetime.now(),tagsSet,rT))

  ipList = '/etc/redelk/iplist_unknown.conf'
  tagsSet = 0
  tagsSet,rT = findIPLines(ipList,"iplist_unknown_v01")
  print("Summary: date: %s, tagsSet: %s, Function:iplist_unknown (total to tag is %s)"%(datetime.datetime.now(),tagsSet,rT))

  ipList = '/etc/redelk/iplist_alarmed.conf'
  tagsSet = 0
  tagsSet,rT = findIPLines(ipList,"iplist_alarmed_v01")
  print("Summary: date: %s, tagsSet: %s, Function:iplist_alarmed (total to tag is %s)"%(datetime.datetime.now(),tagsSet,rT))

  tagsSet = 0
  tagsSet,TotalNotTagged = enrichV1()
  print("Summary: date: %s, tagsSet: %s, Function:enrichV1 (total to tag is %s)"%(datetime.datetime.now(),tagsSet,TotalNotTagged))

  #tagsSet = 0
  #tagsSet,rT = enrich_greynoise()
  #print("Summary: date: %s, tagsSet: %s, Function:enrich_greynoise (total to tag is %s)"%(datetime.datetime.now(),tagsSet,rT))
