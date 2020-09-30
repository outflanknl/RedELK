from elasticsearch import Elasticsearch
import json
import sys
import datetime
import config
import socket
import traceback
es  = Elasticsearch(config.es_connection)

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
    r = es.update(index=l['_index'],doc_type=l['_type'],id=l['_id'],body={'_doc':l['_source']})
    #sys.stdout.write('.')
    #sys.stdout.flush()
