#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
import json
import datetime
import config
import urllib3
import logging
import os
import copy
from elasticsearch import Elasticsearch

urllib3.disable_warnings()
es = Elasticsearch(config.es_connection, verify_certs=False)

logger = logging.getLogger('helpers')


def pprint(r):
    if isinstance(r, type(str)):
        return(r)
    s = json.dumps(r, indent=2, sort_keys=True)
    return(s)


def getValue(path, source):
    p = path.split('.')
    if p[0] in source:
        if len(p) > 1:
            return getValue('.'.join(p[1:]), source[p[0]])
        else:
            if p[0] == 'ip':
                if isinstance(source[p[0]], type([])):
                    return source[p[0]][0]
                else:
                    return source[p[0]]
            else:
                return source[p[0]]
    else:
        return None


def getQuery(query, size=5000, index='redirtraffic-*'):
    q3 = {'query': {'query_string': {'query': query}}}
    r3 = es.search(index=index, body=q3, size=size)
    if(r3['hits']['total']['value'] == 0):
        return([])
    return(r3['hits']['hits'])


def guiQueryWindow(q, start, end):
    q = {
        "query": {
            "bool": {
                "filter": [
                    {
                        "query_string": {
                            "query": "%s" % q
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "from": "%s" % start,
                                "to": "%s" % end
                            }
                        }
                    }
                ]
            }
        }
    }
    return(q)


def countQuery(query, index="redirtraffic-*"):
    q3 = {'query': {'query_string': {'query': query}}}
    r3 = es.search(index=index, body=q3, size=0)
    return(r3['hits']['total']['value'])


def rawSearch(query, size=10000, index="redirtraffic-*"):
    r3 = es.search(index=index, body=query, size=size)
    if(r3['hits']['total']['value'] == 0):
        return(None)
    return(r3)


# Sets tag to all objects in lst
def setTags(tag, lst):
    for doc in lst:
        if 'tags' in doc['_source'] and tag not in doc['_source']['tags']:
            doc['_source']['tags'].append(tag)
        else:
            doc['_source']['tags'] = [tag]
        es.update(index=doc['_index'], id=doc['_id'], body={'doc': doc['_source']})


# Add tags by DSL query in batch
def addTagsByQuery(tags, query, index='redirtraffic-*'):
    tags_string = ','.join(map(repr, tags))

    update_q = {
        'script': {
            'source': 'ctx._source.tags.add([%s])' % tags_string,
            'lang': 'painless'
        },
        'query': query
    }
    return(es.update_by_query(index=index, body=update_q))


# Adds alarm extra data to the source doc in ES
def addAlarmData(doc, data, alarm_name, alarmed=True):
    ts = datetime.datetime.utcnow().isoformat()
    # Create the alarm field if it doesn't exist yet
    if 'alarm' not in doc['_source']:
        doc['_source']['alarm'] = {}

    # Set the last checked date
    data['last_checked'] = ts
    doc['_source']['alarm']['last_checked'] = ts

    # set the last alarmed date (if alarmed)
    if alarmed:
        doc['_source']['alarm']['last_alarmed'] = ts
        data['last_alarmed'] = ts

    # Add the extra data
    doc['_source']['alarm'][alarm_name] = data

    es.update(index=doc['_index'], id=doc['_id'], body={'doc': doc['_source']})
    return(doc)


# Sets the alarm.last_checked date to an ES doc
def setCheckedDate(doc):
    if 'alarm' in doc['_source']:
        doc['_source']['alarm']['last_checked'] = datetime.datetime.utcnow().isoformat()
    else:
        doc['_source']['alarm'] = {
            'last_checked': datetime.datetime.utcnow().isoformat()
        }
    es.update(index=doc['_index'], id=doc['_id'], body={'doc': doc['_source']})
    return(doc)


# Takes a list of hits and a list of field names (dot notation) and returns a grouped list
def groupHits(hits, groupby, res=None):
    if(len(groupby) > 0):
        lHits = dict()
        # First time in the loop
        if res is None:
            for h in hits:
                v = getValue('_source.%s' % groupby[0], h)
                if v in lHits:
                    lHits[v].append(h)
                else:
                    lHits[v] = [h]
        else:
            for key, val in res.items():
                for h in val:
                    v = getValue('_source.%s' % groupby[0], h)
                    tmpKey = '%s / %s' % (key, v)
                    if tmpKey in lHits:
                        lHits[tmpKey].append(h)
                    else:
                        lHits[tmpKey] = [h]
        groupby.pop(0)
        return(groupHits(hits, groupby, lHits))
    else:
        if res is None:
            return hits
        else:
            tmpHits = []
            for k, v in res.items():
                #                v[0]['_groupby'] = k
                tmpHits.append(v[0])
            return tmpHits


def getLastRun(module_name):
    try:
        q = {'query': {'term': {'module.name': module_name}}}
        res = rawSearch(q, index='redelk-modules')
        if len(res['hits']['hits']) > 0:
            es_timestamp = getValue('_source.module.last_run.timestamp', res['hits']['hits'][0])
            ts = datetime.datetime.strptime(es_timestamp, '%Y-%m-%dT%H:%M:%S.%f')
            return(ts)
        else:
            return(datetime.datetime.fromtimestamp(0))
    except Exception as e:
        logger.debug('Error parsing last run time: %s' % e)
        return(datetime.datetime.fromtimestamp(0))


def moduleDidRun(module_name, module_type='unknown', status='unknown', message=None, count=0):
    logger.debug('Module did run: %s:%s [%s] %s' % (module_type, module_name, status, message))
    try:
        ts = datetime.datetime.utcnow().isoformat()
        doc = {
            'module': {
                'name': module_name,
                'type': module_type,
                'last_run': {
                    'timestamp': ts,
                    'status': status,
                    'count': count
                }
            }
        }
        if message:
            doc['module']['last_run']['message'] = message
        es.index(index='redelk-modules', id=module_name, body=doc)
        return(True)
    except Exception as e:
        logger.error('Error writting last run time for module %s: %s' %
                     (module_name, os.path.join(config.tempDir, module_name)))
        logger.exception(e)
        return(False)

# The following function will check if the module is enabled and when is the last time the module ran.
# If the last time is before now - interval, the module will be allowed to run


def shouldModuleRun(module_name, module_type):
    if module_type == 'redelk_alarm':

        if module_name not in config.alarms:
            logger.warn('Missing configuration for alarm [%s]. Will not run!', module_name)
            return(False)

        if 'enabled' in config.alarms[module_name] and not config.alarms[module_name]['enabled']:
            logger.warn('Alarm module [%s] disabled in configuration file. Will not run!' % module_name)
            return(False)

        if 'interval' in config.alarms[module_name]:
            interval = config.alarms[module_name]['interval']
        else:
            interval = 360

    elif module_type == 'redelk_enrich':

        if module_name not in config.enrich:
            logger.warn('Missing configuration for enrichment module [%s]. Will not run!', module_name)
            return(False)

        if 'enabled' in config.enrich[module_name] and not config.enrich[module_name]['enabled']:
            logger.warn('Enrichment module [%s] disabled in configuration file. Will not run!' % module_name)
            return(False)

        if 'interval' in config.enrich[module_name]:
            interval = config.enrich[module_name]['interval']
        else:
            interval = 360

    else:
        logger.warn('Invalid module type for shouldModuleRun(%s, %s)' % (module_name, module_type))
        return(False)

    now = datetime.datetime.utcnow()
    last_run = getLastRun(module_name)
    ival = datetime.timedelta(seconds=interval)
    last_run_max = now - ival

    should_run = last_run < last_run_max

    if not should_run:
        logger.info('Module [%s] already ran within the interval of %s seconds (%s)' %
                    (module_name, interval, last_run.isoformat()))
    else:
        logger.info('All checks ok for module [%s]. Module should run.' % module_name)
        logger.debug('Last run: %s | Last run max: %s' % (last_run.isoformat(), last_run_max.isoformat()))
    return(should_run)


def get_initial_alarm_result():
    return(copy.deepcopy(initial_alarm_result))

initial_alarm_result = {
    'info': {
        'version': 0.0,
        'name': 'unknown',
        'alarmmsg': 'unkown',
        'description': 'unknown',
        'type': 'redelk_alarm',
        'submodule': 'unknown'
    },
    'hits': {
        'hits': [],
        'total': 0
    },
    'mutations': {},
    'fields': ['host.name', 'user.name', '@timestamp', 'c2.message'],
    'groupby': []
}
