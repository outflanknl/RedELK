#!/usr/bin/python3
"""
Part of RedELK

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import copy
import datetime
import json
import logging
import os

from elasticsearch import Elasticsearch
import urllib3

import config

urllib3.disable_warnings()
es = Elasticsearch(config.es_connection, verify_certs=False)

logger = logging.getLogger('helpers')


def pprint(to_print):
    """ Returns a visual representation of an object """
    if isinstance(to_print, type(str)):
        return to_print
    out_string = json.dumps(to_print, indent=2, sort_keys=True)
    return out_string


def get_value(path, source, default_value=None):
    """ Gets the value in source based on the provided path, or 'default_value' if not exists (default: None) """
    split_path = path.split('.')
    if split_path[0] in source:
        if len(split_path) > 1:
            return get_value('.'.join(split_path[1:]), source[split_path[0]])
        if split_path[0] == 'ip':
            if isinstance(source[split_path[0]], type([])):
                return source[split_path[0]][0]
        return source[split_path[0]]
    return default_value


def get_query(query, size=5000, index='redirtraffic-*'):
    """ Get results via ES query. Returns [] if nothing found """
    es_query = {'query': {'query_string': {'query': query}}}
    # pylint: disable=unexpected-keyword-arg
    es_result = es.search(index=index, body=es_query, size=size)
    if es_result['hits']['total']['value'] == 0:
        return []
    return es_result['hits']['hits']


def get_hits_count(query, index="redirtraffic-*"):
    """ Returns the total number of hits for a given query """
    es_query = {'query': {'query_string': {'query': query}}}
    # pylint: disable=unexpected-keyword-arg
    es_result = es.search(index=index, body=es_query, size=0)
    return es_result['hits']['total']['value']


def raw_search(query, size=10000, index="redirtraffic-*"):
    """ Execute a raw ES query. Returns the hits or None if no results """
    # pylint: disable=unexpected-keyword-arg
    es_result = es.search(index=index, body=query, size=size)
    if es_result['hits']['total']['value'] == 0:
        return None
    return es_result


def set_tags(tag, lst):
    """ Sets tag to all objects in lst """
    for doc in lst:
        if 'tags' in doc['_source'] and tag not in doc['_source']['tags']:
            doc['_source']['tags'].append(tag)
        else:
            doc['_source']['tags'] = [tag]
        es.update(index=doc['_index'], id=doc['_id'], body={'doc': doc['_source']})


def add_tags_by_query(tags, query, index='redirtraffic-*'):
    """ Add tags by DSL query in batch """
    tags_string = ','.join(map(repr, tags))

    update_q = {
        'script': {
            'source': 'ctx._source.tags.add([%s])' % tags_string,
            'lang': 'painless'
        },
        'query': query
    }
    return es.update_by_query(index=index, body=update_q)


def add_alarm_data(doc, data, alarm_name, alarmed=True):
    """ Adds alarm extra data to the source doc in ES """
    now_str = datetime.datetime.utcnow().isoformat()
    # Create the alarm field if it doesn't exist yet
    if 'alarm' not in doc['_source']:
        doc['_source']['alarm'] = {}

    # Set the last checked date
    data['last_checked'] = now_str
    doc['_source']['alarm']['last_checked'] = now_str

    # set the last alarmed date (if alarmed)
    if alarmed:
        doc['_source']['alarm']['last_alarmed'] = now_str
        data['last_alarmed'] = now_str

    # Add the extra data
    doc['_source']['alarm'][alarm_name] = data

    es.update(index=doc['_index'], id=doc['_id'], body={'doc': doc['_source']})
    return doc


def set_checked_date(doc):
    """ Sets the alarm.last_checked date to an ES doc """
    if 'alarm' in doc['_source']:
        doc['_source']['alarm']['last_checked'] = datetime.datetime.utcnow().isoformat()
    else:
        doc['_source']['alarm'] = {
            'last_checked': datetime.datetime.utcnow().isoformat()
        }
    es.update(index=doc['_index'], id=doc['_id'], body={'doc': doc['_source']})
    return doc


def group_hits(hits, groupby, res=None):
    """ Takes a list of hits and a list of field names (dot notation) and returns a grouped list """
    if len(groupby) > 0:
        hits_list = dict()
        # First time in the loop
        if res is None:
            for hit in hits:
                value = get_value('_source.%s' % groupby[0], hit)
                if value in hits_list:
                    hits_list[value].append(hit)
                else:
                    hits_list[value] = [hit]
        else:
            for key, val in res.items():
                for hit in val:
                    value = get_value('_source.%s' % groupby[0], hit)
                    tmp_key = '%s / %s' % (key, value)
                    if tmp_key in hits_list:
                        hits_list[tmp_key].append(hit)
                    else:
                        hits_list[tmp_key] = [hit]
        groupby.pop(0)
        return group_hits(hits, groupby, hits_list)

    if res is None:
        return hits

    tmp_hits = []
    for key, value in res.items():
        tmp_hits.append(value[0])

    return tmp_hits


def get_last_run(module_name):
    """ Returns the last time the module did run """
    try:
        query = {'query': {'term': {'module.name': module_name}}}
        es_result = raw_search(query, index='redelk-modules')
        if len(es_result['hits']['hits']) > 0:
            es_timestamp = get_value('_source.module.last_run.timestamp', es_result['hits']['hits'][0])
            es_date = datetime.datetime.strptime(es_timestamp, '%Y-%m-%dT%H:%M:%S.%f')
            return es_date
        else:
            return datetime.datetime.fromtimestamp(0)
    # pylint: disable=broad-except
    except Exception as error:
        logger.debug('Error parsing last run time: %s', error)
        return datetime.datetime.fromtimestamp(0)


def module_did_run(module_name, module_type='unknown', status='unknown', message=None, count=0):
    """ Returns true if the module already ran, false otherwise """
    logger.debug('Module did run: %s:%s [%s] %s', module_type, module_name, status, message)
    try:
        now_ts = datetime.datetime.utcnow().isoformat()
        doc = {
            'module': {
                'name': module_name,
                'type': module_type,
                'last_run': {
                    'timestamp': now_ts,
                    'status': status,
                    'count': count
                }
            }
        }
        if message:
            doc['module']['last_run']['message'] = message
        es.index(index='redelk-modules', id=module_name, body=doc)
        return True
    # pylint: disable=broad-except
    except Exception as error:
        logger.error('Error writting last run time for module %s: %s',
                     module_name, os.path.join(config.TEMP_DIR, module_name))
        logger.exception(error)
        return False

def module_should_run(module_name, module_type):
    """Check if the module is enabled and when is the last time the module ran.
    If the last time is before now - interval, the module will be allowed to run"""
    if module_type == 'redelk_alarm':

        if module_name not in config.alarms:
            logger.warning('Missing configuration for alarm [%s]. Will not run!', module_name)
            return False

        if 'enabled' in config.alarms[module_name] and not config.alarms[module_name]['enabled']:
            logger.warning('Alarm module [%s] disabled in configuration file. Will not run!', module_name)
            return False

        if 'interval' in config.alarms[module_name]:
            interval = config.alarms[module_name]['interval']
        else:
            interval = 360

    elif module_type == 'redelk_enrich':

        if module_name not in config.enrich:
            logger.warning('Missing configuration for enrichment module [%s]. Will not run!', module_name)
            return False

        if 'enabled' in config.enrich[module_name] and not config.enrich[module_name]['enabled']:
            logger.warning('Enrichment module [%s] disabled in configuration file. Will not run!', module_name)
            return False

        if 'interval' in config.enrich[module_name]:
            interval = config.enrich[module_name]['interval']
        else:
            interval = 360

    else:
        logger.warning('Invalid module type for shouldModuleRun(%s, %s)', module_name, module_type)
        return False

    now = datetime.datetime.utcnow()
    last_run = get_last_run(module_name)
    interval = datetime.timedelta(seconds=interval)
    last_run_max = now - interval

    should_run = last_run < last_run_max

    if not should_run:
        logger.info('Module [%s] already ran within the interval of %s seconds (%s)',
                    module_name, interval, last_run.isoformat())
    else:
        logger.info('All checks ok for module [%s]. Module should run.', module_name)
        logger.debug('Last run: %s | Last run max: %s', last_run.isoformat(), last_run_max.isoformat())
    return should_run


def get_initial_alarm_result():
    """ Returns the initial_alarm_result object """
    return copy.deepcopy(initial_alarm_result)

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
