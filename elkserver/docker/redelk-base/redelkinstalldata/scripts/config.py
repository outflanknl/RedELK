#!/usr/bin/python3
"""
Part of RedELK

Script to load the config file

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""

import json
import logging

with open('/etc/redelk/config.json') as json_data:
    d = json.load(json_data)

# -- logging
# CRITICAL, 50
# ERROR, 40
# WARNING, 30
# INFO, 20
# DEBUG, 10
# NOTSET, 0

LOGLEVEL = logging.WARN
if "loglevel" in d:
    LOGLEVEL = d['loglevel']

# -- directory for cache files (including shelves)
TEMP_DIR = "/tmp"
if "tempDir" in d:
    TEMP_DIR = d['tempDir']

# -- Notifications
notifications = {
    'email': {
        'enabled': False,
        'smtp': {
            'host': 'localhost',
            'port': 25,
            'login': '',
            'pass': ''
        },
        'from': '',
        'to': []
    },
    'msteams': {
        'enabled': False,
        'webhook_url': ''
    },
    'slack': {
        'enabled': False,
        'webhook_url': ''
    }
}
if 'notifications' in d:
    for n in d['notifications']:
        notifications[n] = d['notifications'][n]

# -- Alarms
alarms = {
    'alarm_filehash': {
        'enabled': False,
        'interval': 300,
        'vt_api_key': '',  # Virustotal API
        'ibm_basic_auth': '',  # IBM X-Force API (can be retreived from a sample call on their swagger test site)
        'ha_api_key': ''  # Hybrid Analysis API
    },
    'alarm_httptraffic': {
        'enabled': False,
        'interval': 310,
        'notify_interval': 86400  # Only notify on the same IP hit every 24h by default
    },
    'alarm_useragent': {
        'enabled': False,
        'interval': 320
    },
    'alarm_dummy': {
        'enabled': False,
        'interval': 300
    }
}
if 'alarms' in d:
    for a in d['alarms']:
        alarms[a] = d['alarms'][a]

# -- Enrichments modules
enrich = {
    'enrich_csbeacon': {
        'enabled': True,
        'interval': 300
    },
    'enrich_greynoise': {
        'enabled': True,
        'interval': 310,
        'cache': 86400,  # Only query for the same IP hit every 24h by default
        'api_key': 'cEwJeLyDkNSXzabKNvzJSzZjZW0xEJYSYvf2nfhmmaXQHfCA8bJb49AvI3DF5Tlx'  # Greynoise Community API Key - Default RedELK key if none provided
    },
    'enrich_tor': {
        'enabled': True,
        'interval': 320,
        'cache': 3600
    },
    'enrich_iplists': {
        'enabled': True,
        'interval': 330
    },
    'enrich_synciplists': {
        'enabled': True,
        'interval': 360
    }
}
if 'enrich' in d:
    for e in d['enrich']:
        enrich[e] = d['enrich'][e]

es_connection = ['http://localhost:9200']
if 'es_connection' in d:
    es_connection = d['es_connection']
