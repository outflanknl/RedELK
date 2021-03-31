import json
import logging

with open('/etc/redelk/config.json') as json_data:
    d = json.load(json_data)

# -- General
Verbosity = 0  # Verbosity
if "Verbosity" in d:
    Verbosity = int(d['Verbosity'])


# -- logging
#CRITICAL, 50
#ERROR, 40
#WARNING, 30
#INFO, 20
#DEBUG, 10
#NOTSET, 0

DEBUG = 0  # Debug 1 or 0
if "DEBUG" in d:
    DEBUG = int(d['DEBUG'])

LOGLEVEL = logging.INFO
if "LOGLEVEL" in d:
    LOGLEVEL = int(d['LOGLEVEL'])

# -- directory for cache files (including shelves)
tempDir = "/tmp"
if "tempDir" in d:
    tempDir = d['tempDir']

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
        'cache': 86400
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
