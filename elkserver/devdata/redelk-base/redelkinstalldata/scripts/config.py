import json

with open('/etc/redelk/config.json') as json_data:
    d = json.load(json_data)

#### General
Verbosity = 0 #Verbosity
if "Verbosity" in d: Verbosity = int(d['Verbosity'])

DEBUG = 0 #Debug 1 or 0
if "DEBUG" in d: DEBUG = int(d['DEBUG'])

interval = 3600 #interval for rechecking IOC's (in seconds)
if "interval" in d: interval = int(d['interval'])

#### HybridAnalysisAPIKEY
HybridAnalysisAPIKEY = ""
if "HybridAnalysisAPIKEY" in d: HybridAnalysisAPIKEY = d['HybridAnalysisAPIKEY']

#### directory for cache files (including shelves)
tempDir="/tmp"
if "tempDir" in d: tempDir = d['tempDir']

#### Notifications
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

#### Alarms
alarms = {
    'alarm_filehash': {
        'enabled': False,
        'vt_api_key': '', # Virustotal API
        'ibm_basic_auth': '', # IBM X-Force API (can be retreived from a sample call on their swagger test site)
        'ha_api_key': '' # Hybrid Analysis API
    },
    'alarm_httptraffic': {
        'enabled': False
    },
    'alarm_useragent': {
        'enabled': False
    },
    'alarm_dummy': {
        'enabled': False
    }
}
if 'alarms' in d:
    for a in d['alarms']:
        alarms[a] = d['alarms'][a]

es_connection = ['http://localhost:9200']
if 'es_connection' in d: es_connection = d['es_connection']
