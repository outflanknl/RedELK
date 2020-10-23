import json

with open('/etc/redelk/config.json') as json_data:
    d = json.load(json_data)

#### General
Verbosity = 0 #Verbosity
if "Verbosity" in d: Verbosity = int(d['Verbosity'])

DEBUG = 0 #Debug 1 or 0
if "DEBUG" in d: DEBUG = int(d['DEBUG'])

interval = 3600 #interval for rechecking IOC's
if "interval" in d: interval = int(d['interval'])


#### Virustotal API
vt_apikey = ""
if "vt_apikey" in d: vt_apikey = d['vt_apikey']

#### IBM X-Force API (can be retreived from a sample call on their swagger test site)
ibm_BasicAuth = ""
if "ibm_BasicAuth" in d: ibm_BasicAuth = d['ibm_BasicAuth']

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
    'alarm1': {
        'enabled': False
    },
    'alarm2': {
        'enabled': False
    },
    'alarm3': {
        'enabled': False
    }
}
if 'alarms' in d:
    for a in d['alarms']:
        alarms[a] = d['alarms'][a]

es_connection = ['http://localhost:9200']
if 'es_connection' in d: es_connection = d['es_connection']
