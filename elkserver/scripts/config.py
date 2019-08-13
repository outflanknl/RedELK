import json

with open('/etc/redelk/alarm.json.conf') as json_data:
    d = json.load(json_data)

#### General
Verbosity = 0 #Verbosity
if "Verbosity" in d: Verbosity = int(d['Verbosity'])

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

#### SMTP settings
smtpSrv=''
if "smtpSrv" in d: smtpSrv = d['smtpSrv']

smtpPort=25
if "smtpPort" in d: smtpPort = int(d['smtpPort'])

smtpName=""
if "smtpName" in d: smtpName = d['smtpName']

smtpPass=""
if "smtpPass" in d: smtpPass = d['smtpPass']

fromAddr=""
if "fromAddr" in d: fromAddr = d['fromAddr']

toAddrs=[""]
if "toAddrs" in d: toAddrs = d['toAddrs']

#### directory for cache files (including shelves)
tempDir="/tmp"
if "tempDir" in d: tempDir = d['tempDir']
