#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
from modules.helpers import *
from config import interval, alarms
from iocsources import ioc_vt as vt
from iocsources import ioc_ibm as ibm
from iocsources import ioc_hybridanalysis as ha
import traceback
import logging

info = {
    'version': 0.1,
    'name': 'Test file hash against public sources',
    'alarmmsg': 'MD5 HASH SEEN ONLINE',
    'description': 'This check queries public sources given a list of md5 hashes.',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_filehash'
}


class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        pass

    def run(self):
        ret = initial_alarm_result
        ret['info'] = info
        ret['fields'] = ['agent.hostname','@timestamp', 'host.name', 'user.name', 'ioc.type', 'file.name', 'file.hash.md5', 'c2.message', 'alarm.alarm_filehash']
        ret['groupby'] = ['file.hash.md5']
        try:
            report = self.alarm_check()
            ret['hits']['hits'] = report['hits']
            ret['mutations'] = report['mutations']
            ret['hits']['total'] = len(report['hits'])
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            self.logger.exception(e)
            pass
        self.logger.info('finished running module. result: %s hits' % ret['hits']['total'])
        return(ret)

    def alarm_check(self):
        # This check queries public sources given a list of md5 hashes. If a hash was seen we set an alarm
        q = 'c2.log.type:ioc AND NOT tags:alarm_filehash AND ioc.type:file'
        alarmed_md5_q = {
            "aggs": {
                "interval_filter": {
                    "filter": {
                        "range": {
                            "alarm.last_checked": {
                                "gte":"now-%ds" % interval,
                                "lt":"now"
                            }
                        }
                    },
                    "aggs": {
                        "md5_interval": {
                            "terms": {
                                "field": "file.hash.md5"
                            }
                        }
                    }
                },
                "alarmed_filter": {
                    "filter": {
                        "terms": {
                            "tags": ["alarm_filehash"]
                        }
                    },
                    "aggs": {
                        "md5_alarmed": {
                            "terms": {
                                "field": "file.hash.md5"
                            }
                        }
                    }
                }
            }
        }
        report = {}
        iocs = []
        self.logger.debug('Running query %s' % q)
        # FIRST WE GET ALL IOC's
        i = countQuery(q, index='rtops-*')
        if i >= 10000:
            i = 10000
        iocs = getQuery(q, i, index='rtops-*')
        if type(iocs) != type([]):
            iocs = []
        self.logger.debug('found ioc: %s' % iocs)

        # Then we get an aggregation of all md5 alarmed within the last 'interval' time
        self.logger.debug('Running query %s' % alarmed_md5_q)
        omd5 = rawSearch(alarmed_md5_q, index='rtops-*')
        self.logger.debug(omd5['aggregations'])

        already_checked = []
        already_alarmed = []

        # add md5 hashes that have been checked within the 'interval' in 'already_checked'
        for h in omd5['aggregations']['interval_filter']['md5_interval']['buckets']:
            already_checked.append(h['key'])

        # add md5 hashes that have been alarmed previously in 'already_alarmed'
        for h in omd5['aggregations']['alarmed_filter']['md5_alarmed']['buckets']:
            already_alarmed.append(h['key'])

        md5d = {}
        md5s = []
        md5ShouldCheck = {}
        ival = timedelta(seconds=interval)
        last_checked_max = (datetime.utcnow() - ival)

        # Group all hits per md5 hash value
        for ioc in iocs:
            h = getValue('_source.file.hash.md5', ioc)
            if h in md5d:
                md5d[h].append(ioc)
            else:
                md5d[h] = [ioc]

            should_check = True
            # Check if the IOC has already been alarmed
            if h in already_alarmed:
                # Skip it
                should_check = False
                # Set the last checked date
                addAlarmData(ioc, {}, info['submodule'], False)
                # Tag the doc as alarmed
                setTags(info['submodule'], [ioc])

            # Check if the IOC has already been checked within 'interval'
            if h in already_checked:
                # Skip if for now
                should_check = False

            if h in md5ShouldCheck:
                md5ShouldCheck[h] = should_check & md5ShouldCheck[h]
            else:
                md5ShouldCheck[h] = should_check
            # self.logger.debug('Should check: %s' % md5ShouldCheck[h])

        for hash in dict.copy(md5d):
            # If we should not check the hash, remove it from the list
            if hash in md5ShouldCheck and md5ShouldCheck[hash] == False:
                self.logger.debug('[%s] md5 hash already checked within interval or already alarmed previously, skipping' % hash)
                del md5d[hash]

        # Create an array with all md5 hashes to send to the different providers
        # we now have an aray with unique md5's to go test
        for hash in md5d:
            md5s.append(hash)

        self.logger.debug('md5 hashes to check: %s' % md5s)

        reportI = {}

        # ioc VirusTotal
        self.logger.debug('Checking IOC against VirusTotal')
        t = vt.VT(alarms[info['submodule']]['vt_api_key'])
        t.test(md5s)
        reportI['VirusTotal'] = t.report
        self.logger.debug('Results from VirusTotal: %s' % t.report)

        # ioc IBM x-force
        self.logger.debug('Checking IOC against IBM X-Force')
        i = ibm.IBM(alarms[info['submodule']]['ibm_basic_auth'])
        i.test(md5s)
        reportI['IBM X-Force'] = i.report

        # ioc Hybrid Analysis
        self.logger.debug('Checking IOC against Hybrid Analysis')
        h = ha.HA(alarms[info['submodule']]['ha_api_key'])
        h.test(md5s)
        reportI['Hybrid Analysis'] = h.report

        # Will store mutations per hash (temporarily)
        alarmedHashes = {}
        # Loop through the engines
        for engine in reportI.keys():
            # Loop through the hashes results
            for hash in reportI[engine].keys():
                if type(reportI[engine][hash]) == type({}):
                    if reportI[engine][hash]['result'] == 'newAlarm':
                        # If hash was already alarmed by an engine
                        if hash in alarmedHashes:
                            alarmedHashes[hash][engine] = reportI[engine][hash]
                        else:
                            alarmedHashes[hash] = {
                                engine: reportI[engine][hash]
                            }

        # Prepare the object to be returned
        report = {
            'mutations': {},
            'hits': []
        }
        # Loop through all hashes
        for hash in md5d:
            # Loop through all related ES docs
            for ioc in md5d[hash]:
                # Hash has been found in one of the engines and should be alarmed
                if hash in alarmedHashes.keys():
                    report['mutations'][ioc['_id']] = alarmedHashes[hash]
                    report['hits'].append(ioc)
                # Hash was not found so we update the last_checked date
                else:
                    self.logger.debug('md5 hash not alarmed, updating last_checked date: [%s]' % hash)
                    addAlarmData(ioc, {}, info['submodule'], False)

        return(report)
