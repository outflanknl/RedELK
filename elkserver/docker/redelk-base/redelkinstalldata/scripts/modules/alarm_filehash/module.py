#!/usr/bin/python3
"""
Part of RedELK

This check queries public sources given a list of md5 hashes.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging
import traceback

from config import alarms
from iocsources import ioc_hybridanalysis as ha
from iocsources import ioc_ibm as ibm
from iocsources import ioc_vt as vt
from modules.helpers import (add_alarm_data, get_initial_alarm_result,
                             get_query, get_value, raw_search, set_tags)

info = {
    'version': 0.1,
    'name': 'Test file hash against public sources',
    'alarmmsg': 'MD5 HASH SEEN ONLINE',
    'description': 'This check queries public sources given a list of md5 hashes.',
    'type': 'redelk_alarm',   # Could also contain redelk_enrich if it was an enrichment module
    'submodule': 'alarm_filehash'
}


class Module():
    """ Test file hash against public sources """
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        self.interval = alarms[info['submodule']]['interval'] if info['submodule'] in alarms else 360

    def run(self):
        """ Run the alarm module """
        ret = get_initial_alarm_result()
        ret['info'] = info
        ret['fields'] = ['agent.hostname', '@timestamp', 'host.name', 'user.name', 'ioc.type', 'file.name', 'file.hash.md5', 'c2.message', 'alarm.alarm_filehash']
        ret['groupby'] = ['file.hash.md5']
        try:
            report = self.alarm_check()
            ret['hits']['hits'] = report['hits']
            ret['mutations'] = report['mutations']
            ret['hits']['total'] = len(report['hits'])
        except Exception as error:
            stack_trace = traceback.format_exc()
            ret['error'] = stack_trace
            self.logger.exception(error)
            raise
        self.logger.info('finished running module. result: %s hits', ret['hits']['total'])
        return ret

    def alarm_check(self):
        """ This check queries public sources given a list of md5 hashes. If a hash was seen we set an alarm """
        es_query = 'c2.log.type:ioc AND NOT tags:alarm_filehash AND ioc.type:file'
        alarmed_md5_q = {
            "aggs": {
                "interval_filter": {
                    "filter": {
                        "range": {
                            "alarm.last_checked": {
                                "gte": "now-%ds" % self.interval,
                                "lt": "now"
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
        self.logger.debug('Running query %s', es_query)
        # FIRST WE GET ALL IOC's
        iocs = get_query(es_query, 10000, index='rtops-*')
        self.logger.debug('found ioc: %s', iocs)

        # Then we get an aggregation of all md5 alarmed within the last 'interval' time
        self.logger.debug('Running query %s', alarmed_md5_q)
        already_alarmed_result = raw_search(alarmed_md5_q, index='rtops-*')

        already_checked = []
        already_alarmed = []

        if already_alarmed_result:
            self.logger.debug(already_alarmed_result['aggregations'])

            # add md5 hashes that have been checked within the 'interval' in 'already_checked'
            for hit in already_alarmed_result['aggregations']['interval_filter']['md5_interval']['buckets']:
                already_checked.append(hit['key'])

            # add md5 hashes that have been alarmed previously in 'already_alarmed'
            for hit in already_alarmed_result['aggregations']['alarmed_filter']['md5_alarmed']['buckets']:
                already_alarmed.append(hit['key'])

        # Group all hits per md5 hash
        md5_dict = self.group_hits(iocs, already_alarmed, already_checked)

        # Create an array with all md5 hashes to send to the different providers
        # we now have an array with unique md5's to go test
        md5_list = []
        for md5 in md5_dict:
            md5_list.append(md5)

        self.logger.debug('md5 hashes to check: %s', md5_list)

        # Run the checks
        check_results = self.check_hashes(md5_list)

        # Get the alarmed hashes with their corresponding mutations
        alarmed_hashes = self.get_mutations(check_results)

        # Get the report
        report = self.build_report(md5_dict, alarmed_hashes)

        return report

    def group_hits(self, iocs, already_alarmed, already_checked):
        """ Returns all hits grouped by md5 hash """
        md5_dict = {}
        md5_should_check = {}

        # Group all hits per md5 hash value
        for ioc in iocs:
            md5 = get_value('_source.file.hash.md5', ioc)
            if md5 in md5_dict:
                md5_dict[md5].append(ioc)
            else:
                md5_dict[md5] = [ioc]

            should_check = True
            # Check if the IOC has already been alarmed
            if md5 in already_alarmed:
                # Skip it
                should_check = False
                # Set the last checked date
                add_alarm_data(ioc, {}, info['submodule'], False)
                # Tag the doc as alarmed
                set_tags(info['submodule'], [ioc])

            # Check if the IOC has already been checked within 'interval'
            if md5 in already_checked:
                # Skip if for now
                should_check = False

            if md5 in md5_should_check:
                md5_should_check[md5] = should_check & md5_should_check[md5]
            else:
                md5_should_check[md5] = should_check
            # self.logger.debug('Should check: %s' % md5ShouldCheck[h])

        for md5 in dict.copy(md5_dict):
            # If we should not check the hash, remove it from the list
            if md5 in md5_should_check and not md5_should_check[md5]:
                self.logger.debug('[%s] md5 hash already checked within interval or already alarmed previously, skipping', md5)
                del md5_dict[md5]

        return md5_dict

    def check_hashes(self, md5_list):
        """ Check md5 hashes with all providers """

        results = {}

        # ioc VirusTotal
        self.logger.debug('Checking IOC against VirusTotal')
        vt_check = vt.VT(alarms[info['submodule']]['vt_api_key'])
        vt_check.test(md5_list)
        results['VirusTotal'] = vt_check.report
        self.logger.debug('Results from VirusTotal: %s', vt_check.report)

        # ioc IBM x-force
        self.logger.debug('Checking IOC against IBM X-Force')
        ibm_check = ibm.IBM(alarms[info['submodule']]['ibm_basic_auth'])
        ibm_check.test(md5_list)
        results['IBM X-Force'] = ibm_check.report
        self.logger.debug('Results from IBM X-Force: %s', ibm_check.report)

        # ioc Hybrid Analysis
        self.logger.debug('Checking IOC against Hybrid Analysis')
        ha_check = ha.HA(alarms[info['submodule']]['ha_api_key'])
        ha_check.test(md5_list)
        results['Hybrid Analysis'] = ha_check.report
        self.logger.debug('Results from Hybrid Analysis: %s', ha_check.report)

        return results

    def get_mutations(self, check_results):
        """ Add the mutations to be returned """
        # Will store mutations per hash (temporarily)
        alarmed_hashes = {}
        # Loop through the engines
        for engine in check_results.keys():
            # Loop through the hashes results
            for md5 in check_results[engine].keys():
                if isinstance(check_results[engine][md5], type({})):
                    if check_results[engine][md5]['result'] == 'newAlarm':
                        # If hash was already alarmed by an engine
                        if md5 in alarmed_hashes:
                            alarmed_hashes[md5][engine] = check_results[engine][md5]
                        else:
                            alarmed_hashes[md5] = {
                                engine: check_results[engine][md5]
                            }
        return alarmed_hashes

    def build_report(self, md5_dict, alarmed_hashes):
        """ Build report to be returned by the alarm """
        # Prepare the object to be returned
        report = {
            'mutations': {},
            'hits': []
        }
        # Loop through all hashes
        for md5 in md5_dict:
            # Loop through all related ES docs
            for ioc in md5_dict[md5]:
                # Hash has been found in one of the engines and should be alarmed
                if md5 in alarmed_hashes.keys():
                    report['mutations'][ioc['_id']] = alarmed_hashes[md5]
                    report['hits'].append(ioc)
                # Hash was not found so we update the last_checked date
                else:
                    self.logger.debug('md5 hash not alarmed, updating last_checked date: [%s]', md5)
                    add_alarm_data(ioc, {}, info['submodule'], False)

        return report
