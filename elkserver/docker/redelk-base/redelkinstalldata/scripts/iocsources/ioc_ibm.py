#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
import requests
import os
import json
import logging

class IBM():
    def __init__(self, basic_auth):
        self.report = {}
        self.report['source'] = 'IBM X-Force'
        self.logger = logging.getLogger('ioc_ibm')
        self.basic_auth = basic_auth

    def scansAvailable(self):
        # this function must determine the number of scans de last X time to ensure we stay within rate limiting
        return(True)

    def IBMreport(self, hashlist):
        r = []
        headers = {'Authorization': self.basic_auth}
        for h in hashlist:
            response = requests.get('https://api.xforce.ibmcloud.com/malware/%s' % h, headers=headers)
            if response.status_code == 200:
                json_response = response.json()
                json_response['query_hash'] = h
            else:
                json_response = {}
                json_response['query_hash'] = h
            r.append([response.status_code, json_response])
        return(r)

    def test(self, list):
        l = list
        for md5 in list:
            self.report[md5] = {
                'record': {},
                'result': ''
            }
        self.logger.debug('Checcking IOCs on IBM X-Force: %s' % list)
        r = self.IBMreport(list)
        # here we neeed to work with the IBM response_code
        # Looping over individual results
        for res in r:
            self.logger.debug('status code %s' % res[0])
            if res[1] != None:  # We have json response!
                report = res[1]
                md5 = report['query_hash']
                if 'malware' in report:
                    # We have a malware ALARM
                    # Seen ALARM regardless of outcome
                    self.report[md5]['record'] = report
                    self.report[md5]['result'] = 'newAlarm'
                elif 'error' in report:
                    # Malware likely not Seeen:
                    self.report[md5]['result'] = 'clean'
                else:
                    # Unexpected out or 404 which means clean
                    self.logger.warn('WEIRD OUTCOME from IBM on %s => %s' % (md5, json.dumps(report)))
                    self.report[md5]['result'] = 'clean'
