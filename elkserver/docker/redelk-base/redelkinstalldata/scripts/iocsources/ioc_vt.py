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

class VT():
    def __init__(self, api_key):
        self.report = {}
        self.report['source'] = 'Virus Total'
        self.logger = logging.getLogger('ioc_vt')
        self.api_key = api_key

    def scansAvailable(self):
        # this function must determine the number of scans de last X time to ensure we stay within rate limiting
        return(True)

    def virustotalReport(self, hashlist):
        params = {'apikey': self.api_key, 'resource': hashlist}
        headers = {
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'python'
        }
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                params=params, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
        else:
            json_response = None
        return(response.status_code, json_response)

    def test(self, list):
        l = list
        for md5 in list:
            self.report[md5] = {
                'record': {},
                'result': ''
            }
        r = self.virustotalReport(",".join(list))
        res = r[1]
        self.logger.debug('status code %s' % r[0])
        if type(res) != type([]):
            res = [res]  # dirty?
            self.logger.debug('just emties resultlist is was %s' % r[1])
        if len(res) > 0:  # yeah really bad, no time now
            for report in res:
                try:
                    md5 = report['resource']
                    if report['response_code'] != 0:
                        self.report[md5]['result'] = 'newAlarm'
                        self.report[md5]['record'] = report
                    else:
                        self.report[md5]['result'] = 'clean'
                except:
                    self.logger.error("[e] Error in %s" % r[1])
