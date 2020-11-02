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
import time
import json
import logging

class HA():
    def __init__(self, api_key):
        self.report = {}
        self.report['source'] = 'Hybrid Analysis'
        self.logger = logging.getLogger('ioc_hybridanalysis')
        self.api_key = api_key

    def scansAvailable(self):
        # this function must determine the number of scans de last X time to ensure we stay within rate limiting
        return(True)

    def HAreport(self, hashlist):
        r = []
        headers = {'accept': 'application/json',
                   'user-agent': 'Falcon Sandbox',
                   'api-key': self.api_key,
                   'Content-Type': 'application/x-www-form-urlencoded'}
        payload = []
        for h in hashlist:
            payload.append(('hashes[]', h))
        u = 'https://www.hybrid-analysis.com/api/v2/search/hashes?_timestamp=%s' % int(time.time())
        response = requests.post(u, headers=headers, data=payload)
        json_response = {}
        if response.status_code == 200:
            json_response['results'] = response.json()
            json_response['status_code'] = response.status_code
        else:
            json_response['status_code'] = response.status_code
        return(json_response)

    def test(self, list):
        l = list
        for md5 in list:
            self.report[md5] = {
                'record': {},
                'result': ''
            }
        r = self.HAreport(list)
        # here we neeed to work with the HA response_code
        # Looping over individual results
        if 'results' not in r:
            r['results'] = []  # dirty hack.

        for res in r['results']:
            self.logger.debug('status code %s' % r['status_code'])
            if 'md5' in res:  # We have json response!
                md5 = res['md5']
                self.report[md5]['result'] = 'newAlarm'
                self.report[md5]['record'] = res
                # TODO: check if there are 'clean' results
