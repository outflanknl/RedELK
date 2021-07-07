#!/usr/bin/python3
"""
Part of RedELK

This check queries VirusTotal API given a list of md5 hashes.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging
import requests
from modules.helpers import get_value

# The Public API is limited to 500 requests per day and a rate of 4 requests per minute.
# TODO: check for rate limiting when querying the API

class VT():
    """ This check queries VirusTotal API given a list of md5 hashes. """
    def __init__(self, api_key):
        self.report = {}
        self.report['source'] = 'Virus Total'
        self.logger = logging.getLogger('ioc_vt')
        self.api_key = api_key

    def get_remaining_quota(self):
        """ Returns the number of hashes that could be queried within this run """
        url = f'https://www.virustotal.com/api/v3/users/{self.api_key}/overall_quotas'
        headers = {
            'Accept': 'application/json',
            'x-apikey': self.api_key
        }

        # Get the quotas, if response code != 200, return 0 so we don't query further
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
        else:
            self.logger.warning('Error retrieving VT Quota (HTTP Status code: %d)', response.status_code)
            return 0

        # Extract the hourly, daily and montly remaining quotas
        remaining_hourly = get_value('data.api_requests_hourly.user.allowed', json_response, 0) - get_value('data.api_requests_hourly.user.used', json_response, 0)
        remaining_daily = get_value('data.api_requests_daily.user.allowed', json_response, 0) - get_value('data.api_requests_daily.user.used', json_response, 0)
        remaining_monthly = get_value('data.api_requests_monthly.user.allowed', json_response, 0) - get_value('data.api_requests_monthly.user.used', json_response, 0)

        self.logger.debug('Remaining quotas: hourly(%d) / daily(%d) / monthly(%d)', remaining_hourly, remaining_daily, remaining_monthly)

        # Get the smallest one and return it
        remaining_min = min(remaining_hourly, remaining_daily, remaining_monthly)

        return remaining_min


    def get_vt_file_results(self, filehash):
        """ Queries VT API with file hash and returns the results or None if error / nothing found"""
        url = f'https://www.virustotal.com/api/v3/files/{filehash}'
        headers = {
            'Accept': 'application/json',
            'x-apikey': self.api_key
        }

         # Get the quotas, if response code != 200, return 0 so we don't query further
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
        else:
            self.logger.warning('Error retrieving VT File hash results (HTTP Status code: %d)', response.status_code)
            return None

        return json_response

    def query_virustotal(self, hashlist):
        """ queries VT API and returns the results """
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
        return (response.status_code, json_response)

    def test(self, hash_list):
        """ run the query and build the report (results) """

        # Get the remaining quota for this run
        remaining_quota = self.get_remaining_quota()

        vt_results = {}
        # Query VT API for file hashes
        count = 0
        for md5 in hash_list:
            if count < remaining_quota:
                # Within quota, let's check the file hash with VT
                vt_result = self.get_vt_file_results(md5)
                vt_results[md5] = vt_result
            else:
                # Quota reached, skip the check
                vt_results[md5] = None
            count += 1


            self.report[md5] = {
                'record': {},
                'result': ''
            }
        vt_results = self.query_virustotal(','.join(hash_list))
        res = vt_results[1]
        self.logger.debug('status code %s', vt_results[0])
        if not isinstance(res, type([])):
            res = [res]  # dirty?
            self.logger.debug('just emties resultlist is was %s', vt_results[1])
        if len(res) > 0:  # yeah really bad, no time now
            for report in res:
                try:
                    md5 = report['resource']
                    if report['response_code'] != 0:
                        self.report[md5]['result'] = 'newAlarm'
                        self.report[md5]['record'] = report
                    else:
                        self.report[md5]['result'] = 'clean'
                except Exception as error:  # pylint: disable=broad-except
                    self.logger.error('Error in %s', vt_results[1])
                    self.logger.exception(error)
