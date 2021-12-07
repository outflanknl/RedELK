#!/usr/bin/python3
"""
Part of RedELK

This check queries VirusTotal API given a list of md5 hashes.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging
from datetime import datetime
import requests
from modules.helpers import get_value

# The Public API is limited to 500 requests per day and a rate of 4 requests per minute.

class VT():
    """ This check queries VirusTotal API given a list of md5 hashes. """
    def __init__(self, api_key):
        self.logger = logging.getLogger('alarm_filehash.ioc_vt')
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

        # Extract the hourly, daily and monthly remaining quotas
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

        if response.status_code == 200: # Hash found
            json_response = response.json()
        elif response.status_code == 404: # Hash not found
            json_response = None
        else: # Unexpected result
            self.logger.warning('Error retrieving VT File hash results (HTTP Status code: %d): %s', response.status_code, response.text)
            json_response = response.text

        return json_response

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

                if vt_result is not None:
                    if isinstance(vt_result, type({})) and 'data' in vt_result:

                        # Get first submission date
                        first_submitted_ts = get_value('data.attributes.first_submission_date', vt_result, None)
                        try:
                            first_submitted_date = datetime.fromtimestamp(first_submitted_ts).isoformat()
                        # pylint: disable=broad-except
                        except Exception:
                            first_submitted_date = None

                        last_analysis_ts = get_value('data.attributes.last_analysis_date', vt_result, None)
                        try:
                            last_analysis_date = datetime.fromtimestamp(last_analysis_ts).isoformat()
                        # pylint: disable=broad-except
                        except Exception:
                            last_analysis_date = None

                        # Found
                        vt_results[md5] = {
                            'record': vt_result,
                            'result': 'newAlarm',
                            'first_submitted': first_submitted_date,
                            'last_seen': last_analysis_date
                        }
                    else:
                        vt_results[md5] = {
                            'result': 'clean'
                        }
                else:
                    # 404 not found
                    vt_results[md5] = {
                        'result': 'clean'
                    }
            else:
                # Quota reached, skip the check
                vt_results[md5] = {
                    'result': 'skipped, quota reached'
                }
            count += 1

        return vt_results
