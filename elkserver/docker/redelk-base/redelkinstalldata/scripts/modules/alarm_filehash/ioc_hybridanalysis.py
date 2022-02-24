#!/usr/bin/python3
"""
Part of RedELK

This check queries Hybrid Analysis API given a list of md5 hashes.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging
from datetime import datetime
import json
from dateutil import parser
import requests

from modules.helpers import get_value

# The Public API is limited to 2000 requests per hour and a rate of 200 requests per minute.

class HA():
    """ This check queries Hybrid Analysis API given a list of md5 hashes. """

    def __init__(self, api_key):
        self.report = {}
        self.report['source'] = 'Hybrid Analysis'
        self.logger = logging.getLogger('ioc_hybridanalysis')
        self.api_key = api_key

    def get_remaining_quota(self):
        """ Returns the number of hashes that could be queried within this run """
        url = 'https://www.hybrid-analysis.com/api/v2/key/current'
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'RedELK',
            'api-key': self.api_key
        }

        # Get the quotas, if response code != 200, return 0 so we don't query further
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            self.logger.warning('Error retrieving Hybrid Analysis Quota (HTTP Status code: %d)', response.status_code)
            return 0

        api_limits_json = response.headers.get('api-limits')
        api_limits = json.loads(api_limits_json)

        # First check if the limit has been reached
        limit_reached = get_value('limit_reached', api_limits, False)
        if limit_reached:
            return 0

        # Extract the limits and usage
        limits_minute = get_value('limits.minute', api_limits, 0)
        limits_hour = get_value('limits.hour', api_limits, 0)
        used_minute = get_value('used.minute', api_limits, 0)
        used_hour = get_value('used.hour', api_limits, 0)

        remaining_minute = limits_minute - used_minute
        remaining_hour = limits_hour - used_hour

        self.logger.debug('Remaining quotas: hour(%d) / minute(%d)', remaining_hour, remaining_minute)

        # Return the remaining quota per minute
        return remaining_minute

    def get_ha_file_results(self, filehash):
        """ Queries Hybrid Analysis API with file hash and returns the results or None if error / nothing found"""

        url = 'https://www.hybrid-analysis.com/api/v2/search/hash'
        headers = {
            'Accept': 'application/json',
            'api-key': self.api_key,
            'User-Agent': 'RedELK',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        payload = f'hash={filehash}'

        # Search for the file hash
        response = requests.post(url, headers=headers, data=payload)

        if response.status_code == 200: # Hash found 
            json_response = response.json()
        else: # Unexpected result
            self.logger.warning('Error retrieving VT File hash results (HTTP Status code: %d): %s', response.status_code, response.text)
            #json_response = response.text
            json_response = []  # see lione 106 checking for len 0.

        return json_response

    def test(self, hash_list):
        """ run the query and build the report (results) """

        # Get the remaining quota for this run
        remaining_quota = self.get_remaining_quota()

        ha_results = {}
        # Query HA API for file hashes
        count = 0
        for md5 in hash_list:
            if count < remaining_quota:
                # Within quota, let's check the file hash with HA
                ha_result = self.get_ha_file_results(md5)

                # No results, let's return it clean
                if len(ha_result) == 0:
                    ha_results[md5] = {
                        'result': 'clean'
                    }
                else:
                    # Loop through the results to get the first analysis (submission) date
                    first_analysis_time = datetime.utcnow()
                    for result in ha_result:
                        analysis_start_time = get_value('analysis_start_time', result, None)
                        if analysis_start_time is not None:
                            analysis_start_time_date = parser.isoparse(analysis_start_time).replace(tzinfo=None)
                            first_analysis_time = first_analysis_time if first_analysis_time < analysis_start_time_date else analysis_start_time_date
                    # Found
                    ha_results[md5] = {
                        'record': ha_result,
                        'result': 'newAlarm',
                        'first_submitted': first_analysis_time.isoformat(),
                        # TO-DO: loop through the submissions to get the time 'last_seen'
                    }
            else:
                # Quota reached, skip the check
                ha_results[md5] = {
                    'result': 'skipped, quota reached'
                }
            count += 1

        return ha_results
