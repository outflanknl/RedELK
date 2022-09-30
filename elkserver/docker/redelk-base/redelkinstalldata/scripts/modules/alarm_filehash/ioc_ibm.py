#!/usr/bin/python3
"""
Part of RedELK

This check queries IBM X-Force API given a list of md5 hashes.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging
from datetime import datetime
import requests

from modules.helpers import get_value

# Rate limiting:
# Free Tier (Non-Commercial Use Only): The free tier allows usage of up to 5,000 records per month
# Commercial API - Paid Tier (Commercial Use): Usage is priced by the number of data records that you access, which are sold in packs of 10,000 records per month
class IBM:
    """This check queries IBM X-Force API given a list of md5 hashes."""

    def __init__(self, basic_auth):
        # self.report = {}
        # self.report['source'] = 'IBM X-Force'
        self.logger = logging.getLogger("alarm_filehash.ioc_ibm")
        self.basic_auth = basic_auth

    def get_remaining_quota(self):
        """Returns the number of hashes that could be queried within this run"""
        url = "https://api.xforce.ibmcloud.com/all-subscriptions/usage"
        headers = {"Accept": "application/json", "Authorization": self.basic_auth}

        # Get the quotas, if response code != 200, return 0 so we don't query further
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
        else:
            self.logger.warning(
                "Error retrieving IBM X-Force Quota (HTTP Status code: %d)",
                response.status_code,
            )
            return 0

        remaining_quota = 0

        # Extract the hourly, daily and monthly remaining quotas
        for result in json_response:
            # Only take the relevant results (usageData for 'api' type)
            if (
                "subscriptionType" in result
                and result["subscriptionType"] == "api"
                and "usageData" in result
            ):
                # Get the monthly quota (limit)
                entitlement = get_value("usageData.entitlement", result, 0)
                remaining_quota += int(entitlement)

                # Get the usage array (per cycle)
                usage = get_value("usageData.usage", result, [])

                # Find the current cycle and remove the current usage from that cycle from the remaining quota
                for usage_cycle in usage:
                    cycle = get_value("cycle", usage_cycle, 0)
                    if cycle == datetime.now().strftime("%Y-%m"):
                        current_usage = get_value("usage", usage_cycle, 0)
                        remaining_quota -= int(current_usage)

        self.logger.debug("Remaining quota (monthly): %d", remaining_quota)

        return remaining_quota

    def get_ibm_xforce_file_results(self, file_hash):
        """Queries VT API with file hash and returns the results or None if error / nothing found"""

        url = f"https://api.xforce.ibmcloud.com/malware/{file_hash}"
        headers = {"Authorization": self.basic_auth}

        # Get the quotas, if response code != 200, return 0 so we don't query further
        response = requests.get(url, headers=headers)

        if response.status_code == 200:  # Hash found
            json_response = response.json()
        elif response.status_code == 404:  # Hash not found
            json_response = None
        else:  # Unexpected result
            self.logger.warning(
                "Error retrieving IBM X-Force File hash results (HTTP Status code: %d): %s",
                response.status_code,
                response.text,
            )
            # json_response = response.text
            json_response = None

        return json_response

    def test(self, hash_list):
        """run the query and build the report (results)"""
        self.logger.debug("Checking IOCs on IBM X-Force: %s", hash_list)

        # Get the remaining quota for this run
        remaining_quota = self.get_remaining_quota()

        ibm_results = {}
        # Query VT API for file hashes
        count = 0
        for md5 in hash_list:
            if count < remaining_quota:
                # Within quota, let's check the file hash with VT
                ibm_result = self.get_ibm_xforce_file_results(md5)

                if ibm_result is not None:
                    if isinstance(ibm_result, type({})) and "malware" in ibm_result:

                        # Get first submission date
                        first_submitted_date = get_value(
                            "malware.created", ibm_results, None
                        )

                        # Found and marked as malware
                        ibm_results[md5] = {
                            "record": ibm_result,
                            "result": "newAlarm",
                            "first_submitted": first_submitted_date,
                        }
                    else:
                        ibm_results[md5] = {"result": "clean"}
                else:
                    # 404 not found
                    ibm_results[md5] = {"result": "clean"}
            else:
                # Quota reached, skip the check
                ibm_results[md5] = {"result": "skipped, quota reached"}
            count += 1

        return ibm_results
