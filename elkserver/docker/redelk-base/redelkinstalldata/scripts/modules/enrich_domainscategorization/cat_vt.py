#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This script checks for domain categorization data in VirusTotal

Authors:
- Lorenzo Bernardi (@fastlorenzo)
"""

import logging
import requests

from config import enrich
from modules.helpers import get_value


class VT:
    """This script checks for domain categorization data in VirusTotal"""

    def __init__(self):
        self.logger = logging.getLogger("enrich_domaincategorization.vt")
        self.api_key = get_value("enrich_domainscategorization.vt_api_key", enrich)

    def check_domain(self, domain):
        """Check the domain categoriation in VirusTotal"""
        result = {
            "domain": domain,
            "categories": [],
            "status": "unknown",
            "response_code": -1,
            "extra_data": {},
            "last_checked": None,
        }

        # Get the remaining quota for this run
        remaining_quota = self.get_remaining_quota()
        if remaining_quota == 0:
            self.logger.warning("No remaining quota, skipping VT check")
            result["status"] = "skipped"
            return result

        # Within quota, let's check the file hash with VT
        self.logger.debug("Checking domain %s", domain)
        vt_result = self.get_vt_domain_results(domain)
        self.logger.debug("Response: %s", vt_result)

        if (
            vt_result is not None
            and isinstance(vt_result, type({}))
            and "data" in vt_result
        ):
            result["status"] = "found"

            vt_cats = get_value("data.attributes.categories", vt_result, {})
            result["extra_data"]["record"] = get_value("data.attributes", vt_result, {})

            # Parse the categories
            for cat in vt_cats:
                result["categories"].extend(
                    [x.strip() for x in vt_cats[cat].split(",")]
                )

            # # Get first submission date
            # first_submitted_ts = get_value(
            #     "data.attributes.first_submission_date", vt_result, None
            # )
            # try:
            #     first_submitted_date = datetime.fromtimestamp(
            #         first_submitted_ts
            #     ).isoformat()
            # # pylint: disable=broad-except
            # except Exception:
            #     first_submitted_date = None

            # last_modification_ts = get_value(
            #     "data.attributes.last_modification_date", vt_result, None
            # )
            # try:
            #     last_modification_date = datetime.fromtimestamp(
            #         last_modification_ts
            #     ).isoformat()
            # # pylint: disable=broad-except
            # except Exception:
            #     last_modification_date = None

        else:
            # 404 not found
            result["status"] = "not_found"

        return result

    def get_remaining_quota(self):
        """Returns the number of hashes that could be queried within this run"""
        url = f"https://www.virustotal.com/api/v3/users/{self.api_key}/overall_quotas"
        headers = {"Accept": "application/json", "x-apikey": self.api_key}

        # Get the quotas, if response code != 200, return 0 so we don't query further
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
        else:
            self.logger.warning(
                "Error retrieving VT Quota (HTTP Status code: %d)", response.status_code
            )
            return 0

        # Extract the hourly, daily and monthly remaining quotas
        remaining_hourly = get_value(
            "data.api_requests_hourly.user.allowed", json_response, 0
        ) - get_value("data.api_requests_hourly.user.used", json_response, 0)
        remaining_daily = get_value(
            "data.api_requests_daily.user.allowed", json_response, 0
        ) - get_value("data.api_requests_daily.user.used", json_response, 0)
        remaining_monthly = get_value(
            "data.api_requests_monthly.user.allowed", json_response, 0
        ) - get_value("data.api_requests_monthly.user.used", json_response, 0)

        self.logger.debug(
            "Remaining quotas: hourly(%d) / daily(%d) / monthly(%d)",
            remaining_hourly,
            remaining_daily,
            remaining_monthly,
        )

        # Get the smallest one and return it
        remaining_min = min(remaining_hourly, remaining_daily, remaining_monthly)

        return remaining_min

    def get_vt_domain_results(self, domain):
        """Queries VT API with domain and returns the results or None if error / nothing found"""

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"Accept": "application/json", "x-apikey": self.api_key}

        # Get the quotas, if response code != 200, return 0 so we don't query further
        response = requests.get(url, headers=headers)

        if response.status_code == 200:  # Domain found
            json_response = response.json()
        elif response.status_code == 404:  # Domain not found
            json_response = None
        else:  # Unexpected result
            self.logger.warning(
                "Error retrieving VT domain results (HTTP Status code: %d): %s",
                response.status_code,
                response.text,
            )
            json_response = None

        return json_response
