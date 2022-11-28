#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This script checks for domain categorization data in IBM X-Force Exchange

Adapted from Chameleon's script

Authors:
- Lorenzo Bernardi (@fastlorenzo)
"""

import logging
import traceback
import requests

from config import enrich
from modules.helpers import get_value


class IBMXForce:
    """This script checks for domain categorization data in IBM X-Force Exchange"""

    def __init__(self):
        self.logger = logging.getLogger("enrich_domaincategorization.ibmxforce")
        self.ibm_basic_auth = get_value(
            "enrich_domainscategorization.ibm_basic_auth", enrich
        )

    def check_domain(self, domain):
        """Check the domain categoriation in IBM X-Force Exchange"""
        result = {
            "domain": domain,
            "categories": [],
            "status": "unknown",
            "response_code": -1,
            "extra_data": {},
        }

        self.logger.debug("Checking domain %s", domain)

        session = requests.session()
        url = f"https://api.xforce.ibmcloud.com/api/url/{domain}"
        headers = {
            "Accept": "application/json",
            "Authorization": self.ibm_basic_auth,
        }

        response = session.get(url, headers=headers, verify=False)

        self.logger.debug("Response: %s", response.content)
        result["response_code"] = response.status_code

        # Domain was not found in IBM X-Force Exchange
        if response.status_code == 404:
            self.logger.debug(
                "IBM x-Force does not have entries for the domain %s!", domain
            )
            result["status"] = "not_found"

        # Domain was found in IBM X-Force Exchange
        elif response.status_code == 200:

            try:
                json_data = response.json()
                self.logger.debug("Json Response: %s", json_data)
                result["status"] = "found"
                for category in get_value("result.cats", json_data, {}):
                    result["categories"].append(category)
            except Exception:  # pylint: disable=broad-except
                self.logger.error(
                    "Error checking domain %s: %s", domain, traceback.print_exc()
                )
                self.logger.error(traceback.format_exc())
                result["status"] = "error"

        return result
