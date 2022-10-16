#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This script checks for domain categorization data in MCAfee

Adapted from Chameleon's script

Authors:
- Lorenzo Bernardi (@fastlorenzo)
"""

import logging
import traceback
import requests

from bs4 import BeautifulSoup


class MCafee:
    """This script checks for domain categorization data in MCAfee"""

    def __init__(self):
        self.logger = logging.getLogger("enrich_domaincategorization.mcafee")

    def check_domain(self, domain):
        """Check the domain categoriation in MCAfee"""
        result = {
            "domain": domain,
            "categories": [],
            "status": "unknown",
            "response_code": -1,
            "extra_data": {},
        }

        self.logger.debug("Checking domain %s", domain)

        session = requests.session()

        try:
            # Get anti-automation tokens
            headers = {
                "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-GB,en;q=0.5",
            }
            session.headers.update(headers)
            base_url = "https://sitelookup.mcafee.com/"
            response = session.get(base_url)
            bs_parsed = BeautifulSoup(response.text, "html.parser")

            form = bs_parsed.find("form", {"class": "contactForm"})
            e_token = form.find("input", {"name": "e"}).get("value")
            c_token = form.find("input", {"name": "c"}).get("value")

            # Check domain with MCAfee
            headers["Referer"] = base_url
            session.headers.update(headers)
            payload = {
                "sid": (None, ""),
                "e": (None, e_token),
                "c": (None, c_token),
                "p": (None, ""),
                "action": (None, "checksingle"),
                "product": (None, "13-ts-3"),
                "url": (None, domain),
            }
            response = session.post(
                "https://sitelookup.mcafee.com/en/feedback/url",
                headers=headers,
                files=payload,
            )
            result["response_code"] = response.status_code

            # Parse response
            bs_parsed = BeautifulSoup(response.content, "html.parser")
            form = bs_parsed.find("form", {"class": "contactForm"})

            results_table = bs_parsed.find("table", {"class": "result-table"})

            td_cat = results_table.find_all("td")
            categories = td_cat[len(td_cat) - 2].text

            # Split categories by "- " and remove empty strings
            categories = categories.strip().split("- ")[1:]

            self.logger.debug("Categories: %s", categories)
            result["categories"] = categories

            if "Uncategorized URL" in categories:
                result["status"] = "not_found"
            else:
                result["status"] = "found"

        except Exception:  # pylint: disable=broad-except
            # TODO: Add better exception handling
            self.logger.error(
                "Error checking domain %s: %s", domain, traceback.print_exc()
            )
            self.logger.error(traceback.format_exc())
            result["status"] = "error"

        return result
