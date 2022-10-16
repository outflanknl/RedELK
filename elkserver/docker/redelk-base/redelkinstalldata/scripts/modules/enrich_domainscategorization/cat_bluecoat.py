#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This script checks for domain categorization data in Bluecoat

Adapted from Chameleon's script

Authors:
- Lorenzo Bernardi (@fastlorenzo)
"""

import logging
import json
import traceback
import requests


class Bluecoat:
    """This script checks for domain categorization data in Bluecoat"""

    def __init__(self):
        self.logger = logging.getLogger("enrich_domaincategorization.bluecoat")

    def check_domain(self, domain):
        """Check the domain categoriation in Bluecoat"""
        # Category checking lifted from CatMyFish
        # https://github.com/Mr-Un1k0d3r/CatMyFish/blob/master/CatMyFish.py
        self.logger.debug("Checking domain %s", domain)

        session = requests.session()
        url = "https://sitereview.bluecoat.com/resource/lookup"
        cookies = {"XSRF-TOKEN": "028e5984-50bf-4c00-ad38-87d19957201a"}
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en_US",
            "Accept-Encoding": "gzip, deflate",
            "Referer": "https://sitereview.bluecoat.com/",
            "X-XSRF-TOKEN": "028e5984-50bf-4c00-ad38-87d19957201a",
            "Content-Type": "application/json; charset=utf-8",
            "Connection": "close",
        }
        data = {
            "captcha": "",
            "key": "",
            "phrase": "RXZlbiBpZiB5b3UgYXJlIG5vdCBwYXJ0IG9mIGEgY29tbWVyY2lhbCBvcmdhbml6YXRpb24sIHNjcmlwdGluZyBhZ2FpbnN0IFNpdGUgUmV2aWV3IGlzIHN0aWxsIGFnYWluc3QgdGhlIFRlcm1zIG9mIFNlcnZpY2U=",
            "source": "new lookup",
            "url": domain,
        }
        response = session.post(url, headers=headers, cookies=cookies, json=data)

        try:
            json_data = json.loads(response.content)
            if "errorType" in json_data:
                if json_data["errorType"] == "captcha":
                    self.logger.warning("BlueCoat blocked us :(")
                    return "Blocked by BlueCoat"

            category = []
            self.logger.debug("BlueCoat response: %s", json_data)
            for entry in json_data["categorization"]:
                category.append(entry["name"])
            cat = ", ".join(category)
            print("\033[1;32m[-] Your site is categorised as: " + cat + "\033[0;0m")
            return cat
        except Exception:  # pylint: disable=broad-except
            self.logger.error(
                "Error checking domain %s: %s", domain, traceback.print_exc()
            )

        return False
