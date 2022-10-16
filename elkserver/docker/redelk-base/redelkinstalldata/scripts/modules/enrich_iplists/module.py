#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This script enriches redirtraffic documents with data from the different IP lists

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import datetime
import logging

from modules.helpers import (
    add_tags_by_query,
    get_initial_alarm_result,
    get_value,
    raw_search,
)

info = {
    "version": 0.1,
    "name": "Enrich redirtraffic lines with data from IP lists",
    "alarmmsg": "",
    "description": "This script enriches redirtraffic documents with data from the different IP lists",
    "type": "redelk_enrich",
    "submodule": "enrich_iplists",
}


class Module:
    """Enrich redirtraffic lines with data from IP lists"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.now = datetime.datetime.utcnow()

    def run(self):
        """run the enrich module"""
        ret = get_initial_alarm_result()
        ret["info"] = info

        self.now = datetime.datetime.utcnow()

        # 1. get all IPs from the different IP lists (except tor)
        ip_lists = self.get_iplists()
        self.logger.debug("IP Lists: %s", ip_lists)

        # 2. Get all entries in redirtraffic that have not the enrich_iplist tag
        redirtraffic = self.get_redirtraffic()

        # 3. loop through each result and find all IPs that matches in redirtraffic
        res = self.update_traffic(ip_lists)

        # 4. Return all hits so they can be tagged
        ret["hits"]["hits"] = redirtraffic
        ret["hits"]["total"] = res

        self.logger.info(
            "finished running module. result: %s hits", ret["hits"]["total"]
        )
        return ret

    def get_iplists(self):  # pylint: disable=no-self-use
        """Get all IP lists"""
        ip_lists = {}
        # Get all IPs except from tor
        es_query = {
            "query": {"bool": {"must_not": [{"match": {"iplist.name": "tor"}}]}}
        }
        es_results = raw_search(es_query, index="redelk-iplist-*")

        if not es_results:
            return ip_lists

        for ip_doc in es_results["hits"]["hits"]:
            #  pylint: disable=invalid-name
            ip = get_value("_source.iplist.ip", ip_doc)
            iplist_name = get_value("_source.iplist.name", ip_doc)
            # Already one IP found in this list, adding it
            if iplist_name in ip_lists:
                ip_lists[iplist_name].append(ip)
            # First IP for this IP list, creating the array
            else:
                ip_lists[iplist_name] = [ip]

        return ip_lists

    def get_redirtraffic(self):
        """Get all redirtraffic before 'now' that were not processed by previous run of the module"""
        es_query = {
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"lte": self.now.isoformat()}}}
                    ],
                    "must_not": [{"match": {"tags": info["submodule"]}}],
                }
            },
        }

        es_results = raw_search(es_query, index="redirtraffic-*")

        self.logger.debug(es_results)

        if es_results is None:
            return []
        return es_results["hits"]["hits"]

    def update_traffic(self, ip_lists):
        """Update the documents"""
        updated_count = 0

        # 1. Loop through each IP list
        for iplist_name in ip_lists:
            ip_match = []
            iplist_tag = f"iplist_{iplist_name}"

            #  pylint: disable=invalid-name
            for ip in ip_lists[iplist_name]:
                ip_match.append({"match": {"source.ip": ip}})

            es_query = {
                "bool": {
                    "must_not": [{"match": {"tags": iplist_tag}}],
                    "should": ip_match,
                    "filter": [
                        {"range": {"@timestamp": {"lte": self.now.isoformat()}}}
                    ],
                    "minimum_should_match": 1,
                }
            }

            self.logger.debug("Tagging IPs matching IP list %s", iplist_name)
            # 2. For each IP list, update all documents not tagged already
            es_results = add_tags_by_query([iplist_tag], es_query, "redirtraffic-*")
            updated_count += es_results["updated"]

        return updated_count
