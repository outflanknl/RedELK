#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This script enriches redirtraffic documents with VPN, Tor and relay flags from VPNDetection

Authors:
- Uman Shahzad (@UmanShahzad)
"""

import logging
import traceback
from time import time

import requests
from config import enrich
from modules.helpers import (
    es,
    get_initial_alarm_result,
    get_last_run,
    get_value,
    raw_search,
)

info = {
    "version": 0.1,
    "name": "Enrich redirtraffic lines with VPNDetection data",
    "alarmmsg": "",
    "description": "This script enriches redirtraffic documents with VPN, Tor and relay flags from VPNDetection",
    "type": "redelk_enrich",
    "submodule": "enrich_vpndetection",
}


class Module:
    """Enrich redirtraffic lines with VPNDetection data"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.vpndetection_url = "https://api.vpndetection.io/"
        config = enrich[info["submodule"]] if info["submodule"] in enrich else {}
        # Re-query after 1 day by default
        self.cache = config.get("cache", 86400)
        # No key needed for the VPN, Tor and relay flags
        self.api_key = config.get("api_key", "")

    def run(self):
        """run the enrich module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        hits = self.enrich_vpndetection()
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)
        self.logger.info(
            "finished running module. result: %s hits", ret["hits"]["total"]
        )
        return ret

    def enrich_vpndetection(self):
        """Get all lines in redirtraffic that have not been enriched with 'enrich_vpndetection'
        Filter documents that were before the last run time of enrich_iplist (to avoid race condition)
        """
        iplist_lastrun = get_last_run("enrich_iplists")
        es_query = {
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"lte": iplist_lastrun.isoformat()}}}
                    ],
                    "must_not": [{"match": {"tags": info["submodule"]}}],
                }
            },
        }
        es_result = raw_search(es_query, index="redirtraffic-*")
        if es_result is None:
            not_enriched_results = []
        else:
            not_enriched_results = es_result["hits"]["hits"]

        # Created a dict grouped by IP address (from source.ip)
        ips = {}
        for not_enriched in not_enriched_results:
            # pylint: disable=invalid-name
            ip = get_value("_source.source.ip", not_enriched)
            if ip in ips:
                ips[ip].append(not_enriched)
            else:
                ips[ip] = [not_enriched]

        hits = []
        # For each IP, get the VPNDetection data
        # pylint: disable=invalid-name
        for ip, ip_val in ips.items():
            # If no ip, skip it
            if not ip:
                continue

            # Get data from redirtraffic if within interval
            last_es_data = self.get_last_es_data(ip)

            if not last_es_data:
                vpndetection_data = self.get_vpndetection_data(ip)
            else:
                vpndetection_data = get_value(
                    "_source.source.vpndetection", last_es_data
                )

            # If no VPNDetection data found, skip the IP
            if not vpndetection_data:
                continue

            for doc in ip_val:
                es_result = self.add_vpndetection_data(doc, vpndetection_data)
                if es_result:
                    hits.append(es_result)

        return hits

    def get_vpndetection_data(self, ip_address):
        """Get the VPN, Tor and relay flags from VPNDetection for the IP"""
        # Sample (fields kept from https://api.vpndetection.io/146.70.116.130)
        # {
        #     "ip": "146.70.116.130",
        #     "is_vpn": true,
        #     "is_relay": false,
        #     "is_tor": false,
        #     "relay": {},
        #     "tor": {},
        #     "location": {"country": "AT", ...},
        #     "asn": {"asn": 9009, "name": "M247 Europe SRL", "type": "hosting", ...}
        # }
        try:
            headers = {"User-Agent": "vpndetection-redelk-enrichment"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            response = requests.get(
                f"{self.vpndetection_url}{ip_address}", headers=headers, timeout=10
            )
            if response.status_code != 200:
                self.logger.error(
                    "VPNDetection answered %s for IP %s",
                    response.status_code,
                    ip_address,
                )
                return False
            json_result = response.json()
            result = {
                "ip": ip_address,
                "is_vpn": get_value("is_vpn", json_result, False),
                "is_tor": get_value("is_tor", json_result, False),
                "is_relay": get_value("is_relay", json_result, False),
                "relay_provider": get_value("relay.provider_name", json_result, None),
                "country": get_value("location.country", json_result, None),
                "asn": get_value("asn.asn", json_result, None),
                "as_name": get_value("asn.name", json_result, None),
                "network_type": get_value("asn.type", json_result, None),
                "query_timestamp": int(time()),
            }
            return result
        # pylint: disable=broad-except
        except Exception as error:
            self.logger.error("Error getting VPNDetection IP %s", ip_address)
            self.logger.exception(error)
            return False

    def get_last_es_data(self, ip_address):
        """Get VPNDetection data from ES if less than 1 day old"""
        es_query = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "source.vpndetection.query_timestamp": {
                                    "gte": f"now-{self.cache}s",
                                    "lte": "now",
                                }
                            }
                        },
                        {"term": {"tags": "enrich_vpndetection"}},
                        {"term": {"host.ip": ip_address}},
                    ]
                }
            },
        }

        es_results = raw_search(es_query, index="redirtraffic-*")

        self.logger.debug(es_results)

        # Return the latest hit or False if not found
        if es_results and len(es_results["hits"]["hits"]) > 0:
            return es_results["hits"]["hits"][0]
        return False

    def add_vpndetection_data(self, doc, data):
        """Add VPNDetection data to the doc"""
        doc["_source"]["source"]["vpndetection"] = data

        try:
            es.update(index=doc["_index"], id=doc["_id"], body={"doc": doc["_source"]})
            return doc
        # pylint: disable=broad-except
        except Exception as error:
            stack_trace = traceback.format_exc()
            self.logger.error(
                "Error adding VPNDetection data to document %s: %s",
                doc["_id"],
                stack_trace,
            )
            self.logger.exception(error)
            return False
