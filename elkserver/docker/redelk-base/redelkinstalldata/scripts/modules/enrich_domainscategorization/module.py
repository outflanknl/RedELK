#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This script enriches domains lists with categorization data

Authors:
- Lorenzo Bernardi (@fastlorenzo)
"""
import datetime
import logging
import copy

# from modules.enrich_domainscategorization.cat_bluecoat import Bluecoat
from modules.enrich_domainscategorization.cat_ibmxforce import IBMXForce
from modules.enrich_domainscategorization.cat_mcafee import MCafee
from modules.enrich_domainscategorization.cat_vt import VT

from modules.helpers import (
    get_initial_alarm_result,
    get_value,
    raw_search,
    es,
)

info = {
    "version": 0.1,
    "name": "Enrich domains lists with categorization data",
    "alarmmsg": "",
    "description": "This script enriches domains lists with categorization data",
    "type": "redelk_enrich",
    "submodule": "enrich_domainscategorization",
}


class Module:
    """Enrich domains lines with data from domains lists"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.now = datetime.datetime.utcnow()
        self.enabled_engines = ["vt", "ibmxforce", "mcafee"]

    def run(self):
        """run the enrich module"""
        ret = get_initial_alarm_result()
        ret["info"] = info

        self.now = datetime.datetime.utcnow()

        # 1. get all IPs from the different IP lists (except tor)
        domains = self.get_domains()
        self.logger.debug("Domains: %s", domains)

        # 2. Check all domains
        checked_domains = self.check_domains(domains)
        self.logger.debug("Checked domains: %s", checked_domains)

        # 3. loop through each result and update the categorization data
        # res = self.update_traffic(domains_lists)
        self.update_categorization_data(domains, checked_domains)

        # 4. Return all hits so they can be tagged
        ret["hits"]["hits"] = []
        ret["hits"]["total"] = []

        self.logger.info(
            "finished running module. result: %s hits", ret["hits"]["total"]
        )
        return ret

    def get_domains(self):
        """Get all domains from the different domains lists"""
        domains = {}
        # Get all IPs except from tor
        # es_query = {'query': {'bool': {'must_not': [{'match': {'domainslist.name': 'tor'}}]}}}
        es_query = {}
        es_results = raw_search(es_query, index="redelk-domainslist-*")

        if not es_results:
            return domains

        for domain_doc in es_results["hits"]["hits"]:
            domain = get_value("_source.domainslist.domain", domain_doc)
            domains[domain] = domain_doc

        return domains

    def check_domains(self, domains):
        """Check the domains categorization"""

        # bluecoat = Bluecoat()
        ibmxforce = IBMXForce()
        mcafee = MCafee()
        vt = VT()  # pylint: disable=invalid-name

        checked_domains = {}

        for domain in domains:
            checked_domains[domain] = {
                "categorization": {
                    "engines": {},
                    "categories": [],
                    "categories_str": "",
                }
            }

            # Loop through all enabled engines and check the domain
            for engine in self.enabled_engines:
                try:

                    self.logger.debug("Checking %s with %s", domain, engine)
                    if engine == "vt":
                        result = copy.deepcopy(vt.check_domain(domain))
                    elif engine == "ibmxforce":
                        result = copy.deepcopy(ibmxforce.check_domain(domain))
                    elif engine == "mcafee":
                        result = copy.deepcopy(mcafee.check_domain(domain))
                    # elif engine == "bluecoat":
                    #     result = copy.deepcopy(bluecoat.check_domain(domain))
                    else:
                        self.logger.error("Unknown engine: %s", engine)

                except Exception as err:  # pylint: disable=broad-except
                    self.logger.error(
                        "Error checking domain %s with %s: %s", domain, engine, err
                    )
                    result = {
                        "categories": [],
                        "extra_data": {},
                    }

                checked_domains[domain]["categorization"]["engines"][engine] = {
                    "categories": result["categories"],
                    "extra_data": result["extra_data"],
                }

                checked_domains[domain]["categorization"]["categories"].extend(
                    result["categories"]
                )
                checked_domains[domain]["categorization"][
                    "categories_str"
                ] += f"{engine}={','.join(result['categories'])}"

        return checked_domains

    def update_categorization_data(self, domains, checked_domains):
        """Update the categorization data for each domain"""
        for domain in domains:
            self.logger.debug("Updating categorization data for %s", domain)
            # Check if current categorization data is different from the new one
            new_categories = []

            new_categories = get_value(
                "categorization.categories_str", checked_domains[domain], ""
            )
            old_categories = get_value(
                "_source.domainslist.categorization.categories_str", domains[domain], ""
            )
            self.logger.debug("New categories: %s", new_categories)
            self.logger.debug("Old categories: %s", old_categories)

            # Update the categorization data if needed
            if new_categories != old_categories:
                self.logger.debug(
                    "Updating categorization data for %s with %s",
                    domain,
                    new_categories,
                )

                # Get old categorization data to add in bluecheck
                try:
                    old_categorization = copy.deepcopy(
                        domains[domain]["_source"]["domainslist"]["categorization"]
                    )
                except Exception as err:  # pylint: disable=broad-except
                    self.logger.error(
                        "Error getting old categorization data for %s: %s", domain, err
                    )
                    old_categorization = {
                        "categories_str": get_value(
                            "_source.domainslist.categorization.categories_str",
                            domains[domain],
                            "",
                        ),
                        "categories": get_value(
                            "_source.domainslist.categorization.categories",
                            domains[domain],
                            [],
                        ),
                    }
                domains[domain]["_source"]["domainslist"][
                    "categorization"
                ] = checked_domains[domain]["categorization"]

                es.update(
                    index=domains[domain]["_index"],
                    id=domains[domain]["_id"],
                    body={"doc": domains[domain]["_source"]},
                )

                self.add_bluecheck_entry(domains[domain], old_categorization)

    def add_bluecheck_entry(self, domain, old_categorization):
        """Add an entry to the bluecheck index"""

        data = domain["_source"]
        self.logger.debug(
            "Adding bluecheck entry with data: %s [old:%s]", data, old_categorization
        )
        data["domainslist"]["categorization"]["old"] = old_categorization

        now = datetime.datetime.utcnow()

        doc_id = f"{domain['_id']}-{now.timestamp()}"

        # Add checked_at field
        data["@timestamp"] = now.isoformat()

        # Create the document in bluecheck index
        es.create(index="bluecheck-domains", body=data, id=doc_id)
