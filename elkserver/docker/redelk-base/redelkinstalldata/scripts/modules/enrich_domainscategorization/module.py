#!/usr/bin/python3
"""
Part of RedELK

This script enriches domains lists with categorization data

Authors:
- Lorenzo Bernardi (@fastlorenzo)
"""
import datetime
import logging
import re
from this import d

from modules.enrich_domainscategorization.cat_bluecoat import Bluecoat
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

        # 3. loop through each result and update the categorization data
        # res = self.update_traffic(domains_lists)
        self.update_categorization_data(checked_domains)

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

        for domain in domains:
            domains[domain]["categories"] = {}
            domains[domain]["extra_data"] = {}

            # Loop through all enabled engines and check the domain
            for engine in self.enabled_engines:
                self.logger.debug("Checking %s with %s", domain, engine)
                if engine == "vt":
                    result = vt.check_domain(domain)
                elif engine == "ibmxforce":
                    result = ibmxforce.check_domain(domain)
                elif engine == "mcafee":
                    result = mcafee.check_domain(domain)
                # elif engine == "bluecoat":
                #     result = bluecoat.check_domain(domain)
                else:
                    self.logger.error("Unknown engine: %s", engine)

                domains[domain]["categories"][engine] = result["categories"]
                domains[domain]["extra_data"][engine] = get_value(
                    "extra_data", result, {}
                )

        return domains

    def update_categorization_data(self, domains):
        """Update the categorization data for each domain"""
        for domain in domains:
            self.logger.debug("Updating categorization data for %s", domain)
            # Check if current categorization data is different from the new one
            new_categories = []
            raw_categories = []
            for engine in domains[domain]["categories"]:
                if len(domains[domain]["categories"][engine]) > 0:
                    new_categories.append(
                        f"{engine}={';'.join(domains[domain]['categories'][engine])}"
                    )
                    raw_categories.extend(domains[domain]["categories"][engine])

            new_categories = "|".join(new_categories)
            old_categories = get_value(
                "_source.domainslist.categories", domains[domain], ""
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
                domains[domain]["_source"]["domainslist"]["categories"] = new_categories
                domains[domain]["_source"]["domainslist"][
                    "raw_categories"
                ] = raw_categories
                domains[domain]["_source"]["domainslist"]["categories_extra"] = domains[
                    domain
                ]["extra_data"]
                es.update(
                    index=domains[domain]["_index"],
                    id=domains[domain]["_id"],
                    body={"doc": domains[domain]["_source"]},
                )
                # TODO: add a document to the bluecheck index to indicate that the categorization data has been updated
