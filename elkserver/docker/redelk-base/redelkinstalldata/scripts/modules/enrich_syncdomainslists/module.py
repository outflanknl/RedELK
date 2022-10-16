#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

Syncs domainslists data between ES and legacy config files

Authors:
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging
import datetime
import os.path

from modules.helpers import (
    get_initial_alarm_result,
    get_query,
    get_value,
    es,
    match_domain_name,
)

info = {
    "version": 0.1,
    "name": "Enrich sync domainslists",
    "alarmmsg": "",
    "description": "Syncs domainslists data between ES and legacy config files",
    "type": "redelk_enrich",
    "submodule": "enrich_domainslists",
}


class Module:
    """Syncs domainslists data between ES and legacy config files"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.domainslists = ["redteam"]

    def run(self):
        """run the module"""
        ret = get_initial_alarm_result()
        ret["info"] = info

        hits = []

        # Loop through all domainslists
        for domainslist in self.domainslists:
            self.sync_domainslist(domainslist)

        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)

        self.logger.info(
            "finished running module. result: %s hits", ret["hits"]["total"]
        )
        return ret

    def sync_domainslist(self, domainlist="redteam"):
        """Sync data between ES domainlist and config files"""

        # Get data from config file domainlist
        cfg_domainslist = self.get_cfg_domains(domainlist)

        # If the config file doesn't exist, skip the sync
        if cfg_domainslist is None:
            return []

        # Get data from ES domainlist
        query = f"domainslist.name:{domainlist}"
        es_domainslist_docs = get_query(query, size=10000, index="redelk-domainslist-*")

        # Check if config domain is in ES and source = config_file
        es_domainslist = []
        for doc in es_domainslist_docs:
            domain = get_value(
                "_source.domainslist.domain", doc
            )  # pylint: disable=invalid-name
            if domain:
                es_domainslist.append((domain, doc))

        for domainc, comment in cfg_domainslist:
            found = [item for item in es_domainslist if domainc in item]
            if not found:
                self.logger.debug("Domain not found in ES: %s", domainc)
                # if not, add it
                self.add_es_domain(domainc, domainlist, comment)

        toadd = []
        for domaine, doc in es_domainslist:

            # Check if ES domain is in config file
            found = [item for item in cfg_domainslist if domaine in item]

            # if not, check if source = config_file
            if not found:
                # if yes, remove domain from ES
                if get_value("_source.domainslist.source", doc) == "config_file":
                    self.remove_es_domain(doc, domainlist)
                # if not, add it
                else:
                    comment = get_value("_source.domainslist.comment", doc)
                    if comment:
                        domaina = f"{domaine} # From ES -- {comment}"
                    else:
                        domaina = f"{domaine} # From ES"
                    toadd.append(domaina)

        self.add_cfg_domains(toadd, domainlist)

        return toadd

    def get_cfg_domains(self, domainslist):
        """Gets the list of Domains present in the config file"""
        cfg_domainslist = []

        fname = f"/etc/redelk/domainslist_{domainslist}.conf"

        # Check first if the local config file exists; if not, skip the sync
        if not os.path.isfile(fname):
            self.logger.warning(
                "File %s doesn't exist, skipping domain list sync for this one.", fname
            )
            return None

        with open(fname, "r", encoding="utf-8") as config_file:
            content = config_file.readlines()

        for line in content:
            domain_match = match_domain_name(line)
            self.logger.debug("Domain match: %s", domain_match)
            if domain_match and domain_match.group(1) is not None:
                cfg_domainslist.append(
                    (
                        domain_match.group(1),
                        domain_match.group(len(domain_match.groups())),
                    )
                )
            else:
                self.logger.debug("Invalid domain in %s: %s", fname, line)

        return cfg_domainslist

    def add_cfg_domains(self, toadd, domainslist):
        """Add Domains to cfg file"""
        try:
            fname = f"/etc/redelk/domainslist_{domainslist}.conf"
            with open(fname, "a", encoding="utf-8") as config_file:
                for domainsl in toadd:
                    config_file.write(f"{domainsl}\n")
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to update %s: %s", fname, error)
            self.logger.exception(error)
            raise

    def add_es_domain(self, domain, domainslist, comment=None):
        """Add domain to ES domains list"""
        try:
            date_added = datetime.datetime.utcnow().isoformat()
            doc = {
                "@timestamp": date_added,
                "domainslist": {
                    "name": domainslist,
                    "source": "config_file",
                    "domain": domain,
                },
            }

            if comment:
                doc["domainslist"]["comment"] = comment

            index = f"redelk-domainslist-{domainslist}"
            es.index(index=index, body=doc)

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                "Failed to add domain %s in %s: %s", domain, domainslist, error
            )
            self.logger.exception(error)
            raise

    def remove_es_domain(self, doc, domainslist):
        """Remove domain from ES domains list"""
        try:
            index = f"redelk-domainslist-{domainslist}"
            es.delete(index=index, id=doc["_id"])

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                "Failed to delete doc %s from %s: %s", doc["_id"], domainslist, error
            )
            self.logger.exception(error)
            raise
