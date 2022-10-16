#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

Syncs iplists data between ES and legacy config files

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging
import re
import datetime
import os.path

from modules.helpers import get_initial_alarm_result, get_query, get_value, es

IP_RE = r"^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\s?#\s?(.*))?$"
IP_CIDR_RE = r"^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-2][0-9]|3[0-2]|[0-9])))(\s?#\s?(.*))?$"

info = {
    "version": 0.1,
    "name": "Enrich sync iplist",
    "alarmmsg": "",
    "description": "Syncs iplists data between ES and legacy config files",
    "type": "redelk_enrich",
    "submodule": "enrich_synciplists",
}


class Module:
    """Syncs iplists data between ES and legacy config files"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.iplists = ["customer", "redteam", "unknown", "blueteam"]

    def run(self):
        """run the module"""
        ret = get_initial_alarm_result()
        ret["info"] = info

        hits = []
        for iplist in self.iplists:
            self.sync_iplist(iplist)
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)

        self.logger.info(
            "finished running module. result: %s hits", ret["hits"]["total"]
        )
        return ret

    def sync_iplist(self, iplist="redteam"):
        """Sync data between ES iplist and config files"""
        # Get data from config file iplist
        cfg_iplist = self.get_cfg_ips(iplist)

        # If the config file doesn't exist, skip the sync
        if cfg_iplist is None:
            return []

        # Get data from ES iplist
        query = f"iplist.name:{iplist}"
        es_iplist_docs = get_query(query, size=10000, index="redelk-*")

        # Check if config IP is in ES and source = config_file
        es_iplist = []
        for doc in es_iplist_docs:
            ip = get_value("_source.iplist.ip", doc)  # pylint: disable=invalid-name
            if ip:
                es_iplist.append((ip, doc))

        for ipc, comment in cfg_iplist:
            found = [item for item in es_iplist if ipc in item]
            if not found:
                self.logger.debug("IP not found in ES: %s", ipc)
                # if not, add it
                self.add_es_ip(ipc, iplist, comment)

        toadd = []
        for ipe, doc in es_iplist:
            # Check if ES IP is in config file
            found = [item for item in cfg_iplist if ipe in item]
            if not found:
                # if not, check if source = config_file
                if get_value("_source.iplist.source", doc) == "config_file":
                    # if yes, remove IP from ES
                    self.remove_es_ip(doc, iplist)
                else:
                    # if not, add it
                    comment = get_value("_source.iplist.comment", doc)
                    if comment:
                        ipa = f"{ipe} # From ES -- {comment}"
                    else:
                        ipa = f"{ipe} # From ES"
                    toadd.append(ipa)

        self.add_cfg_ips(toadd, iplist)

        return toadd

    def get_cfg_ips(self, iplist):
        """Gets the list of IPs present in the config file"""
        cfg_iplist = []

        fname = f"/etc/redelk/iplist_{iplist}.conf"

        # Check first if the local config file exists; if not, skip the sync
        if not os.path.isfile(fname):
            self.logger.warning(
                "File %s doesn't exist, skipping IP list sync for this one.", fname
            )
            return None

        with open(fname, "r", encoding="utf-8") as config_file:
            content = config_file.readlines()

        for line in content:
            ip_match = re.match(IP_CIDR_RE, line)
            if ip_match:
                cfg_iplist.append(
                    (ip_match.group(1), ip_match.group(len(ip_match.groups())))
                )
            else:
                ip_match = re.match(IP_RE, line)
                if ip_match:
                    cfg_iplist.append(
                        (
                            f"{ip_match.group(1)}/32",
                            ip_match.group(len(ip_match.groups())),
                        )
                    )

        return cfg_iplist

    def add_cfg_ips(self, toadd, iplist):
        """Add IPs to cfg file"""
        try:
            fname = f"/etc/redelk/iplist_{iplist}.conf"
            with open(fname, "a", encoding="utf-8") as config_file:
                for ipl in toadd:
                    config_file.write(f"{ipl}\n")
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to update %s: %s", fname, error)
            self.logger.exception(error)
            raise

    def add_es_ip(self, ip, iplist, comment=None):  # pylint: disable=invalid-name
        """Add IP to ES IP list"""
        try:
            ts = datetime.datetime.utcnow().isoformat()  # pylint: disable=invalid-name
            doc = {
                "@timestamp": ts,
                "iplist": {"name": iplist, "source": "config_file", "ip": ip},
            }

            if comment:
                doc["iplist"]["comment"] = comment

            index = f"redelk-iplist-{iplist}"
            es.index(index=index, body=doc)

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to add IP %s in %s: %s", ip, iplist, error)
            self.logger.exception(error)
            raise

    def remove_es_ip(self, doc, iplist):
        """Remove IP from ES IP list"""
        try:
            index = f"redelk-iplist-{iplist}"
            es.delete(index=index, id=doc["_id"])

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                "Failed to delete doc %s from %s: %s", doc["_id"], iplist, error
            )
            self.logger.exception(error)
            raise
