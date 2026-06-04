#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This script enriches rtops lines with data from initial Mythic beacon

Authors:
- @hegusung
"""

import logging
import traceback

from modules.helpers import es, get_initial_alarm_result, get_query, get_value

info = {
    "version": 0.1,
    "name": "Enrich Mythic beacon data",
    "alarmmsg": "",
    "description": "This script enriches rtops lines with data from initial Mythic beacon",
    "type": "redelk_enrich",
    "submodule": "enrich_mythic",
}


class Module:
    """enrich mythic beacon module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        """run the enrich module"""

        ret = get_initial_alarm_result()
        ret["info"] = info
        hits = self.enrich_beacon_data()
        hits += self.enrich_beacon_response_data()
        hits += self.enrich_credentials_data()
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)
        self.logger.info(
            "finished running module. result: %s hits", ret["hits"]["total"]
        )
        return ret

    def enrich_beacon_data(self):
        """Get all lines in rtops that have not been enriched yet (for Mythic)"""
        es_query = f'implant.id:* AND c2.program: mythic AND NOT c2.log.type:implant_newimplant AND NOT tags:{info["submodule"]}'
        not_enriched_results = get_query(es_query, size=10000, index="rtops-*")

        # Created a dict grouped by implant ID
        implant_ids = {}
        for not_enriched in not_enriched_results:
            implant_id = get_value("_source.implant.id", not_enriched)
            if implant_id in implant_ids:
                implant_ids[implant_id].append(not_enriched)
            else:
                implant_ids[implant_id] = [not_enriched]

        hits = []
        # For each implant ID, get the initial beacon line
        for implant_id, implant_val in implant_ids.items():
            initial_beacon_doc = self.get_initial_beacon_doc(implant_id)

            # If not initial beacon line found, skip the beacon ID
            if not initial_beacon_doc:
                continue

            for doc in implant_val:
                # Fields to copy: host.*, implant.*, process.*, user.*
                res = self.copy_data_fields(
                    initial_beacon_doc, doc, ["host", "implant", "user", "process"]
                )
                if res:
                    hits.append(res)

        return hits

    def get_initial_beacon_doc(self, implant_id):
        """Get the initial beacon document from mythic or return False if none found"""
        query = f"implant.id:{implant_id} AND c2.program: mythic AND c2.log.type:implant_newimplant"
        initial_beacon_doc = get_query(query, size=1, index="rtops-*")
        initial_beacon_doc = (
            initial_beacon_doc[0] if len(initial_beacon_doc) > 0 else False
        )
        self.logger.debug(
            "Initial beacon line [%s]: %s", implant_id, initial_beacon_doc
        )
        return initial_beacon_doc

    def enrich_beacon_response_data(self):
        """Get all lines in rtops that have not been enriched yet (for Mythic)"""
        es_query = f'implant.task_id:* AND c2.program: mythic AND NOT c2.log.type:implant_task AND NOT tags:{info["submodule"]}'
        not_enriched_results = get_query(es_query, size=10000, index="rtops-*")

        # Created a dict grouped by implant ID
        task_ids = {}
        for not_enriched in not_enriched_results:
            task_id = get_value("_source.implant.task_id", not_enriched)
            if task_id in task_ids:
                task_ids[task_id].append(not_enriched)
            else:
                task_ids[task_id] = [not_enriched]

        hits = []
        # For each implant ID, get the initial beacon line
        for task_id, implant_task_val in task_ids.items():
            initial_task_doc = self.get_initial_task_doc(task_id)

            # If not initial task line found, skip the beacon ID
            if not initial_task_doc:
                continue

            initial_beacon_doc = self.get_initial_beacon_doc(initial_task_doc["_source"]["implant"]["id"])

            # If not initial task line found, skip the beacon ID
            if not initial_beacon_doc:
                continue

            for doc in implant_task_val:
                # Fields to copy: host.*, implant.*, process.*, user.*
                res = self.copy_data_fields(
                    initial_beacon_doc, doc, ["host", "implant", "user", "process"]
                )
                if res:
                    hits.append(res)

        return hits

    def get_initial_task_doc(self, task_id):
        """Get the initial task document from mythic or return False if none found"""
        query = f"implant.task_id:{task_id} AND c2.program: mythic AND c2.log.type:implant_task"
        initial_task_doc = get_query(query, size=1, index="rtops-*")
        initial_task_doc = (
            initial_task_doc[0] if len(initial_task_doc) > 0 else False
        )
        self.logger.debug(
            "Initial task line [%s]: %s", task_id, initial_task_doc
        )
        return initial_task_doc


    def copy_data_fields(self, src, dst, fields):
        """Copy all data of [fields] from src to dst document and save it to ES"""
        for field in fields:
            if field in dst["_source"]:
                self.logger.info(
                    "Field [%s] already exists in destination document, it will be overwritten",
                    field,
                )
            dst["_source"][field] = src["_source"][field]

        try:
            es.update(index=dst["_index"], id=dst["_id"], body={"doc": dst["_source"]})
            return dst
        # pylint: disable=broad-except
        except Exception as error:
            # stackTrace = traceback.format_exc()
            self.logger.error(
                "Error enriching beacon document %s: %s", dst["_id"], traceback
            )
            self.logger.exception(error)
            return False

    def enrich_credentials_data(self):
        """Get all lines in creds that have not been enriched yet (for Mythic)"""
        es_query = f'creds.task_id:* AND c2.program: mythic AND c2.log.type:credentials AND NOT tags:{info["submodule"]}'
        not_enriched_results = get_query(es_query, size=10000, index="credentials-*")

        # Created a dict grouped by task ID
        task_ids = {}
        for not_enriched in not_enriched_results:
            task_id = get_value("_source.creds.task_id", not_enriched)
            if task_id in task_ids:
                task_ids[task_id].append(not_enriched)
            else:
                task_ids[task_id] = [not_enriched]

        hits = []
        # For each implant ID, get the initial beacon line
        for task_id, creds_val in task_ids.items():
            initial_task_doc = self.get_initial_task_doc(task_id)

            # If not initial task line found, skip the beacon ID
            if not initial_task_doc:
                continue

            initial_beacon_doc = self.get_initial_beacon_doc(initial_task_doc["_source"]["implant"]["id"])

            # If not initial task line found, skip the beacon ID
            if not initial_beacon_doc:
                continue

            for doc in creds_val:
                # initial_beacon.host.name =>  doc.creds.host
                doc["_source"]["creds"]["host"] = initial_beacon_doc["_source"]["host"]["name"]

                # initial_task.implant.task =>  doc.creds.source
                doc["_source"]["creds"]["source"] = initial_task_doc["_source"]["implant"]["task"]

                try:
                    es.update(index=doc["_index"], id=doc["_id"], body={"doc": doc["_source"]})
                    hits.append(doc)
                    
                # pylint: disable=broad-except
                except Exception as error:
                    # stackTrace = traceback.format_exc()
                    self.logger.error(
                        "Error enriching beacon document %s: %s", dst["_id"], traceback
                    )
                    self.logger.exception(error)

        return hits

