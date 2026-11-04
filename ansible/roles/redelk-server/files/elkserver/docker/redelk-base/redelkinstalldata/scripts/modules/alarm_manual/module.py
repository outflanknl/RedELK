#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This check queries for C2 messages that contain "REDELK_ALARM" and will send an alarm with the content of that line.

Only alarms when c2.log.type is: events or implant_input

Authors:
- Outflank B.V. / Marc Smeets (@MarcOverIp)
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging

from modules.helpers import get_initial_alarm_result, get_value, raw_search

info = {
    "version": 0.1,
    "name": "Alarm manual module",
    "description": 'This check queries c2.message items (output and event log) that contain "REDELK_ALARM" and alarms the content of that line',
    "type": "redelk_alarm",
    "submodule": "alarm_manual",
}


class Module:
    """Alarm manual module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        """Run the alarm module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [
            "@timestamp",
            "c2.message",
            "agent.name",
            "c2.log.type",
            "host.name",
            "user.name",
            "host.ip",
        ]
        ret["groupby"] = ["@timestamp"]
        alarmed_messages = self.get_alarmed_messages()
        report = self.alarm_check(alarmed_messages)
        ret["hits"]["hits"] = report
        ret["hits"]["total"] = len(report)
        self.logger.info(
            "finished running module. result: %s hits", ret["hits"]["total"]
        )
        return ret

    def get_alarmed_messages(self):
        """Returns all previous messages that have been alarmed already"""
        es_query = {
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-1y"}}},
                        {"match": {"tags": info["submodule"]}},
                    ]
                }
            },
        }
        res = raw_search(es_query, index="rtops-*")
        if res is None:
            alarmed_hits = []
        else:
            alarmed_hits = res["hits"]["hits"]

        # Created a dict grouped by c2 message (from c2.message)
        messages = {}
        for alarmed_hit in alarmed_hits:
            # pylint: disable=invalid-name
            message = get_value("_source.c2.message", alarmed_hit)
            if message in messages:
                messages[message].append(alarmed_hit)
            else:
                messages[message] = [alarmed_hit]

        return messages

    def alarm_check(self, alarmed_messages):
        """This check queries for C2 messages (input of eventlog) that contain 'REDELK_ALARM'"""
        es_query = {
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": "(c2.message:*REDELK_ALARM*) AND (((c2.log.type:implant_input) AND (tags:enrich_*)) OR (c2.log.type:events))"
                        }
                    },
                    "must_not": [{"match": {"tags": info["submodule"]}}],
                }
            },
        }
        res = raw_search(es_query, index="rtops-*")
        if res is None:
            not_enriched_hits = []
        else:
            not_enriched_hits = res["hits"]["hits"]

        # Created a dict grouped by c2 messages (from c2.message)
        messages = {}
        for not_enriched in not_enriched_hits:
            # pylint: disable=invalid-name
            message = get_value("_source.c2.message", not_enriched)
            if message in messages:
                messages[message].append(not_enriched)
            else:
                messages[message] = [not_enriched]

        hits = []

        # Now we check if the C2 messages have already been alarmed in the past timeframe defined in the config
        # pylint: disable=invalid-name
        for message, message_val in messages.items():
            # Not alarmed yet, process it
            if message not in alarmed_messages:
                hits += message_val

        # Return the array of new documents to be alarmed
        return hits
