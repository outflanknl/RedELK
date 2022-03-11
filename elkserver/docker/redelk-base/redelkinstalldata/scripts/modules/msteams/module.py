#!/usr/bin/python3
"""
Part of RedELK

This connector sends RedELK alerts via Microsoft Teams

Authors:
- Lorenzo Bernardi (@fastlorenzo)
"""
import logging
import pymsteams

import config
from modules.helpers import get_value, pprint

info = {
    'version': 0.1,
    'name': 'msteams connector',
    'description': 'This connector sends RedELK alerts via Microsoft Teams',
    'type': 'redelk_connector',
    'submodule': 'msteams'
}


class Module():  # pylint: disable=too-few-public-methods
    """ msteams connector module """
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

    def send_alarm(self, alarm):
        """ Send the alarm notification """
        tmsg = pymsteams.connectorcard(config.notifications['msteams']['webhook_url'])
        description = alarm['info']['description']
        if len(alarm['groupby']) > 0:
            description += f'\n *Please note that the items below have been grouped by: {pprint(alarm["groupby"])}*'
        tmsg.text(description)
        tmsg.color('red')
        try:
            for hit in alarm['hits']['hits']:
                tcs = pymsteams.cardsection()
                tcs.disableMarkdown()
                i = 0
                title = hit['_id']
                while i < len(alarm['groupby']):
                    val = get_value(f'_source.{alarm["groupby"][i]}', hit)
                    if i == 0:
                        title = val
                    else:
                        title = f'{title} / {val}'
                    i += 1
                tcs.activityTitle(f'Alarm on item: {title}')
                # tcs.activitySubtitle(alarm['info']['description'])
                for field in alarm['fields']:
                    val = get_value(f'_source.{field}', hit)
                    tcs.addFact(field, pprint(val))
                tmsg.addSection(tcs)
        # pylint: disable=broad-except
        except Exception as error:
            self.logger.exception(error)

        tmsg.title(f'[{config.project_name}] Alarm from {alarm["info"]["name"]} [{alarm["hits"]["total"]} hits]')
        tmsg.send()
