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


class Module():
    """ msteams connector module """
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

    def send_alarm(self, alarm):
        """ Send the alarm notification """
        tmsg = pymsteams.connectorcard(config.notifications['msteams']['webhook_url'])
        description = alarm['info']['description']
        if len(alarm['groupby']) > 0:
            description += '\n *Please note that the items below have been grouped by: %s*' % pprint(alarm['groupby'])
        tmsg.text(description)
        tmsg.color('red')
        try:
            for hit in alarm['hits']['hits']:
                tcs = pymsteams.cardsection()
                tcs.disableMarkdown()
                i = 0
                title = hit['_id']
                while i < len(alarm['groupby']):
                    if i == 0:
                        title = get_value('_source.%s' % alarm['groupby'][i], hit)
                    else:
                        title = '%s / %s' % (title, get_value('_source.%s' % alarm['groupby'][i], hit))
                    i += 1
                tcs.activityTitle('Alarm on item: %s' % title)
                # tcs.activitySubtitle(alarm['info']['description'])
                for field in alarm['fields']:
                    val = get_value('_source.%s' % field, hit)
                    tcs.addFact(field, pprint(val))
                tmsg.addSection(tcs)
        # pylint: disable=broad-except
        except Exception as error:
            self.logger.exception(error)

        tmsg.title('Alarm from %s [%s hits]' % (alarm['info']['name'], alarm['hits']['total']))
        tmsg.send()
