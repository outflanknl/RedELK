#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Lorenzo Bernardi (@fastlorenzo)
#
import config
import pymsteams
import logging
from modules.helpers import *

info = {
    'version': 0.1,
    'name': 'msteams connector',
    'description': 'This connector sends RedELK alerts via Microsoft Teams',
    'type': 'redelk_connector',
    'submodule': 'msteams'
}

class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        pass

    def send_alarm(self, alarm):

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
                        title = getValue('_source.%s' % alarm['groupby'][i], hit)
                    else:
                        title = '%s / %s' % (title, getValue('_source.%s' % alarm['groupby'][i], hit))
                    i += 1
                tcs.activityTitle('Alarm on item: %s' % title)
                #tcs.activitySubtitle(alarm['info']['description'])
                for field in alarm['fields']:
                    val = getValue('_source.%s' % field, hit)
                    tcs.addFact(field, pprint(val))
                tmsg.addSection(tcs)
        except Exception as e:
            self.logger.exception(e)
            pass

        tmsg.title('Alarm from %s [%s hits]' % (alarm['info']['name'], alarm['hits']['total']))
        tmsg.send()
