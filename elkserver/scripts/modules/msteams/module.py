#!/usr/bin/python3
#
# Part of RedELK
#
# Author: Lorenzo Bernardi / @fastlorenzo
#
import config
import pymsteams
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
        #print("class init")
        pass

    def send_alarm(self, alarm):

        tmsg = pymsteams.connectorcard(config.msTeamsWebhookURL)
        tmsg.summary(alarm['info']['description'])
        try:
            for resk, resv in alarm['results'].items():
                tcs = pymsteams.cardsection()
                tcs.disableMarkdown()
                tcs.activityTitle('Alarm on item: %s' % resk)
                # tcs.activitySubtitle(v['description'])
                for key, val in resv.items():
                    tcs.addFact(key, str(val))
                tmsg.addSection(tcs)
        except Exception as e:
            print(pprint(e))
            pass

        tmsg.title('Alarm from %s [%s hits]' % (alarm['info']['name'], alarm['hits']['total']))
        tmsg.send()
