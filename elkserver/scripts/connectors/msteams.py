#!/usr/bin/env python
import config
import pymsteams
import socket
import json

def pprint(r):
    s = json.dumps(r, indent=2, sort_keys=True)
    return(s)

def SendTeamsAlarm(alarm):
    tmsg = pymsteams.connectorcard(config.msTeamsWebhookURL)
    tmsg.summary('The following alarms have been triggered in RedELK:')
    subjectPostPend = ''
    try:
        for k,v in alarm.checkDict.items():
            for item,itemData in v['results'].items():
                tcs = pymsteams.cardsection()
                tcs.disableMarkdown()
                tcs.activityTitle('Alarm on item %s: %s' % (item,v['name']))
                tcs.activitySubtitle(v['description'])
                # tcs.activityText(pprint(itemData))
                for itemDataK,ItemDataV in itemData.items():
                    tcs.addFact(itemDataK, str(ItemDataV))
                tmsg.addSection(tcs)
            subjectPostPend = ' | %s' % v['name']
    except Exception as e:
        print(pprint(e))
        pass

    tmsg.title('Alarm from %s %s' % (socket.gethostname(),subjectPostPend))
    tmsg.send()
