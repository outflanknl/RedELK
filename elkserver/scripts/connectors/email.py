#!/usr/bin/env python
import config
import socket
import json
from SendMail import *

def pprint(r):
        s = json.dumps(r, indent=2, sort_keys=True)
        return(s)

def SendEmailAlarm(alarm):
        fontsize = 13
        mail = """
            <html><head><style type="text/css">
            #normal {
                font-family: Tahoma, Geneva, sans-serif;
                font-size: 16px;
                line-height: 24px;
            }
            </style>
            </head><body>
        """
        subjectPostPend = ""
        #print(a.checkDict)
        try:
            for k,v in alarm.checkDict.items():
                for item,itemData in v['results'].items():
                    mail = mail + "<p style=\"font-size:%spx\">Alarm on item %s while \"%s\"</p>\n"%(fontsize,item,v['name'])
                    mail = mail + "<p style=\"color:#770000; font-size:%spx\">%s</p>\n"%(fontsize-3,pprint(itemData))
                    mail = mail + "<table>"
                    for itemDataK,ItemDataV in itemData.items():
                        mail = mail + "<tr><td style=\"font-size:%spx\">%s</td<><td style=\"font-size:%spx\">%s</td></tr>"%(fontsize-3,itemDataK,fontsize-3,ItemDataV)
                    mail = mail + "</table>"
                    subjectPostPend = " | %s"%v['name']
        except Exception as e:
            print('Error sending email: %s' % e)
            pass
        mail = mail + "</body></html>\n"
        smtpResp = SendMail(config.toAddrs,mail,"Alarm from %s %s"%(socket.gethostname(),subjectPostPend))
