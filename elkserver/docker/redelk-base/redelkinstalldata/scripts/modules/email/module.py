#!/usr/bin/python3
#
# Part of RedELK
# Script to check if there are alarms to be sent
#
# Author: Outflank B.V. / Mark Bergman / @xychix
# Contributor: Lorenzo Bernardi / @fastlorenzo
#
import config
import socket
import json
import argparse
import csv
import hashlib
import requests
import smtplib
import os
import shutil
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.utils import COMMASPACE, formatdate
from email.header import Header
from email.utils import formataddr
from email.mime.text import MIMEText
from modules.helpers import *
from subprocess import Popen, PIPE
from time import sleep

info = {
    'version': 0.1,
    'name': 'email connector',
    'description': 'This connector sends RedELK alerts via email',
    'type': 'redelk_connector',
    'submodule': 'email'
}

class Module():
    def __init__(self):
        #print("class init")
        pass

    def SendMail(self, to, mail, subject, fromaddr=config.fromAddr, attachment="None", smtpSrv=config.smtpSrv, smtpPort=config.smtpPort, smtpName=config.smtpName, smtpPass=config.smtpPass):
        msg = MIMEMultipart()
        # Read html File
        html = mail
        msg['Subject'] = subject
        msg['From'] = formataddr((str(Header(fromaddr, 'utf-8')), fromaddr))
        msg['To'] = ", ".join(to)
        msg['Date'] = formatdate()
        # DONE PREPARATION, BUILD MAIL
        msg.attach(MIMEText(html, 'html'))
        if attachment != "None":
            msg = self.Attach(msg, attachment)
        # Sending the stuff
        s = smtplib.SMTP(smtpSrv, int(smtpPort))
        s.starttls()
        s.login(smtpName, smtpPass)
        resp = s.sendmail(fromaddr, to, msg.as_string())
        print("[c] smtpd response: %s" % (resp))
        s.close()


    def Attach(self, msg, filename):
        with open(filename, "rb") as fil:
            part = MIMEApplication(
                fil.read(),
                Name=filename
            )
            part['Content-Disposition'] = 'attachment; filename="%s"' % filename
            msg.attach(part)
        return msg

    def send_alarm(self, alarm):
        fontsize = 13
        mail = """
                <html>
                    <head>
                        <style type="text/css">
                            #normal {
                                font-family: Tahoma, Geneva, sans-serif;
                                font-size: 16px;
                                line-height: 24px;
                            }
                        </style>
                    </head>
                <body>
                <p>%s</p>
            """ % alarm['info']['description']
        subject = 'Alarm from %s [%s hits]' % (alarm['info']['name'], alarm['hits']['total'])
        mail += '<table>'
        try:
            for resk, resv in alarm['results'].items():
                mail += '<tr><td colspan=2>--- %s ---</td></tr>' % resk
                for key, val in resv.items():
                    mail += '<tr><td>%s</td><td>%s</td></tr>' % (key, val)
            mail += '</table>'
        except Exception as e:
            print('Error sending email: %s' % e)
            pass
        mail += "</body></html>\n"
        smtpResp = self.SendMail(config.toAddrs, mail, subject)
