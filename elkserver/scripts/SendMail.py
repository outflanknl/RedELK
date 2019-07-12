#!/usr/bin/env python
#
# Part of RedELK
# Script to email events as alarms
#
# Author: Outflank B.V. / Mark Bergman / @xychix
#

import argparse
import csv, hashlib
import requests
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.utils import COMMASPACE, formatdate
from email.header import Header
from email.utils import formataddr
from email.mime.text import MIMEText
import os,shutil
from subprocess import Popen, PIPE
from time import sleep

import config

def SendMail(to, mail, subject, fromaddr=config.fromAddr, attachment = "None", smtpSrv=config.smtpSrv,smtpPort=config.smtpPort,smtpName=config.smtpName,smtpPass=config.smtpPass):
    msg = MIMEMultipart()
    #Read html File
    html = mail
    msg['Subject'] = subject
    msg['From'] = formataddr((str(Header(fromaddr, 'utf-8')), fromaddr))
    msg['To'] = to
    msg['Date'] = formatdate()
    #DONE PREPARATION, BUILD MAIL
    msg.attach(MIMEText(html,'html'))
    if attachment != "None":
        msg = Attach(msg,attachment)
    #Sending the stuff
    s = smtplib.SMTP(smtpSrv,int(smtpPort))
    s.starttls()
    s.login(smtpName, smtpPass)
    resp = s.sendmail(fromaddr, to, msg.as_string())
    print("smtpd response: %s"%(resp))
    s.close()

def Attach(msg,filename):
    with open(filename, "rb") as fil:
        part = MIMEApplication(
                fil.read(),
                Name=filename
            )
        part['Content-Disposition'] = 'attachment; filename="%s"' % filename
        msg.attach(part)
    return msg

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Description of your program')
  parser.add_argument('-m','--mfile', help='mail html file', required=True)
  parser.add_argument('-t','--to', help='send mail to', required=True)
  parser.add_argument('-s','--subject', help='subject', required=True)
  parser.add_argument('-f','--from', help='from, please note SPF records!', required=True)
  parser.add_argument('-a','--attachment', help='attachment', required=False, default="None")
  args = vars(parser.parse_args())
  SendMail(args['to'],args['mfile'],args['subject'],args['from'],args['attachment'])
