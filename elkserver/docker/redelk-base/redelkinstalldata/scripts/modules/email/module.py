#!/usr/bin/python3
"""
Part of RedELK

This connector sends RedELK alerts via email

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""
import os
import logging
import smtplib
import base64
from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate
from json2html import json2html

from config import notifications, project_name
from modules.helpers import get_value, pprint


info = {
    'version': 0.1,
    'name': 'email connector',
    'description': 'This connector sends RedELK alerts via email',
    'type': 'redelk_connector',
    'submodule': 'email'
}

FILEDIR = os.path.abspath(os.path.dirname(__file__))

class Module():
    """ email connector module """
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

    def send_mail(self, to_addresses, mail, subject,
                 from_address=notifications['email']['from'],
                 attachment=None,
                 smtp_host=notifications['email']['smtp']['host'],
                 smtp_port=notifications['email']['smtp']['port'],
                 smtp_user=notifications['email']['smtp']['login'],
                 smtp_pass=notifications['email']['smtp']['pass']
                 ):  # pylint: disable=too-many-arguments
        """ Sends the email """
        message = MIMEMultipart()
        # Read html File
        html = mail
        message['Subject'] = f'[{project_name}] {subject}'
        message['From'] = formataddr((str(Header(from_address, 'utf-8')), from_address))
        message['To'] = ', '.join(to_addresses)
        message['Date'] = formatdate()
        # DONE PREPARATION, BUILD MAIL
        message.attach(MIMEText(html, 'html'))
        if attachment is not None:
            message = self.attach_file(message, attachment)
        # Sending the stuff
        connection = smtplib.SMTP(smtp_host, int(smtp_port))
        connection.starttls()
        connection.login(smtp_user, smtp_pass)
        resp = connection.sendmail(from_address, to_addresses, message.as_string())
        self.logger.debug('smtpd response: %s', resp)
        connection.close()

    def attach_file(self, message, filename):  # pylint: disable=no-self-use
        """ Attaches the HTML version of the email to the message """
        with open(filename, 'rb') as file:
            part = MIMEApplication(
                file.read(),
                Name=filename
            )
            part['Content-Disposition'] = f'attachment; filename="{filename}"'
            message.attach(part)
        return message

    def send_alarm(self, alarm):
        """ Send the alarm """

        # Read the RedELK logo from file and base64 encode it
        with open(f'{FILEDIR}/redelk_white.png', 'rb') as logo_file:
            redelk_logo_b64 = base64.b64encode(logo_file.read()).decode('utf-8')

        mail = f'''
                <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
                <html xmlns="http://www.w3.org/1999/xhtml">
                    <head>
                        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
                        <title>Alarm from RedELK</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
                        <style type="text/css">
                            #normal {{
                                font-family: Tahoma, Geneva, sans-serif;
                                font-size: 16px;
                                line-height: 24px;
                            }}
                        </style>
                    </head>
                <body style="margin: 0; padding: 0;">
                    <table align="center" cellpadding="0" cellspacing="0" width="800" style="border-collapse: collapse;" style="max-width:800px;">
                    <tr>
                        <td bgcolor="#212121" rowspan=2 width="120px" style="padding: 30px 30px 30px 30px; text-align:center;">
                            <img height="60px" src="data:image/png;base64,{redelk_logo_b64}" alt="img" />
                        </td>
                        <td bgcolor="#212121" height="30px" style="color: #FAFAFA; font-family: Arial, sans-serif; font-size: 24px; padding: 30px 30px 0px 10px;">
                            RedELK alarm: <em>{alarm["info"]["name"]}</em>
                        </td>
                    </tr>
                    <tr>
                        <td bgcolor="#212121" height="20px" style="color: #FAFAFA; font-family: Arial, sans-serif; font-size: 16px; line-height: 20px; padding: 20px 30px 30px 10px;">
                            Project: <em>{project_name}</em><br/>Total hits: <em>{alarm["hits"]["total"]}</em>
                        </td>
                    </tr>
                    <tr>
                        <td colspan=2 style="color: #153643; font-family: Arial, sans-serif; font-size: 16px; line-height: 20px; padding: 0px 30px 0px 10px;">
                            <p>{alarm["info"]["description"]}</p>
                        </td>
                    </tr>
            '''

        subject = f'Alarm from {alarm["info"]["name"]} [{alarm["hits"]["total"]} hits]'

        if len(alarm['groupby']) > 0:
            mail += f'''
                <tr>
                    <td colspan=2 style="color: #153643; font-family: Arial, sans-serif; font-size: 12px; line-height: 16px; padding: 0px 15px 0px 15px;">
                        <p>Please note that the items below have been grouped by: {pprint(alarm["groupby"])}</p>
                    </td>
                </tr>
                '''

        try:
            for hit in alarm['hits']['hits']:
                index = 0
                title = hit['_id']
                while index < len(alarm['groupby']):
                    val = get_value(f'_source.{alarm["groupby"][index]}', hit)
                    if index == 0:
                        title = val
                    else:
                        title = f'{title} / {val}'
                    index += 1

                mail += f'''
                    <tr>
                        <td bgcolor="#323232" colspan=2 style="color: #FAFAFA; font-family: Arial, sans-serif; font-size: 16px; line-height: 20px; padding: 10px 10px 10px 10px; text-align:center;">
                            <b>{title}</b>
                        </td>
                    </tr>
                    '''

                row = 0
                for field in alarm['fields']:
                    bgcolor = '#FAFAFA' if row % 2 == 0 else '#F1F1F1'
                    val = get_value(f'_source.{field}', hit)
                    value = json2html.convert(json=val)
                    mail += f'''
                        <tr bgcolor="{bgcolor}" style="color: #153643; font-family: Arial, sans-serif; font-size: 12px; line-height: 16px;">
                            <td style="padding: 10px 10px 10px 10px;"><b>{field}</b></td>
                            <td style="padding: 10px 10px 10px 10px; white-space:pre-wrap; word-wrap:break-word">{value}</td>
                        </tr>
                        '''
                    row += 1
                mail += '<tr><td colspan=2 style="padding: 15px;">&nbsp;</td></tr>'

            mail += '</table>\n</body>\n</html>'
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error('Error sending email: %s', error)
            self.logger.exception(error)

        mail += '</body></html>\n'

        self.send_mail(notifications['email']['to'], mail, subject)
