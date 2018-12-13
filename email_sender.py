#!/usr/local/bin/python3

"""
Email sender with attachment support
"""

import smtplib
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders
import os
import sys

COMMASPACE = ', '


def send_message(dict_msg_attr):
    """
    Send email message, support multiple attachments

    Example param:

    dict_msg = {
    "username": "testk@gmail.com",
    "password": "123456",
    "server": "smtp.gmail.com",
    "port": 587,
    "ssl": True,
    "from": "First Last <testk@gmail.com>",
    "recipients": ["hello@vegalayer.com", "moathmaharmeh@vegalayer.com"],
    "message": "this is the email text body.",
    "subject": "Scan report",
    "attachments": text string
    }
    :param dict_msg_attr: message header, body, attachments and smtp server info
    :return: True if msg sent to SMTP. False if failed to send
    """
    if dict_msg_attr is None:
        return False

    username = dict_msg_attr["username"]
    password = dict_msg_attr["password"]
    smtp_host = dict_msg_attr["server"]
    smtp_port = int(dict_msg_attr["port"])
    smtp_ssl = bool(dict_msg_attr["ssl"])
    recipients = dict_msg_attr["recipients"]
    message = dict_msg_attr["message"]

    # Create the enclosing (outer) message
    outer = MIMEMultipart()
    outer['Subject'] = dict_msg_attr["subject"]
    outer['To'] = COMMASPACE.join(recipients)
    outer['From'] = dict_msg_attr["from"]
    outer.preamble = 'You will not see this in a MIME-aware mail reader.\n'

    # List of attachments
    attachments = dict_msg_attr["attachments"]
    if attachments is not None:
        # Add the attachments to the message
        try:
            msg = MIMEBase('application', "octet-stream")
            msg.set_payload(bytes(dict_msg_attr["attachments"], "utf-8"))
            encoders.encode_base64(msg)
            msg.add_header('Content-Disposition', 'attachment', filename=os.path.basename("{}.txt".format("report")))
            outer.attach(msg)

        except:
            print("Unable to read the attachments. More info: ", sys.exc_info()[0])
            raise

    outer.attach(MIMEText(message, 'plain'))
    composed = outer.as_string()

    # send email
    try:
        with smtplib.SMTP('{}: {}'.format(smtp_host, smtp_port)) as server:
            server.ehlo()
            if smtp_ssl:
                server.starttls()
                server.ehlo()

            server.login(username, password)
            server.sendmail(dict_msg_attr["from"], recipients, composed)

            server.close()
            server.close()

            return True

    except:
        print("Sending email failed. More info {}: ".format(sys.exc_info()[0]), sys.exc_info()[0])
        raise