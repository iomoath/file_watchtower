"""
Email sender with attachment support
"""

import smtplib
import ssl
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import encoders
import os
import sys
import settings


COMMASPACE = ', '

def send(sender, recipients, composed):
    if settings.SMTP_SEC_PROTOCOL == "ssl":
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, ssl.create_default_context()) as server:
            server.ehlo_or_helo_if_needed()
            if settings.SMTP_REQUIRE_AUTH:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(sender, recipients, composed)
            server.close()
            return True
    elif settings.SMTP_SEC_PROTOCOL == "tls":
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.ehlo_or_helo_if_needed()

            if settings.SMTP_REQUIRE_AUTH:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(sender, recipients, composed)
            server.close()
            return True
    else:
        with smtplib.SMTP(settings.SMTP_HOST) as server:
            server.ehlo_or_helo_if_needed()

            if settings.SMTP_REQUIRE_AUTH:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(sender, recipients, composed)
            server.close()
            return True


def send_message(dict_msg_attr):
    """
    Send email message, support multiple attachments
    Example param:
    dict_msg = {
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

    recipients = dict_msg_attr["recipients"]
    message = dict_msg_attr["message"]

    # Create the enclosing (outer) message
    outer = MIMEMultipart()
    outer['Subject'] = dict_msg_attr["subject"]
    outer['To'] = COMMASPACE.join(recipients)
    outer['From'] = dict_msg_attr["from"]
    outer.preamble = 'You will not see this in a MIME-aware mail reader.\n'

    # List of attachments
    if 'attachments' in dict_msg_attr and dict_msg_attr["attachments"] is not None:
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
        sender = "{} <{}>".format(settings.FROM_NAME, settings.FROM)
        send(sender, recipients, composed)
    except:
        print("Sending email failed. More info {}: ".format(sys.exc_info()[0]), sys.exc_info()[0])
        raise