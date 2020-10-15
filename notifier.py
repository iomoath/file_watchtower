__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__email__ = "moath@vegalayer.com"
__created__ = "13/Dec/2018"
__modified__ = "7/Apr/2020"
__project_page__ = "https://github.com/iomoath/file_watchtower"


import functions
import logger
import sys
import os
import db
import email_sender
import settings
from Enum import *

""" 
Severity Definition:
# CRITICAL: Unable to start. DOWN state.
# MEDIUM: Not used in WatchTower, for future use
# LOW: Not used in WatchTower, for future use
# INFO: Not used in WatchTower, for future use
"""

module_name = os.path.basename(__file__)

ALERT_LEVEL = Enum(["CRITICAL", "WARNING", "ERROR", "INFO"])

TEMPLATE = Enum(["WATCHLIST_FILE_READ_ERROR",
                 "WATCHLIST_FILE_EMPTY",
                 "FILE_CHANGED",
                 "NEW_FILE_DETECTED",
                 "FILE_DELETED",
                 "FILE_RENAMED",
                 "WATCHLIST_FILE_NOT_FOUND"
                 ])


ALERT_TEMPLATE_FILE = {
    TEMPLATE.WATCHLIST_FILE_READ_ERROR: "email_templates/watchlist_read_error.txt",
    TEMPLATE.WATCHLIST_FILE_NOT_FOUND: "email_templates/watchlist_not_found.txt",
    TEMPLATE.WATCHLIST_FILE_EMPTY: "email_templates/watchlist_file_empty.txt",
    TEMPLATE.FILE_DELETED: "email_templates/file_deleted.txt",
    TEMPLATE.FILE_CHANGED: "email_templates/file_changed.txt",
    TEMPLATE.NEW_FILE_DETECTED: "email_templates/new_file_detected.txt",
    TEMPLATE.FILE_RENAMED: "email_templates/file_renamed.txt",
}


def read_template_file(template_file):
    """Reads email template file"""
    global TEMPLATE

    template_path = ALERT_TEMPLATE_FILE[template_file]

    if not os.path.exists(template_path):
        log_msg = functions.get_file_does_not_exist_msg(template_path)
        logger.log_error(log_msg, module_name)
        sys.exit(log_msg)
    try:
        file_stream = open(template_path, "r")
    except IOError as e:
        log_msg = functions.get_file_read_error_msg(template_path, e.errno, e.strerror)
        logger.log_error(log_msg, module_name)
        sys.exit(log_msg)
    else:
        with file_stream:
            file_content = file_stream.read()

            if not file_content:
                log_msg = functions.get_file_empty_error_msg(template_path)
                logger.log_error(log_msg, module_name)
                sys.exit(log_msg)
    return file_content.strip()


def construct_msg_file_changed(file_info_list, alert_lvl):
    """
    Construct:
    1. email message from an email txt template
    2. txt email attachment contains list of files that is changed
    :param file_info_list: number of files has been changed
    :param alert_lvl: Alert level Enum
    :return: dict{subject, body, attachment}
    """

    # Message subject
    message_subject = "{} - File Change has been detected".format(alert_lvl)

    # Message body
    message_body = read_template_file(TEMPLATE.FILE_CHANGED)
    message_body = message_body.replace("%VIOLATION_COUNT%", str(len(file_info_list)))

    # Message attachment
    attachment_str = ""
    for file_info in file_info_list:
        attachment_str += "File Path: '{}'\n".format(file_info["path"])
        attachment_str += "Old Size: {}\n".format(file_info["previous_size"])
        attachment_str += "New Size: {}\n".format(file_info["new_size"])
        attachment_str += "Old Hash: {}\n".format(file_info["previous_hash"])
        attachment_str += "New Hash: {}\n".format(file_info["new_hash"])
        attachment_str += "Event time: {}\n".format(file_info["detection_time"])
        attachment_str += "-" * 50
        attachment_str += '\n'

    attachment_str = functions.encode_base64(attachment_str)
    email_msg_dict = {"subject": message_subject, "body": message_body, "attachment": attachment_str}
    return email_msg_dict


def construct_msg_new_file_detected(file_info_list, alert_lvl):
    """
       Construct:
       1. email message from an email txt template
       2. txt email attachment contains list of new detected files
       :param file_info_list: number of new files has been detected
       :param alert_lvl: Alert level Enum
       :return: dict{subject, body, attachment}
       """

    # Message subject
    message_subject = "{} - New files has been detected".format(alert_lvl)

    # Message body
    message_body = read_template_file(TEMPLATE.NEW_FILE_DETECTED)
    message_body = message_body.replace("%NEW_FILE_COUNT%", str(len(file_info_list)))

    # Message attachment
    attachment_str = ""
    for file_info in file_info_list:
        attachment_str += "File Path: '{}'\n".format(file_info["path"])
        attachment_str += "Size: {}\n".format(file_info["size"])
        attachment_str += "Hash: {}\n".format(file_info["hash"])
        attachment_str += "Event time: {}\n".format(file_info["detection_time"])
        attachment_str += "-" * 50
        attachment_str += '\n'

    attachment_str = functions.encode_base64(attachment_str)
    email_msg_dict = {"subject": message_subject, "body": message_body, "attachment": attachment_str}
    return email_msg_dict


def construct_msg_file_deleted(file_info_list, alert_lvl):
    """
           Construct:
           1. email message from an email txt template
           2. txt email attachment contains list of deleted files
           :param file_info_list: number of files has been deleted
           :param alert_lvl: Alert level Enum
           :return: dict{subject, body, attachment}
           """

    # Message subject
    message_subject = "{} - File Deletion has been detected".format(alert_lvl)

    # Message body
    message_body = read_template_file(TEMPLATE.FILE_DELETED)
    message_body = message_body.replace("%DELETION_COUNT%", str(len(file_info_list)))

    # Message attachment
    attachment_str = ""
    for file_info in file_info_list:
        attachment_str += "File Path: '{}'\n".format(file_info["path"])
        attachment_str += "Size: {}\n".format(file_info["size"])
        attachment_str += "Hash: {}\n".format(file_info["hash"])
        attachment_str += "Event time: {}\n".format(file_info["detection_time"])
        attachment_str += "-" * 50
        attachment_str += '\n'

    attachment_str = functions.encode_base64(attachment_str)
    email_msg_dict = {"subject": message_subject, "body": message_body, "attachment": attachment_str}
    return email_msg_dict


def construct_msg_file_renamed(file_info_list, alert_lvl):
    """
           Construct:
           1. email message from an email txt template
           2. txt email attachment contains list of deleted files
           :param file_info_list: number of files has been deleted
           :param alert_lvl: Alert level Enum
           :return: dict{subject, body, attachment}
           """

    # Message subject
    message_subject = "{} - File Rename has been detected".format(alert_lvl)

    # Message body
    message_body = read_template_file(TEMPLATE.FILE_RENAMED)
    message_body = message_body.replace("%RENAME_COUNT%", str(len(file_info_list)))

    # Message attachment
    attachment_str = ""
    for file_info in file_info_list:
        attachment_str += "Old Path: '{}'\n".format(file_info["old_path"])
        attachment_str += "New Path: '{}'\n".format(file_info["new_path"])
        attachment_str += "Hash: {}\n".format(file_info["hash"])
        attachment_str += "Event time: {}\n".format(file_info["detection_time"])
        attachment_str += "-" * 50
        attachment_str += '\n'

    attachment_str = functions.encode_base64(attachment_str)
    email_msg_dict = {"subject": message_subject, "body": message_body, "attachment": attachment_str}
    return email_msg_dict


def construct_msg_watchlist_not_found(alert_lvl, detection_time):

    # Message subject
    message_subject = "{} - Watchlist file could not be found".format(alert_lvl)

    # Message body
    message_body = read_template_file(TEMPLATE.WATCHLIST_FILE_NOT_FOUND)
    message_body = message_body.replace("%WATCH_LIST_FILE_PATH%", settings.WATCH_LIST_FILE_PATH)
    message_body = message_body.replace("%DETECTION_TIME%", detection_time)
    message_body += '\n'
    message_body += "-" * 50
    message_body += '\n'

    email_msg_dict = {"subject": message_subject, "body": message_body, "attachment": None}
    return email_msg_dict


def construct_msg_watchlist_read_error(alert_lvl, detection_time):
    # Message subject
    message_subject = "{} - Unable to access the Watchlist file.".format(alert_lvl)

    # Message body
    message_body = read_template_file(TEMPLATE.WATCHLIST_FILE_READ_ERROR)
    message_body = message_body.replace("%WATCH_LIST_FILE_PATH%", settings.WATCH_LIST_FILE_PATH)
    message_body = message_body.replace("%DETECTION_TIME%", detection_time)
    message_body += '\n'
    message_body += "-" * 50
    message_body += '\n'

    email_msg_dict = {"subject": message_subject, "body": message_body, "attachment": None}
    return email_msg_dict


def construct_msg_watchlist_file_empty(alert_lvl, detection_time):
    # Message subject
    message_subject = "{} - Watch list file is empty.".format(alert_lvl)

    # Message body
    message_body = read_template_file(TEMPLATE.WATCHLIST_FILE_EMPTY)
    message_body = message_body.replace("%WATCH_LIST_FILE_PATH%", settings.WATCH_LIST_FILE_PATH)
    message_body = message_body.replace("%DETECTION_TIME%", detection_time)
    message_body += '\n'
    message_body += "-" * 50
    message_body += '\n'

    email_msg_dict = {"subject": message_subject, "body": message_body, "attachment": None}
    return email_msg_dict


def construct_email_for_sending(msg_info_dict):
    try:
        attachments = functions.decode_base64(msg_info_dict["attachments"])
    except:
        attachments = None

    dict_msg = {
        "username": settings.SMTP_USERNAME,
        "password": settings.SMTP_PASSWORD,
        "host": settings.SMTP_HOST,
        "port": settings.SMTP_PORT,
        "ssl": settings.SMTP_SSL,
        "from": "{} <{}>".format(settings.FROM_NAME, settings.FROM),
        "recipients": settings.TO.split(','),
        "message": msg_info_dict["body"],
        "subject": msg_info_dict["subject"],
        "attachments": attachments}

    return dict_msg


def queue_email_message(msg_template, alert_level, file_info_list):
    """
    # Queue message in the DB For sending

    :param msg_template: Enum notifier.template
    :param alert_level: alert to be included in email subject
    :param file_info_list: list of dict. ex; [{'path': '../p.txt', 'old_hash': '111', 'new_hash': '222',
     'old_size': '507', 'new_size': 73, 'detection_time': '2018-12-13 22:56:00'}'}]
    :return:
    """
    try:
        logger.log_debug("queue_message(): Constructing Email message" "Template: '{}'".format(TEMPLATE.FILE_CHANGED),
                         module_name)

        if msg_template == TEMPLATE.FILE_CHANGED:
            msg_dict = construct_msg_file_changed(file_info_list, alert_level)
            row_id = db.insert_email_msg(msg_dict)
            if row_id > 0:
                logger.log_debug("queue_message(): Email message has been queued for sending. "
                                 "Template: '{}'".format(TEMPLATE.FILE_CHANGED),
                                 module_name)

        elif msg_template == TEMPLATE.NEW_FILE_DETECTED:
            msg_dict = construct_msg_new_file_detected(file_info_list, alert_level)

            row_id = db.insert_email_msg(msg_dict)
            if row_id > 0:
                logger.log_debug("queue_message(): Email message has been queued for sending. "
                                 "Template: '{}'".format(TEMPLATE.NEW_FILE_DETECTED),
                                 module_name)

        elif msg_template == TEMPLATE.FILE_DELETED:
            msg_dict = construct_msg_file_deleted(file_info_list, alert_level)

            row_id = db.insert_email_msg(msg_dict)
            if row_id > 0:
                logger.log_debug("queue_message(): Email message has been queued for sending. "
                                 "Template: '{}'".format(TEMPLATE.FILE_DELETED),
                                 module_name)
        elif msg_template == TEMPLATE.FILE_RENAMED:
            msg_dict = construct_msg_file_renamed(file_info_list, alert_level)

            row_id = db.insert_email_msg(msg_dict)
            if row_id > 0:
                logger.log_debug("queue_message(): Email message has been queued for sending. "
                                 "Template: '{}'".format(TEMPLATE.FILE_RENAMED),
                                 module_name)
    except Exception as e:
        logger.log_error("queue_message(): Failed to queue email message in the database. More info: {}"
                         .format(e), module_name)


def queue_email_message_text(msg_template, alert_level, msg_text):
    """
    # Queue message in the DB For sending, then try to send it after queuing it

    :param msg_template: Enum notifier.template
    :param alert_level: alert to be included in email subject
    :param msg_text: Message text
    :return:
    """
    try:
        logger.log_debug(
            "queue_message(): Constructing Email message" "Template: '{}'".format(
                TEMPLATE.WATCHLIST_FILE_READ_ERROR),
            module_name)

        if msg_template == TEMPLATE.WATCHLIST_FILE_NOT_FOUND:
            msg_dict = construct_msg_watchlist_not_found(alert_level, functions.get_datetime())

            row_id = db.insert_email_msg(msg_dict)
            if row_id > 0:
                logger.log_debug("queue_message(): Email message has been queued for sending. "
                                 "Template: '{}'".format(TEMPLATE.WATCHLIST_FILE_NOT_FOUND),
                                 module_name)

        elif msg_template == TEMPLATE.WATCHLIST_FILE_EMPTY:
            msg_dict = construct_msg_watchlist_file_empty(alert_level, functions.get_datetime())

            row_id = db.insert_email_msg(msg_dict)
            if row_id > 0:
                logger.log_debug("queue_message(): Email message has been queued for sending. "
                                 "Template: '{}'".format(TEMPLATE.WATCHLIST_FILE_NOT_FOUND),
                                 module_name)

        elif msg_template == TEMPLATE.WATCHLIST_FILE_READ_ERROR:
            msg_dict = construct_msg_watchlist_read_error(alert_level, functions.get_datetime())

            row_id = db.insert_email_msg(msg_dict)
            if row_id > 0:
                logger.log_debug("queue_message(): Email message has been queued for sending. "
                                 "Template: '{}'".format(TEMPLATE.WATCHLIST_FILE_READ_ERROR),
                                 module_name)
    except Exception as e:
        logger.log_error("queue_message(): Failed to queue email message in the database. More info: {}"
                         .format(e), module_name)

    # Try Send the message
    try:
        send_queued_messages()
    except:
        pass


def send_queued_messages():
    msg_list = db.get_unsent_messages()

    logger.log_debug("send_queued_messages(): Sending email messages..", module_name)

    for msg_dict in msg_list:
        logger.log_debug("send_queued_messages(): Sending message id '{}'".format(msg_dict["id"]), module_name)
        msg_dict_full = construct_email_for_sending(msg_dict)
        if email_sender.send_message(msg_dict_full):
            db.delete_msg(msg_dict["id"])
            logger.log_debug("send_queued_messages(): Sent message id '{}'".format(msg_dict["id"]), module_name)

    logger.log_debug("send_queued_messages(): Sending email messages complete.",
                     module_name)

