#!/usr/local/bin/python3
__author__ = "Moath Maharmeh"

"""
Core functionally module of File WatchTower

Created By: Moath Maharmeh
Contact: moath@vegalayer.com
"""

import hashlib
import os
import sqlite3
import sys

import db
import extensions
import file_scanner
import logger
from watchtower_settings import EMAIL_NOTIFICATIONS_ENABLED
from watchtower_settings import WATCH_LIST_FILE_PATH
import notifier

FILE_COUNTER = 0  # file counter to count how many files processed during the scan process


def reset_processed_files_counter():
    global FILE_COUNTER
    FILE_COUNTER = 0


def sha256_file(file_path):
    with open(file_path, "rb") as f:
        file_bytes = f.read()
        return hashlib.sha256(file_bytes).hexdigest()


def get_watch_dir_info(line):
    """
    line format: directory path, bool: scan_sub folders, list: excluded extensions, int: max file size in byte unit
    :param line: a line extracted from WATCH_LIST_FILE_PATH
    :return: dict contains directory path, is_recursive_scan, excluded_extensions, max_file_size
    """
    try:
        parts = line.split(',')
        directory_info = {"path": parts[0].strip(),
                          "is_recursive": parts[1].strip(),
                          "excluded_extensions": parts[2].strip().split('|'),
                          "max_size": int(parts[3])
                          }

        if directory_info["is_recursive"] == 'yes':
            directory_info["is_recursive"] = True
        elif directory_info["is_recursive"] == 'no':
            directory_info["is_recursive"] = False
        else:
            return None

        if os.path.isdir(directory_info["path"]) and len(directory_info) == 4:
            return directory_info
    except IndexError:
        return None


def filter_file(file_path, excluded_extensions, max_size):
    """
    Filters a file path against a filters excluded extensions and max file size
    :param file_path: File path
    :param excluded_extensions: List of excluded extensions
    :param max_size: max file size. file_path should not exceed the max_size value
    :return: None if file_path not passed the filters or file_path if filter pass.
    """
    try:
        if os.path.getsize(file_path) > max_size:
            return None

        for extension in excluded_extensions:
            if file_path.endswith(extension):
                return None

        return file_path
    except:
        logger.log_debug("filter_file: An error has occurred while filtering the file '{}'".format(file_path),
                         os.path.basename(__file__))
        pass


def filter_file_path_list(file_path_list, excluded_extensions, max_size):
    filtered_file_path_list = []

    for file_path in file_path_list:
        logger.log_debug("filter_file_path_list(): Processing '{}'".format(file_path), os.path.basename(__file__))
        file_path = str(file_path)

        if filter_file(file_path, excluded_extensions, max_size) is not None:
            logger.log_debug("filter_file_path_list(): Processed '{}'".format(file_path), os.path.basename(__file__))
            filtered_file_path_list.append(file_path)

    return filtered_file_path_list


def get_file_path_list(dir_info):
    """
    :param dir_info: a line from WATCH_LIST_FILE_PATH file
    :param dir_info: ex; '/var/www/html/wordpress/wp-content/themes', 'True', ['.css', '.woff', '.ttf'], 1048576
    :return: a list contain all file paths in the dir, includes files in sub-dirs if recursive scan is requested
    """
    root_dir_path = dir_info["path"]

    # Get file path list
    if dir_info["is_recursive"]:
        file_path_list = file_scanner.get_file_list_in_dir(root_dir_path, True)
    else:
        file_path_list = file_scanner.get_file_list_in_dir(root_dir_path, False)

    # Filter file path
    filtered_path_list = filter_file_path_list(file_path_list, dir_info["excluded_extensions"], dir_info["max_size"])

    return filtered_path_list


def get_dir_path_list(dir_info):
    """
    :param dir_info: a line from WATCH_LIST_FILE_PATH file
    :param dir_info: ex; '/var/www/html/wordpress/wp-content/themes', 'True', ['.css', '.woff', '.ttf'], 1048576
    :return: a list contain all directory paths in the dir, includes files in sub-dirs if recursive scan is requested
    """
    dir_path_list = []

    root_dir_path = dir_info["path"]

    # Get sub-dirs path list
    if dir_info["is_recursive"]:
        dir_path_list = extensions.get_dir_path_list(root_dir_path)

    return dir_path_list


def process_watch_list(watch_list):
    """
    # Step #2
    # Directory Format: directory path, scan_sub folders, excluded extensions, max file size in byte unit
    # comma separated, length 4 means a directory format
    # Single File Format: full_file_path
    :param watch_list: list contains lines of the file WATCH_LIST_FILE_PATH
    :return: filtered file path list
    """
    file_path_list = []
    for line in watch_list:
        try:
            # check if the line is a directory format with args
            logger.log_debug("process_watch_list(): Processing '{}'".format(line), os.path.basename(__file__))
            watch_dir = get_watch_dir_info(line)
            if watch_dir is not None:
                logger.log_debug("process_watch_list(): Processed '{}'".format(line), os.path.basename(__file__))
                file_path_list += get_file_path_list(watch_dir)

            # check if the line is a file path
            elif os.path.isfile(line):
                logger.log_debug("process_watch_list(): Processed '{}'".format(line), os.path.basename(__file__))
                file_path_list.append(line)
                continue

            # check if file has a record in the DB.
            # If the file has record in the Db, then it might be deleted or moved
            # add the path to file_path_list so the integrity_check function can report this incident
            try:
                if not os.path.exists(line) and watch_dir is None:
                    file_hash_in_db = db.get_file_hash(line)

                    if file_hash_in_db is not None:
                        logger.log_debug("process_watch_list(): Processed '{}'".format(line),
                                         os.path.basename(__file__))
                        file_path_list.append(line)
            except IndexError:
                continue

        except:
            logger.log_debug("process_watch_list(): An error has occurred while processing the line"
                             " '{}' More Info: {}".format(line, sys.exc_info()),
                             os.path.basename(__file__))
            # print(sys.exc_info()[0])
            pass

    # eliminate duplicate file paths, convert to a set
    file_path_set = extensions.convert_list_to_set(file_path_list)
    return file_path_set


def read_file_watch_list():
    """
    Reads WATCH_LIST_FILE_PATH file and returns content
    Step #1
    """

    if not os.path.exists(WATCH_LIST_FILE_PATH):
        log_msg = extensions.get_file_does_not_exist_msg(WATCH_LIST_FILE_PATH)
        logger.log_critical(log_msg, os.path.basename(__file__))

        if EMAIL_NOTIFICATIONS_ENABLED:
            notifier.queue_email_message_text(notifier.TEMPLATE.WATCHLIST_FILE_NOT_FOUND, notifier.ALERT_LEVEL.CRITICAL, None)
        sys.exit("'{}' configuration file does not exist.".format(WATCH_LIST_FILE_PATH))

    try:
        file_stream = open(WATCH_LIST_FILE_PATH, "r")
    except IOError as e:
        log_msg = extensions.get_file_read_error_msg(WATCH_LIST_FILE_PATH, e.errno, e.strerror)
        logger.log_critical(log_msg,
                            os.path.basename(__file__))
        if EMAIL_NOTIFICATIONS_ENABLED:
            notifier.queue_email_message_text(notifier.TEMPLATE.WATCHLIST_FILE_READ_ERROR, notifier.ALERT_LEVEL.CRITICAL, None)
        sys.exit("Unable to read watch list file '{}'".format(WATCH_LIST_FILE_PATH))
    else:
        with file_stream:
            file_content = file_stream.readlines()

            if not file_content:
                log_msg = extensions.get_file_empty_error_msg(WATCH_LIST_FILE_PATH)
                logger.log_critical(log_msg, os.path.basename(__file__))

                if EMAIL_NOTIFICATIONS_ENABLED:
                    notifier.queue_email_message_text(notifier.TEMPLATE.WATCHLIST_FILE_EMPTY,
                                                      notifier.ALERT_LEVEL.CRITICAL, None)
                sys.exit(log_msg)

            lines = [path.strip() for path in file_content]
    return lines


def create_file_record(file_path):
    """
        # Calculate sha256 for given file path then insert a record in the database
        # FILE_COUNTER is increased by 1 for each file processed successfully
        :param file_path: file path
        :return: nothing
        """

    global FILE_COUNTER

    if not os.path.isfile(file_path):
        return None
    try:
        logger.log_debug("create_file_record(): Creating a DB file record for '{}'".format(file_path),
                         os.path.basename(__file__))

        sha256 = sha256_file(file_path)
        check_date = extensions.get_current_datetime()
        file_size = extensions.get_file_size(file_path)
        file_record = {"path": file_path, "sha256": sha256, "file_size": file_size, "exists_on_disk": "True",
                       "datetime_last_check": check_date}

        if db.insert_file_record(file_record) > 0:
            logger.log_debug("create_file_record(): Created a DB file record for '{}'".format(file_path),
                             os.path.basename(__file__))
            FILE_COUNTER += 1
        else:
            logger.log_debug("create_file_record(): Failed to create a DB file record for '{}'".format(file_path),
                             os.path.basename(__file__))

    except sqlite3.IntegrityError:
        logger.log_debug("create_file_record(): The file '{}' is already exist in the database".format(file_path),
                         os.path.basename(__file__))


def db_cleanup():
    """
    Database cleanup, removes file records from the database that is no longer exist in the watch list file (WATCH_LIST_FILE_PATH)
    :return: None if error occurred during reading the path list from watch list or the database
    """
    logger.log_debug("db_cleanup(): Starting database cleanup.", os.path.basename(__file__))

    path_list = read_file_watch_list()  # from watch list file

    file_path_list = []
    dir_path_list = []

    logger.log_debug("db_cleanup(): Scanning Watch list file...", os.path.basename(__file__))
    for line in path_list:
        try:
            logger.log_debug("db_cleanup(): Processing '{}'".format(line), os.path.basename(__file__))
            watch_dir = get_watch_dir_info(line)
            if watch_dir is not None:
                dir_path_list.append(watch_dir["path"])
                logger.log_debug("db_cleanup(): Processed '{}'".format(line), os.path.basename(__file__))

            # check if the line is a file path
            elif os.path.isfile(line):
                logger.log_debug("db_cleanup(): Processed '{}'".format(line), os.path.basename(__file__))
                file_path_list.append(line)
                continue
        except:
            logger.log_debug("db_cleanup(): An error has occurred while processing the line '{}'".format(line), os.path.basename(__file__))
            continue

    file_path_list_in_db = db.get_all_file_paths()
    for path in file_path_list_in_db:
        try:
            in_watch_list_file = False

            if path in file_path_list:
                in_watch_list_file = True

            for dir_path in dir_path_list:
                if in_directory(path, dir_path):
                    in_watch_list_file = True

            if not in_watch_list_file:
                logger.log_debug("db_cleanup(): Removing '{}' from the database.".format(path),
                                 os.path.basename(__file__))
                db.delete_file_record(path)
                logger.log_debug("db_cleanup(): Removed '{}' from the database.".format(path),
                                 os.path.basename(__file__))
        except:
            logger.log_debug("db_cleanup(): An error has occurred while processing '{}' from the database."
                             " More info: {}".format(path, sys.exc_info()), os.path.basename(__file__))
            continue


def create_files_records(path_list):
    """
    # Calculate sha256 for each file and then insert a record in the database
    # FILE_COUNTER is increased by 1 for each file processed successfully
    :param path_list: file path list
    :return: nothing
    """
    for path in path_list:
        logger.log_debug("create_files_records(): Processing '{}'".format(path), os.path.basename(__file__))
        create_file_record(path)


def in_directory(file, directory):
    """
    Checks if a given file path is located in a sub-directory of a another dir
    :param file: File path
    :param directory: root path
    :return: True if file is in a sub-directory of "directory"
    """
    directory = os.path.join(os.path.realpath(directory), '')
    file = os.path.realpath(file)

    return os.path.commonprefix([file, directory]) == directory


def is_file_renamed(file_hash, file_path_in_db):
    """
    Detects if a file in db is renamed on disk
    :param file_path_in_db: file path in db
    :param file_hash: file hash
    :return: False if file is not renamed, True if file is renamed
    """
    return not os.path.isfile(file_path_in_db) and db.is_file_has_record_by_hash(file_hash)


def get_file_path_list_in_db_not_exists_on_disk():
    file_path_list = []  # list of file paths
    dir_path_list = []  # list of directory paths, include sub-folders paths if recursive is enabled
    file_path_db_list = db.get_all_file_paths()  # list of file paths from database
    deleted_file_list = []  # list of confirmed deleted files paths

    logger.log_debug("scan_for_file_deletion(): Detecting File deletion...", os.path.basename(__file__))

    # Get file path list (watch list)
    logger.log_debug("scan_for_file_deletion(): Reading watch list file.", os.path.basename(__file__))
    watch_list = read_file_watch_list()

    # fill file_path_list & dir_path_list by processing watch_list lines
    for line in watch_list:
        try:
            # check if the line is a directory format with args
            watch_dir = get_watch_dir_info(line)
            if watch_dir is not None:
                dir_path_list.append(watch_dir)

            # check if the line is a file path
            elif os.path.isfile(line) or os.access(os.path.dirname(line), os.W_OK):
                file_path_list.append(line)
                continue
        except ValueError:
            continue

    # Detect file deletion, if a file path in the database is not exist on disk
    # means that file is deleted
    # process file_path_list & dir_path_list
    for file_path in file_path_db_list:
        logger.log_debug("detect_file_deletion(): Processing '{}' ".format(file_path), os.path.basename(__file__))

        # Check if file exists on disk
        is_missing_on_disk = False
        db_exists_on_disk_value = db.get_exists_on_disk_value(file_path)

        if not os.path.isfile(file_path):
            # Check if file is exists in watch_list file
            if file_path in file_path_list:
                is_missing_on_disk = True
            else:
                # Check if file is located in a sub-dirs of watch-list dirs
                for dir_info in dir_path_list:
                    if dir_info["is_recursive"] and in_directory(file_path, dir_info["path"]):
                        is_missing_on_disk = True

                    elif os.path.dirname(os.path.abspath(file_path)) == dir_info["path"]:
                        is_missing_on_disk = True

        if is_missing_on_disk and db_exists_on_disk_value == "True":
            deleted_file_list.append(file_path)
            db.update_exists_on_disk_value(file_path, "False")
            logger.log_warning("'{}' is deleted or can not be accessed".format(file_path),
                                       os.path.basename(__file__))

        elif not is_missing_on_disk and db_exists_on_disk_value == "False":
                logger.log_warning("'{}' was missing from disk. File is now available now on disk".format(file_path),
                                   os.path.basename(__file__))
                db.update_exists_on_disk_value(file_path, "True")

        logger.log_debug("detect_file_deletion(): Processed '{}' ".format(file_path), os.path.basename(__file__))

    return deleted_file_list


def start_routine_scan(path_list):
    """
    # Checks if the given files is changed since last hash check.
    # Detects new files added and has no record in the DB (is genuinely added ?).
    # Detects if a file(s) is deleted from disk.
    :param path_list: file path list
    :return: tuple (list of files that is changed since last check, list of files that has no record in th db,
    list of files that is deleted from disk and has a record in the DB)
    """
    files_changed_list = []  # path's for files that has been changed, hash does not match
    new_files_path_list = []  # path's for new files added since last scan. (no record in the DB)
    deleted_files_path_list = []  # path's for files deleted from disk but has a record in the DB.
    renamed_files_path_list = []  # path's for files that has been renamed

    # Detect new files in dirs being watched
    # Detect File change
    # Detect File rename
    for file_path in path_list:
        logger.log_debug("start_routine_scan(): Processing '{}' ".format(file_path), os.path.basename(__file__))
        try:
            sha256 = sha256_file(file_path)
            file_size = extensions.get_file_size(file_path)
            file_path_in_db = None
            sha256_in_db = None
            file_size_in_db = None

            try:
                if db.is_file_has_record_by_hash(sha256):
                    file_db_record = db.get_file_record_by_hash(sha256)
                else:
                    file_db_record = db.get_file_record(file_path)

                has_a_db_record = file_db_record is not None
            except:
                has_a_db_record = False

            if has_a_db_record:
                file_path_in_db = file_db_record[1]
                sha256_in_db = file_db_record[2]
                file_size_in_db = file_db_record[3]

            # Detect File rename
            if file_path_in_db is not None:
                renamed = is_file_renamed(sha256, file_path_in_db)
                if renamed:
                    incident = {"old_path": file_path_in_db, "new_path": file_path, "sha256": sha256,
                                "detection_time": extensions.get_current_datetime()}
                    renamed_files_path_list.append(incident)
                    db.update_file_path(sha256, file_path)
                    db.update_exists_on_disk_value(file_path, "True")

                    logger.log_warning("Detected File Rename. Old Name '{}' New Name '{} '".format(file_path_in_db, file_path),
                                     os.path.basename(__file__))

                    continue

            # Check if it's a new file
            if not has_a_db_record:
                file_record_dict = {"path": file_path, "sha256": sha256, "size": file_size,
                                    "detection_time": extensions.get_current_datetime()}
                new_files_path_list.append(file_record_dict)
                create_file_record(file_path)
                logger.log_info("New file detected '{}' a record for the file has been added to the database. "
                                "File hash: '{}' File size: '{}'".format(file_path, sha256, file_size),
                                os.path.basename(__file__))
                logger.log_debug("start_routine_scan(): Processed '{}' ".format(file_path), os.path.basename(__file__))
                continue

            # Detect file change
            # check if the file is changed since last check
            if sha256_in_db is not None and sha256 != sha256_in_db:
                # update the DB with the new file hash
                db.update_file_hash(file_path, sha256)

                inc = {"path": file_path, "previous_sha256": sha256_in_db, "new_sha256": sha256,
                       "previous_size": file_size_in_db, "new_size": file_size,
                       "detection_time": extensions.get_current_datetime()}
                files_changed_list.append(inc)

                logger.log_warning(
                    "'{}' has been changed. Old hash: '{}' New hash: '{}'"
                    " Old size: '{}' New size: '{}'".format(file_path, sha256_in_db,
                                                                 sha256, file_size_in_db, file_size),
                    os.path.basename(__file__))

            logger.log_debug("start_routine_scan(): Processed '{}' ".format(file_path), os.path.basename(__file__))
        except:
            logger.log_debug(
                "start_routine_scan(): Unable to process file '{}' An error has occurred. {}".
                    format(file_path, sys.exc_info()[0]),
                os.path.basename(__file__))
            continue

    try:
        deleted_list = get_file_path_list_in_db_not_exists_on_disk()
        for f_path in deleted_list:
            inc = {"path": f_path, "size":  db.get_file_size(f_path), "sha256": db.get_file_hash(f_path),
                   "detection_time": extensions.get_current_datetime()}
            deleted_files_path_list.append(inc)
    except:
        pass

    return files_changed_list, new_files_path_list, deleted_files_path_list, renamed_files_path_list


def start_initial_scan():
    global FILE_COUNTER

    logger.log_debug("initial_scan(): Starting Initial Scan.", os.path.basename(__file__))

    # Init the file counter (to count how many files processed)
    logger.log_debug("initial_scan(): Resetting file counters", os.path.basename(__file__))
    reset_processed_files_counter()

    # Get file path list
    logger.log_debug("initial_scan(): Reading watch list file", os.path.basename(__file__))
    path_list = read_file_watch_list()

    logger.log_debug("initial_scan(): Filtering watch list paths.", os.path.basename(__file__))
    filtered_path_list = process_watch_list(path_list)

    # Exclude DB file
    db_path = db.get_db_path()
    if db_path in filtered_path_list:
        filtered_path_list.remove(db_path)

    # Loop through the file path list and calculate hash for each, create record in db
    logger.log_debug("initial_scan(): Creating file records in the database", os.path.basename(__file__))
    create_files_records(filtered_path_list)

    # report to log file
    logger.log_debug("initial_scan(): Initial scan complete. Files processed: {}".format(FILE_COUNTER),
                     os.path.basename(__file__))
    print("Initial scan complete. Number of files processed: {}".format(FILE_COUNTER))


def scan():

    logger.log_debug("scan(): Starting a routine scan..", os.path.basename(__file__))

    db_cleanup()

    # Reset the file(s) counters
    logger.log_debug("scan(): Resetting file counters.", os.path.basename(__file__))

    # Get file path list
    logger.log_debug("scan(): Reading watch list file.", os.path.basename(__file__))
    path_list = read_file_watch_list()

    logger.log_debug("scan(): Filtering watch list paths.", os.path.basename(__file__))
    filtered_path_list = process_watch_list(path_list)

    # check the files integrity
    logger.log_debug("scan(): Starting routine scan.", os.path.basename(__file__))
    check_result = start_routine_scan(filtered_path_list)
    logger.log_debug("scan(): Routine scan complete.", os.path.basename(__file__))

    # Violation lists
    files_changed_list = check_result[0]
    new_files_detected_list = check_result[1]
    deleted_files_list = check_result[2]
    renamed_files_list = check_result[3]

    # Queue in the DB for sending notification, notification will be sent on next cron schedule
    if len(files_changed_list) > 0:
        notifier.queue_email_message(notifier.TEMPLATE.FILE_CHANGED, notifier.ALERT_LEVEL.WARNING, files_changed_list)

    if len(new_files_detected_list) > 0:
        notifier.queue_email_message(notifier.TEMPLATE.NEW_FILE_DETECTED, notifier.ALERT_LEVEL.INFO,
                                     new_files_detected_list)

    if len(deleted_files_list) > 0:
        notifier.queue_email_message(notifier.TEMPLATE.FILE_DELETED, notifier.ALERT_LEVEL.WARNING, deleted_files_list)

    if len(renamed_files_list) > 0:
        notifier.queue_email_message(notifier.TEMPLATE.FILE_RENAMED, notifier.ALERT_LEVEL.WARNING, renamed_files_list)

    # report to log file
    print("Routine scan is complete.\n"
          "Files Change: {}\n"
          "Files Deletion: {}\n"
          "File Rename: {}\n"
          "New Files Detected: {}\n"
          "".format(len(files_changed_list), len(deleted_files_list), len(renamed_files_list),
                    len(new_files_detected_list)))

    # Send notifications
    if EMAIL_NOTIFICATIONS_ENABLED:
        notifier.send_queued_messages()


def export_file_records_to_csv(export_path):
    try:
        logger.log_debug("export_file_records_to_csv(): Exporting 'file_records' table to '{}'...".format(export_path),
                         os.path.basename(__file__))
        db.dump_file_records_to_csv(export_path)
        logger.log_debug("export_file_records_to_csv(): Exported 'file_records' table to '{}'...".format(export_path),
                         os.path.basename(__file__))
    except:
        logger.log_debug(
            "export_file_records_to_csv(): An error has occured while exporting"
            " 'file_records' table to 'file_records.csv'...",
            os.path.basename(__file__))
