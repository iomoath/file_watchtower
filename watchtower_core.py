__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__version__ = "1.2"
__email__ = "moath@vegalayer.com"
__created__ = "13/Dec/2018"
__modified__ = "7/Apr/2020"
__project_page__ = "https://github.com/iomoath/file_watchtower"


"""
Core functionally module of File WatchTower
"""

import os
import sqlite3
import sys

import db
import logger
from settings import EMAIL_ALERTS_ENABLED
from settings import WATCH_LIST_FILE_PATH
import notifier

import functions

module_name = os.path.basename(__file__)
FILE_COUNTER = 0  # file counter to count how many files processed during the scan process


def reset_processed_files_counter():
    global FILE_COUNTER
    FILE_COUNTER = 0


def build_watch_option(line):
    """
    Build structured options dictionary from a given string.
    string format: directory path, bool: scan_sub folders, list: excluded extensions, int: max file size in byte unit
    :param line: a line extracted from WATCH_LIST_FILE_PATH (watch_list.txt)
    :return: dict contains directory path, is_recursive_scan, excluded_extensions, max_file_size
    """
    try:
        parts = line.split(',')
        directory_info = {}

        # Try parse path
        try:
            path = parts[0].strip()
            directory_info["watch_path"] = path

            if os.path.isfile(path):
                directory_info['path_type'] = 'file'
            elif os.path.isdir(path):
                directory_info['path_type'] = 'dir'


        except:
            return None # at least, a path is required


        # Try parse is_recursive option
        try:
            parts_b = parts[1].strip()

            if parts_b == 'true':
                directory_info["is_recursive"] = True
            else:
                directory_info["is_recursive"] = False
        except:
            pass


        # Try parse excluded extensions
        try:
            directory_info['excluded_extensions'] = parts[2].strip().split('|')
        except:
            pass


        # Try parse max file length option
        try:
            directory_info['max_file_size'] = int(parts[3])
        except:
            pass


        if "is_recursive" not in directory_info:
            directory_info["is_recursive"] = False

        if "excluded_extensions" not in directory_info:
            directory_info["excluded_extensions"] = []

        if "max_file_size" not in directory_info:
            directory_info["max_file_size"] = -1

        if "exists_on_disk" not in directory_info:
            directory_info["exists_on_disk"] = True

        return directory_info
    except:
        return None


def build_watch_option_list(watch_list_file_lines):
    watch_options_list = []

    for line in watch_list_file_lines:
        watch_options = build_watch_option(line)
        if watch_options is not None:
            watch_options_list.append(watch_options)
    return watch_options_list


def get_directory_file_set(directory_path, is_recursive):

    # Get file path set
    if is_recursive:
        file_path_set = functions.get_directory_file_set_recursive(directory_path, files_only=True)
    else:
        file_path_set = functions.get_directory_file_set(directory_path, files_only=True)

    return file_path_set


def filter_file(file_path, disallowed_extensions, max_size):
    """
    Check if a file pass the provided filters.
    :param file_path: Path to file
    :param disallowed_extensions: List of disallowed extensions, separated by comma. ex; .txt, png. will check if file name end with
    :param max_size: max file size. file_path should not exceed the max_size value
    :return: None if file_path not passed the filters or file_path if filter pass.
    """
    try:
        if not os.path.exists(file_path):
            return None

        if max_size > 0:
            if os.path.getsize(file_path) > max_size:
                return None

        if disallowed_extensions is not None:
            for ext in disallowed_extensions:
                if file_path.endswith(ext):
                    return None

        return file_path
    except Exception as e:
        logger.log_error("filter_file(): An error has occurred while filtering the file '{}' Error: {}".format(file_path, e),
                         module_name)
        return None


def filter_file_path_set(file_path_set, disallowed_extensions, max_size):
    if disallowed_extensions is None and max_size <= 0: # No valid filters
        return file_path_set

    filtered_file_path_set = set()

    for file_path in file_path_set:
        logger.log_debug("filter_file_path_list(): Processing '{}'".format(file_path), module_name)

        if filter_file(file_path, disallowed_extensions, max_size) is not None:
            logger.log_debug("filter_file_path_list(): Processed '{}'".format(file_path), module_name)
            filtered_file_path_set.add(file_path)

    return filtered_file_path_set


def process_watch_list(watch_list):
    """
    :param watch_list: list contains lines of the file WATCH_LIST_FILE_PATH (watch_list.txt)
    :return: filtered file path list
    """
    file_path_set = set()
    watch_options_list = build_watch_option_list(watch_list)

    for options in watch_options_list:
        try:
            # check if the line is a file path
            if options['path_type'] == 'file':
                file_path_set.add(options['watch_path'])

            elif options['path_type'] == 'dir':
                file_path_set = get_directory_file_set(options['watch_path'], options['is_recursive'])
                file_path_set = filter_file_path_set(file_path_set, options['excluded_extensions'], options['max_file_size'])

            # check if file has a record in the DB.
            # If the file has record in the Db, then it might be deleted or moved
            # add the path to file_path_list so the integrity_check function can report this incident
            try:
                if not options['exists_on_disk']:
                    file_hash_in_db = db.get_file_hash(options['watch_path'])
                    if file_hash_in_db is not None:
                        file_path_set.add(options['watch_path'])
            except IndexError:
                continue

        except Exception as e:
            logger.log_error("process_watch_list(): An error has occurred while processing the line"
                             " '{}' More Info: {}".format(options['watch_path'], e), module_name)
            pass

    return file_path_set


def read_file_watch_list():
    """
    Reads WATCH_LIST_FILE_PATH (watch_list.txt) file and returns content
    """

    if not os.path.exists(WATCH_LIST_FILE_PATH):
        log_msg = functions.get_file_does_not_exist_msg(WATCH_LIST_FILE_PATH)
        logger.log_critical(log_msg, os.path.basename(__file__))

        if EMAIL_ALERTS_ENABLED:
            notifier.queue_email_message_text(notifier.TEMPLATE.WATCHLIST_FILE_NOT_FOUND, notifier.ALERT_LEVEL.CRITICAL, None)
        sys.exit("'{}' configuration file does not exist.".format(WATCH_LIST_FILE_PATH))

    try:
        file_stream = open(WATCH_LIST_FILE_PATH, "r")
    except IOError as e:
        log_msg = functions.get_file_read_error_msg(WATCH_LIST_FILE_PATH, e.errno, e.strerror)
        logger.log_critical(log_msg, module_name)
        if EMAIL_ALERTS_ENABLED:
            notifier.queue_email_message_text(notifier.TEMPLATE.WATCHLIST_FILE_READ_ERROR, notifier.ALERT_LEVEL.CRITICAL, None)
        sys.exit("[-] Unable to read watch list file '{}'".format(WATCH_LIST_FILE_PATH))
    else:
        with file_stream:
            file_content = file_stream.readlines()

            if not file_content:
                log_msg = functions.get_file_empty_error_msg(WATCH_LIST_FILE_PATH)
                logger.log_critical(log_msg, os.path.basename(__file__))

                if EMAIL_ALERTS_ENABLED:
                    notifier.queue_email_message_text(notifier.TEMPLATE.WATCHLIST_FILE_EMPTY,
                                                      notifier.ALERT_LEVEL.CRITICAL, None)
                sys.exit(log_msg)

            lines = [path.strip() for path in file_content]
    return lines


def db_cleanup():
    """
    Database cleanup, removes file records from the database that is no longer exist in the watch list file (WATCH_LIST_FILE_PATH)
    :return: None if error occurred during reading the path list from watch list or the database
    """
    logger.log_debug("db_cleanup():Started a database cleanup.", module_name)
    path_list = read_file_watch_list()  # from watch list file

    file_path_list = []
    dir_path_list = []

    logger.log_debug("db_cleanup():Scanning Watch list file '{}'".format(WATCH_LIST_FILE_PATH), module_name)

    for line in path_list:
        try:
            logger.log_debug("db_cleanup(): Processing line '{}'".format(line), module_name)

            watch_options = build_watch_option(line)
            if watch_options is not None:
                if watch_options["path_type"] == 'dir':
                    dir_path_list.append(watch_options['watch_path'])
                elif watch_options["path_type"] == 'file':
                    file_path_list.append(watch_options['watch_path'])

                logger.log_debug("db_cleanup(): Processed line '{}'".format(line), module_name)

        except Exception as e:
            logger.log_error("db_cleanup(): An error has occurred while processing the line '{}' Error: {}".format(line, e), module_name)
            continue

    # get all paths from database
    file_path_list_in_db = db.get_all_file_paths()

    for path in file_path_list_in_db:
        try:
            in_watch_list_file = False

            if path in file_path_list:
                in_watch_list_file = True

            for dir_path in dir_path_list:
                if functions.in_directory(path, dir_path):
                    in_watch_list_file = True

            if not in_watch_list_file:
                logger.log_debug("db_cleanup(): Removing '{}' from the database.".format(path),
                                 module_name)
                db.delete_file_record(path)
                logger.log_debug("db_cleanup(): Removed '{}' from the database.".format(path), module_name)
        except Exception as e:
            logger.log_error("db_cleanup(): An error has occurred while processing '{}' from the database. Error: {}".format(path, e), module_name)
            continue


def create_file_record(file_path):
    """
        # Calculate sha256 for given file path then insert a record into the database
        # FILE_COUNTER is increased by 1 if file processed successfully
        :param file_path: file path
        :return: True if db insertion success, false if insertion failed
        """
    if not os.path.isfile(file_path):
        return False


    try:
        logger.log_debug("create_file_record(): Creating a record for '{}'".format(file_path), module_name)

        sha256 = functions.sha256_file(file_path)
        check_date = functions.get_datetime()
        file_size = functions.get_file_size(file_path)

        file_record = {"path": file_path, "hash": sha256, "file_size": file_size, "exists_on_disk": "True",
                       "datetime_last_check": check_date}

        if db.insert_file_record(file_record) > 0:
            print("[+] Created a record for '{}'".format(file_path))
            logger.log_debug("create_file_record(): Created a DB file record for '{}'".format(file_path), module_name)
            return True
        else:
            print("[+] Failed to create a record for '{}'".format(file_path))
            logger.log_debug("create_file_record(): Failed to create a DB file record for '{}'".format(file_path),
                             module_name)
            return False

    except sqlite3.IntegrityError:
        print("[*] Ignoring '{}' Already has a record.".format(file_path))
        logger.log_debug("create_file_record(): The file '{}' is already exist in the database".format(file_path),
                         module_name)
        return False


def create_files_records(path_list):
    """
    # Calculate hash for each file and then insert a record into the database
    # FILE_COUNTER is increased by 1 for each file processed successfully
    :param path_list: file path list
    :return: nothing
    """
    global FILE_COUNTER

    for path in path_list:
        logger.log_debug("create_files_records(): Processing '{}'".format(path), module_name)
        if create_file_record(path):
            FILE_COUNTER += 1
            logger.log_debug("create_files_records(): Processed '{}'".format(path), module_name)


def is_file_renamed(file_hash, file_path_in_db):
    """
    Detects if a file in db is renamed on disk
    :param file_path_in_db: file path in db
    :param file_hash: file hash
    :return: False if file is not renamed, True if file is renamed
    """
    return not os.path.isfile(file_path_in_db) and db.is_file_has_record_by_hash(file_hash)


def is_watch_options_list_contains_file_path(watch_options_list, file_path):
    if watch_options_list is None:
        return False

    for dictionary in watch_options_list:
        if dictionary['watch_path'] == file_path:
            return True
    return False


def get_file_path_list_in_db_not_exists_on_disk():
    file_path_db_list = db.get_all_file_paths()  # list of file paths from database
    deleted_file_list = []  # list of confirmed deleted files paths

    # Get file path list (watch list)
    logger.log_debug("scan_for_file_deletion(): Reading watch list file.", module_name)
    watch_list = read_file_watch_list()

    # fill file_path_list & dir_path_list by processing watch_list lines
    watch_options_list = build_watch_option_list(watch_list)

    # Detect file deletion, if a file path in the database is not exist on disk
    # means that file is deleted or moved
    # process file_path_list & dir_path_list
    for file_path in file_path_db_list:
        logger.log_debug("detect_file_deletion(): Processing '{}' ".format(file_path), module_name)

        # Check if file exists on disk
        is_missing_on_disk = False
        db_exists_on_disk_value = db.get_exists_on_disk_value(file_path)
        if not os.path.exists(file_path):
            # Check if file is exists in watch_list file
            if is_watch_options_list_contains_file_path(watch_options_list, file_path):
                is_missing_on_disk = True
            else:
                # Check if file is located in a sub-dirs of watch-list dirs
                for options in watch_options_list:
                    if options["is_recursive"] and functions.in_directory(file_path, options["watch_path"]):
                        is_missing_on_disk = True

                    elif os.path.dirname(os.path.abspath(file_path)) == options["watch_path"]:
                        is_missing_on_disk = True

        if is_missing_on_disk and db_exists_on_disk_value == "True":
            deleted_file_list.append(file_path)
            db.update_exists_on_disk_value(file_path, "False")
            logger.log_warning("'{}' is deleted or can not be accessed".format(file_path), module_name)

        elif not is_missing_on_disk and db_exists_on_disk_value == "False":
                logger.log_warning("'{}' was missing from disk. File is now available now on disk".format(file_path), module_name)
                db.update_exists_on_disk_value(file_path, "True")

        logger.log_debug("detect_file_deletion(): Processed '{}' ".format(file_path), module_name)

    return deleted_file_list



def start_routine_scan():
    """
    # Checks if the registered file(s) hash changed since last hash check.
    # Detects new files added in directories being watched and has no record in the DB (is genuinely added ?).
    # Detects if a file(s) is deleted from disk.f
    # Detects if a file(s) is renamed.
    :return: tuple (list of files that is changed since last check, list of files that has no record in th db,
    list of files that is deleted from disk and has a record in the DB)
    """

    logger.log_debug("Started a routine scan", module_name)
    print("[+] Started a routine scan")

    files_changed_list = []  # path's for files that has been changed, hash does not match
    new_files_path_list = []  # path's for new files added since last scan. (no record in the DB)
    deleted_files_path_list = []  # path's for files deleted from disk but has a record in the DB.
    renamed_files_path_list = []  # path's for files that has been renamed

    reset_processed_files_counter()

    # Get file path list
    watch_list_file_lines = read_file_watch_list()

    # Get file path list
    file_path_list = process_watch_list(watch_list_file_lines)

    # Exclude DB file
    db_path = db.get_db_path()
    if db_path in file_path_list:
        file_path_list.remove(db_path)


    # Detect new files in dirs being watched
    # Detect File change
    # Detect File rename
    for file_path in file_path_list:
        logger.log_debug("start_routine_scan(): Processing '{}' ".format(file_path), module_name)
        try:
            file_hash = functions.sha256_file(file_path)
            file_size = functions.get_file_size(file_path)
            file_path_in_db = None
            file_hash_in_db = None
            file_size_in_db = None

            try:
                if db.is_file_has_record_by_hash(file_hash):
                    file_db_record = db.get_file_record_by_hash(file_hash)
                else:
                    file_db_record = db.get_file_record(file_path)

                has_a_db_record = file_db_record is not None
            except:
                has_a_db_record = False

            if has_a_db_record:
                file_path_in_db = file_db_record["file_path"]
                file_hash_in_db = file_db_record["hash"]
                file_size_in_db = file_db_record["file_size"]


            # Detect File rename
            if file_path_in_db is not None:
                renamed = is_file_renamed(file_hash, file_path_in_db)
                if renamed:
                    incident = {"old_path": file_path_in_db, "new_path": file_path, "hash": file_hash,
                                "detection_time": functions.get_datetime()}
                    renamed_files_path_list.append(incident)
                    db.update_file_path(file_hash, file_path)
                    db.update_exists_on_disk_value(file_path, "True")

                    print("[*] Detected a file RENAME. '{}' => '{}'".format(file_path_in_db, file_path))
                    logger.log_warning("Detected a file RENAME. '{}' => '{}'".format(file_path_in_db, file_path),
                                     module_name)

                    logger.log_file_rename(file_path_in_db, file_path, file_hash)

                    continue


            # Check if it's a new file
            p = db.get_file_hash(file_path)
            if p is None:
                file_record_dict = {"path": file_path, "hash": file_hash, "size": file_size,
                                    "detection_time": functions.get_datetime()}
                new_files_path_list.append(file_record_dict)
                create_file_record(file_path)

                print("[*] New file detected '{}' '{}'".format(file_path, file_hash))

                logger.log_info("New file detected '{}' '{}' '{}'".format(file_path, file_hash, file_size),
                                module_name)
                logger.log_debug("start_routine_scan(): Processed '{}' ".format(file_path), module_name)
                logger.log_file_creation(file_path, file_size, file_hash)
                continue

            # Detect file change
            # check if the file is changed since last check
            if file_hash_in_db is not None and file_hash != file_hash_in_db:
                # update the DB with the new file hash
                db.update_file_hash(file_path, file_hash)

                inc = {"path": file_path, "previous_hash": file_hash_in_db, "new_hash": file_hash,
                       "previous_size": file_size_in_db, "new_size": file_size,
                       "detection_time": functions.get_datetime()}
                files_changed_list.append(inc)

                print("[*] Detected a file CHANGE in '{}' '{}' => '{}'".format(file_path, file_hash_in_db, file_hash))

                logger.log_warning(
                    "Detected a file CHANGE in '{}' '{}' => '{}' '{}' => '{}'".format(file_path, file_hash_in_db, file_hash, file_size_in_db, file_size),module_name)

                logger.log_file_change(file_path, file_hash_in_db, file_size_in_db, file_size, file_hash)

            logger.log_debug("start_routine_scan(): Processed '{}' ".format(file_path), module_name)
        except Exception as e:
            logger.log_error(
                "start_routine_scan(): Unable to process file '{}' An error has occurred. {}".
                    format(file_path, e), module_name)
            continue

    try:
        deleted_list = get_file_path_list_in_db_not_exists_on_disk()
        for f_path in deleted_list:

            inc = {"path": f_path, "size": db.get_file_size(f_path), "hash": db.get_file_hash(f_path),
                   "detection_time": functions.get_datetime()}

            logger.log_warning("Detected a file DELETION. '{}'".format(f_path), module_name)
            print("[*] Detected a file DELETION. '{}'".format(f_path))


            logger.log_file_deletion(inc["path"], inc["size"], inc["hash"])

            deleted_files_path_list.append(inc)
    except:
        pass

    return files_changed_list, new_files_path_list, deleted_files_path_list, renamed_files_path_list


def silent_scan():
    global FILE_COUNTER

    logger.log_debug("Started a silent Scan", module_name)
    print("[+] Started a silent Scan")

    reset_processed_files_counter()

    # Get file path list
    watch_list_file_lines = read_file_watch_list()

    # Get file path list
    filtered_path_list = process_watch_list(watch_list_file_lines)

    # Exclude DB file
    db_path = db.get_db_path()
    if db_path in filtered_path_list:
        filtered_path_list.remove(db_path)


    # Loop through the file path list and calculate hash for each, create record in db
    logger.log_debug("silent_scan(): Creating file records in the database", module_name)
    create_files_records(filtered_path_list)

    # report & log
    logger.log_debug("Silent scan complete. Number files processed: {}".format(FILE_COUNTER), module_name)
    print("[+] Silent scan complete.")
    print("[+] Count of new files processed: {}".format(FILE_COUNTER))


def start_scan(is_silent_scan):
    db_cleanup()

    if is_silent_scan:

        silent_scan()
        return

    scan_result = start_routine_scan()

    # Violation lists
    files_changed_list = scan_result[0]
    new_files_detected_list = scan_result[1]
    deleted_files_list = scan_result[2]
    renamed_files_list = scan_result[3]


    # Queue in the DB for sending notification, notification will be sent on next cron schedule
    if len(files_changed_list) > 0 and EMAIL_ALERTS_ENABLED:
        notifier.queue_email_message(notifier.TEMPLATE.FILE_CHANGED, notifier.ALERT_LEVEL.WARNING, files_changed_list)

    if len(new_files_detected_list) > 0 and EMAIL_ALERTS_ENABLED:
        notifier.queue_email_message(notifier.TEMPLATE.NEW_FILE_DETECTED, notifier.ALERT_LEVEL.INFO,
                                     new_files_detected_list)

    if len(deleted_files_list) > 0 and EMAIL_ALERTS_ENABLED:
        notifier.queue_email_message(notifier.TEMPLATE.FILE_DELETED, notifier.ALERT_LEVEL.WARNING, deleted_files_list)

    if len(renamed_files_list) > 0 and EMAIL_ALERTS_ENABLED:
        notifier.queue_email_message(notifier.TEMPLATE.FILE_RENAMED, notifier.ALERT_LEVEL.WARNING, renamed_files_list)

    # report to log file
    print("[+] Routine scan is complete.")
    print("[+] File Change: {}".format(len(files_changed_list)))
    print("[+] File Deletion: {}".format(len(deleted_files_list)))
    print("[+] File Rename: {}".format(len(renamed_files_list)))
    print("[+] File Creation: {}".format(len(new_files_detected_list)))



def export_file_records_to_csv(export_path):
    try:
        logger.log_debug("Exporting 'file_records' table to '{}'".format(export_path), module_name)
        db.dump_file_records_to_csv(export_path)
        logger.log_debug("Exported 'file_records' table to '{}'".format(export_path),module_name)
    except Exception as e:
        print('[-] ERROR: {}'.format(e))
        logger.log_error("An error has occurred while exporting 'file_records' table to 'file_records.csv'. {}".format(e), module_name)
