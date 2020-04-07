__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__email__ = "moath@vegalayer.com"
__created__ = "13/Dec/2018"
__modified__ = "7/Apr/2020"
__project_page__ = "https://github.com/iomoath/file_watchtower"


import logging
import functions
from settings import DEBUG_LOG_ENABLED
from settings import DEBUG_LOG_FILE_PATH
from settings import FILE_RENAME_LOG_FILE_PATH
from settings import FILE_CREATION_LOG_FILE_PATH
from settings import FILE_CHANGE_LOG_FILE_PATH
from settings import FILE_DELETION_LOG_FILE_PATH



logging.basicConfig(filename=DEBUG_LOG_FILE_PATH,
                    level=logging.INFO,
                    format="%(asctime)s  %(levelname)-10s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")

def log_error(message, module_name):
    if not DEBUG_LOG_ENABLED:
        return
    logging.error("({}): {}".format(module_name, message))


def log_debug(message, module_name):
    if not DEBUG_LOG_ENABLED:
        return
    logging.debug("({}): {}".format(module_name, message))


def log_critical(message, module_name):
    if not DEBUG_LOG_ENABLED:
        return
    logging.critical("({}): {}".format(module_name, message))


def log_warning(message, module_name):
    if not DEBUG_LOG_ENABLED:
        return
    logging.warning("({}): {}".format(module_name, message))


def log_info(message, module_name):
    if not DEBUG_LOG_ENABLED:
        return
    logging.info("({}): {}".format(module_name, message))



def log_file_rename(old_file_path, new_file_path, file_hash):
    try:
        # Log format: [%time%] "%old_file_path%" "%new_file_path%" %file_hash%

        log_row = "[{}] \"{}\" \"{}\" {}".format(functions.get_datetime(), old_file_path, new_file_path, file_hash)

        with open(FILE_RENAME_LOG_FILE_PATH, 'a+') as f:
            f.write(log_row)
            f.write("\n")
    except Exception as e:
        log_critical(e, "logger.py")


def log_file_creation(file_path, file_size, file_hash):
    try:
        # Log format: [%time%] "%file_path%" %file_size% %file_hash%

        log_row = "[{}] \"{}\" {} {}".format(functions.get_datetime(), file_path, file_size, file_hash)

        with open(FILE_CREATION_LOG_FILE_PATH, 'a+') as f:
            f.write(log_row)
            f.write("\n")
    except Exception as e:
        log_critical(e, "logger.py")


def log_file_change(file_path, old_file_hash, old_file_size, new_file_size, new_file_hash):
    try:
        # Log format: [%time%] "%file_path%" %old_file_hash% %old_file_size% %new_file_size% %new_file_hash%

        log_row = "[{}] \"{}\" {} {} {} {}".format(functions.get_datetime(), file_path, old_file_hash, old_file_size, new_file_size, new_file_hash)

        with open(FILE_CHANGE_LOG_FILE_PATH, 'a+') as f:
            f.write(log_row)
            f.write("\n")
    except Exception as e:
        log_critical(e, "logger.py")


def log_file_deletion(file_path, file_size, file_hash):
    try:
        # Log format: [%time%] "%file_path%" %file_size% %file_hash%

        log_row = "[{}] \"{}\" {} {}".format(functions.get_datetime(), file_path, file_size, file_hash)

        with open(FILE_DELETION_LOG_FILE_PATH, 'a+') as f:
            f.write(log_row)
            f.write("\n")
    except Exception as e:
        log_critical(e, "logger.py")