__author__ = "Moath Maharmeh"
__license__ = "GNU General Public License v2.0"
__email__ = "moath@vegalayer.com"
__created__ = "13/Dec/2018"
__modified__ = "5/Apr/2020"
__project_page__ = "https://github.com/iomoath/file_watchtower"


import os
import glob
from pathlib import Path
from datetime import datetime
import hashlib
import base64
import pathlib

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_directory_file_set(dir_path, files_only, filters = None):
    """
    Scan for files in a given directory path
    :param dir_path: directory path
    :param files_only: If set to False then will get files and directories list. True will get only files list in given directory path
    :param filters: file extensions: example ['*', '*.*', '*.txt']
    :return: Set of files that matches given filters
    """
    file_path_set = set()
    if filters is None:
        filters = ['*']

    for f in filters:
        for path in glob.glob(os.path.join(dir_path, f)):
            if files_only:
                if os.path.isfile(path):
                    if type(path) is pathlib.PosixPath:
                        path = path.absolute().as_posix()
                    file_path_set.add(path)
            else:
                file_path_set.add(path)
    return file_path_set


def get_directory_file_set_recursive(root_dir_path, files_only, filters = None):
    """
    Scan for files and directories recursively in a given directory path
    :param root_dir_path: directory path
    :param files_only: If set to False then will get files and directories list. True will get only files list in given directory path
    :param filters: file extensions: example ['*', '*.*', '*.txt']
    :return: Set of files that matches given filters
    """
    file_path_set = set()

    if filters is None:
        filters = ['*']

    for f in filters:
        for path in Path(root_dir_path).glob('**/{}'.format(f)):
            if files_only:
                if os.path.isfile(path):
                    if type(path) is pathlib.PosixPath:
                        path = path.absolute().as_posix()
                    file_path_set.add(path)
            else:
                file_path_set.add(path)
    return file_path_set


def read_file_lines(file_path):
    with open(file_path) as fp:
        return fp.readlines()


def get_datetime():
    return datetime.now().strftime(DATETIME_FORMAT)


def write_to_file(file_path, content):
    with open(file_path, mode='w') as file:
        file.write(content)


def sha256_file(file_path):
    with open(file_path, "rb") as f:
        file_bytes = f.read()
        return hashlib.sha256(file_bytes).hexdigest()


def get_file_size(path):
    """
    :param path: file path on disk
    :return: file size in bytes
    """
    return os.path.getsize(path)


def encode_base64(text):
    return base64.b64encode(bytes(text, "utf-8"))


def decode_base64(base64_str):
    base64_str = base64.b64decode(base64_str)
    return base64_str.decode("utf-8")



def convert_list_to_set(lst):
    s = set()

    for item in lst:
        s.add(item)
    return s


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


def get_file_empty_error_msg(file_path):
    return "Watch list file '{}' is empty.".format(file_path)


def get_file_read_error_msg(file_path, errno="", strerror=""):
    return "Could not read file: '{}' ({}) {}".format(file_path, errno, strerror)


def get_file_does_not_exist_msg(file_path):
    return "File '{}' does not exist".format(file_path)
