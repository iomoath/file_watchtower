#!/usr/local/bin/python3

__author__ = "Moath Maharmeh"


import os
import base64
from glob import glob
import datetime

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_file_empty_error_msg(file_path):
    return "File '{}' is empty: ".format(file_path)


def get_file_read_error_msg(file_path, errno="", strerror=""):
    return "Could not read file: '{}' ({}) {}".format(file_path, errno, strerror)


def get_file_does_not_exist_msg(file_path):
    return "File '{}' does not exist".format(file_path)


def convert_list_to_set(list):
    s = set()

    for item in list:
        s.add(item)
    return s


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


def get_dir_path_list(root_dir_path):
    return glob("{}/*/".format(root_dir_path))



def get_current_datetime():
    global DATETIME_FORMAT
    return datetime.datetime.now().strftime(DATETIME_FORMAT)
