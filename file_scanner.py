#!/usr/local/bin/python3

import os
import glob
from pathlib import Path


def recursive_file_scan(root_dir_path, filters):
    """scans a directory recursively for files"""
    file_path_set = set()

    for f in filters:
        for file_path in Path(root_dir_path).glob('**/{}'.format(f)):
            if os.path.isfile(file_path):
                file_path_set.add(file_path)
    return file_path_set


def get_file_list_in_dir(dir_path, recursive):
    file_path_list = []
    filters = ['*', '.*']

    if not recursive:
        for f in filters:
            file_path_list.extend(glob.glob(os.path.join(dir_path, f)))
        return file_path_list
    else:
        return recursive_file_scan(dir_path, filters)
