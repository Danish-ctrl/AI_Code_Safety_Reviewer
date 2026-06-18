# file_loader.py

import os
from config import SUPPORTED_EXTENSIONS, IGNORED_FOLDERS


def should_ignore_folder(folder_name):
    return folder_name in IGNORED_FOLDERS


def is_supported_file(file_name):
    return any(file_name.endswith(extension) for extension in SUPPORTED_EXTENSIONS)


def find_files_to_scan(folder_path):
    files_to_scan = []

    for root, folders, files in os.walk(folder_path):
        folders[:] = [
            folder for folder in folders
            if not should_ignore_folder(folder)
        ]

        for file in files:
            if is_supported_file(file):
                full_path = os.path.join(root, file)
                files_to_scan.append(full_path)

    return files_to_scan