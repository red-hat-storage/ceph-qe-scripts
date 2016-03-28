import os
import hashlib


def get_md5(file_path):

    return hashlib.md5(open(file_path, 'rb').read()).hexdigest()


def create_file(fname, size):

    file_size = 1024 * 1024 * size

    with open(fname, 'wb') as f:
        f.truncate(file_size)

    path = os.path.abspath(fname)

    md5 = get_md5(fname)

    return path, md5
