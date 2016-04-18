import os
import hashlib
import subprocess
import log
import json
import glob


def get_md5(file_path):

    return hashlib.md5(open(file_path, 'rb').read()).hexdigest()


def create_file(fname, size):

    # give the size in mega bytes.

    file_size = 1024 * 1024 * size

    with open(fname, 'wb') as f:
        f.truncate(file_size)

    fname_with_path = os.path.abspath(fname)

    md5 = get_md5(fname)

    return fname_with_path, md5


def split_file(fname, size_to_split=5):

    try:

        split_cmd = "split" + " " + '-b' + str(size_to_split) + "m " + fname
        subprocess.check_output(split_cmd, shell=True, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as e:
        error = e.output + str(e.returncode)
        log.error(error)
        return False


def break_connection():
    pass
