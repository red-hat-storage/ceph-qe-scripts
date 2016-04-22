import os
import hashlib
import subprocess
import log
import json
from random import randint


def get_md5(file_path):

    return hashlib.md5(open(file_path, 'rb').read()).hexdigest()


def get_file_size(min, max):

    size = lambda x: x if x % 5 == 0 else size(randint(min, max))

    return size(randint(min, max))


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


class JsonFileOps(object):

    def __init__(self, filename):

        self.fname = filename

    def get_data(self):

        with open(self.fname) as fp:
            json_data = json.load(fp)
        fp.close()

        return json_data

    def add_data(self, data):

        with open(self.fname, "w") as fp:
            json.dump(data, fp, indent=4)
        fp.close()
