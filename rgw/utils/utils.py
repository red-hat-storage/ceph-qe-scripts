import os
import hashlib
import subprocess
import log
import json
import glob


def get_md5(file_path):

    return hashlib.md5(open(file_path, 'rb').read()).hexdigest()


def create_file(fname, size):

    file_size = 1024 * 1024 * size

    with open(fname, 'wb') as f:
        f.truncate(file_size)

    path = os.path.abspath(fname)

    md5 = get_md5(fname)

    return path, md5


def split_file(fname, size_to_split=5):

    try:

        split_cmd = "split" + " " + '-b' + str(size_to_split) + "m " + fname
        subprocess.check_output(split_cmd, shell=True, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as e:
        error = e.output + str(e.returncode)
        log.error(error)
        return False


class JsonOps(object):

    def __init__(self, fname):
        self.fname = fname

        self.total_parts_count = 0
        self.remaining_file_parts = []

    def create_json_data(self):

        json_data = {'total_parts': self.total_parts_count,
                     'remaining_parts': self.remaining_file_parts
                     }

        return json_data

    def create_update_json_file(self):

        json_data = self.create_json_data()

        with open(self.fname, "w") as fp:
            json.dump(json_data, fp, indent=4)

    def refresh_json_data(self):
        with open(self.fname) as fp:
            json_data = json.load(fp)

        self.total_parts_count = json_data['total_parts']
        self.remaining_file_parts = json_data['remaining_parts']
