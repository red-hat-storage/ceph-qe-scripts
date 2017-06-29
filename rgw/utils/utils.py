import os
import hashlib
import subprocess
import log
import json
from random import randint
import ConfigParser


def exec_shell_cmd(command):

    try:

        print('executing command: %s' % command)

        variable = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        v = variable.stdout.read()
        return True, v

    except (Exception, subprocess.CalledProcessError) as e:
        print('command failed')
        error = e.output + " " + str(e.returncode)
        print(error)
        return False, error


def get_md5(file_path):

    return hashlib.md5(open(file_path, 'rb').read()).hexdigest()

    # return "@424242"


def get_file_size(min, max):

    size = lambda x: x if x % 5 == 0 else size(randint(min, max))

    return size(randint(min, max))


def create_file(fname, size):

    # give the size in mega bytes.

    file_size = 1024 * 1024 * size

    with open(fname, 'wb') as f:
        f.truncate(file_size)

    fname_with_path = os.path.abspath(fname)

    # md5 = get_md5(fname)

    return fname_with_path


def split_file(fname, size_to_split=5):

    try:

        split_cmd = "split" + " " + '-b' + str(size_to_split) + "m " + fname
        subprocess.check_output(split_cmd, shell=True, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as e:
        error = e.output + str(e.returncode)
        log.error(error)
        return False


class FileOps(object):

    def __init__(self, filename, type):
        self.type = type
        self.fname = filename

    def get_data(self):

        data = None

        with open(self.fname) as fp:

            if self.type == 'json':
                data = json.load(fp)

            if self.type == 'txt' or self.type == 'ceph.conf' :
                raw_data = fp.readlines()
                tmp = lambda x: x.rstrip('\n')
                data = map(tmp, raw_data)

        fp.close()

        return data

    def add_data(self, data):

        with open(self.fname, "w") as fp:

            if self.type == 'json':

                json.dump(data, fp, indent=4)

            if self.type == 'txt':
                fp.write(data)

            if self.type == 'ceph.conf':
                data.write(fp)

            elif self.type is None:
                data.write(fp)

        fp.close()


class ConfigParse(object):

    def __init__(self, fname):

        self.fname = fname
        self.cfg = ConfigParser.ConfigParser()
        self.cfg.read(fname)

    def set(self, section, option, value =None):

        self.cfg.set(section, option, value)

        return self.cfg

    def add_section(self, section):

        try:
            self.cfg.add_section(section)
            return self.cfg
        except ConfigParser.DuplicateSectionError, e :
            log.info('section already exists: %s' % e)
            return self.cfg

def make_copy_of_file(f1, f2):

    """
    copy f1 to f2 location

    """

    cmd = 'sudo cp %s %s' % (f1, f2)
    executed_status = exec_shell_cmd(cmd)

    if not executed_status[0]:
        return executed_status
    else:
        return os.path.abspath(f2)


class RGWService(object):

    def __init__(self):
        pass

    def restart(self):

        executed = exec_shell_cmd('sudo systemctl restart ceph-radosgw.target')

        return executed[0]

    def stop(self):

        executed = exec_shell_cmd('sudo systemctl stop ceph-radosgw.target')

        return executed[0]

    def start(self):

        executed = exec_shell_cmd('sudo systemctl stop ceph-radosgw.target')

        return executed[0]


def get_radosgw_port_no():

    op = exec_shell_cmd('sudo netstat -nltp | grep radosgw')

    x = op[1].split(" ")

    port = [i for i in x if ':' in i][0].split(':')[1]

    log.info('radosgw is running in port: %s' % port)

    return port


def get_all_in_dir(path):

    all = []

    for dirName, subdirList, fileList in os.walk(path):
        print('%s' % dirName)
        log.info('dir_name: %s' % dirName)
        for fname in fileList:
            log.info('filename: %s' % os.path.join(dirName,fname))
            all.append( os.path.join(dirName,fname))
        log.info('----------------')

    return all

