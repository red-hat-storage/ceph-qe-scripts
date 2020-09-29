import os
import hashlib
import subprocess
import logging
import json
from random import randint
import configparser
import yaml
import random
import string
import socket

BUCKET_NAME_PREFIX = 'bucky' + '-' + str(random.randrange(1, 5000))
S3_OBJECT_NAME_PREFIX = 'key'
log = logging.getLogger()


def exec_shell_cmd(cmd):
    try:
        log.info('executing cmd: %s' % cmd)
        pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,  shell=True)
        out, err = pr.communicate()
        if pr.returncode == 0:
            log.info('cmd excuted')
            if out is not None: log.info(out)
            return out
        else:
            raise Exception("error: %s \nreturncode: %s" % (err, pr.returncode))
    except Exception as e:
        log.error('cmd execution failed')
        log.error(e)
        return False


def get_md5(fname):
    log.info('fname: %s' % fname)
    return hashlib.md5(open(fname, 'rb').read()).hexdigest()
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


def split_file(fname, size_to_split=5, splitlocation=""):
    # size_to_split should be in MBs
    split_cmd = "split" + " " + '-b' + str(size_to_split) + "m " + fname + " " + splitlocation
    exec_shell_cmd(split_cmd)


class FileOps(object):
    def __init__(self, filename, type):
        self.type = type
        self.fname = filename

    def get_data(self):
        data = None
        with open(self.fname, 'r') as fp:
            if self.type == 'json':
                data = json.load(fp)
            if self.type == 'txt' or self.type == 'ceph.conf':
                raw_data = fp.readlines()
                tmp = lambda x: x.rstrip('\n')
                data = list(map(tmp, raw_data))
            if self.type == 'yaml':
                data = yaml.safe_load(fp)
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
            elif self.type == 'yaml':
                yaml.dump(data, fp, default_flow_style=False)
        fp.close()


class ConfigParse(object):
    def __init__(self, fname):
        self.fname = fname
        self.cfg = configparser.ConfigParser()
        self.cfg.read(fname)

    def set(self, section, option, value=None):
        self.cfg.set(section, option, value)
        return self.cfg

    def add_section(self, section):
        try:
            self.cfg.add_section(section)
            return self.cfg
        except configparser.DuplicateSectionError as e:
            log.info('section already exists: %s' % e)
            return self.cfg

    def check_if_section_exists(self, section):
        log.info('checking if section: {} exists'.format(section))
        exists = self.cfg.has_section(section)
        log.info('section exists status: {}'.format(exists))
        return exists


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
        return executed

    def stop(self):
        executed = exec_shell_cmd('sudo systemctl stop ceph-radosgw.target')
        return executed

    def start(self):
        executed = exec_shell_cmd('sudo systemctl stop ceph-radosgw.target')
        return executed


def get_radosgw_port_no():
    op = exec_shell_cmd('sudo netstat -nltp | grep radosgw')
    log.info('output: %s' % op)
    x = op.split(" ")
    port = [i for i in x if ':' in i][0].split(':')[1]
    log.info('radosgw is running in port: %s' % port)
    return port


def get_all_in_dir(path):
    all = []

    for dirName, subdirList, fileList in os.walk(path):
        log.info('%s' % dirName)
        log.info('dir_name: %s' % dirName)
        for fname in fileList:
            log.info('filename: %s' % os.path.join(dirName, fname))
            all.append(os.path.join(dirName, fname))
        log.info('----------------')

    return all


def gen_bucket_name_from_userid(user_id, rand_no=0):
    log.info('generating bucket name or basedir to create')
    bucket_name_to_create = user_id + "." + BUCKET_NAME_PREFIX + "." + str(rand_no)
    log.info('bucket or basedir name to create generated: %s' % bucket_name_to_create)
    return bucket_name_to_create


def gen_s3_object_name(bucket_name, rand_no=0):
    log.info('generating s3 object name to create')
    s3_object_name_to_create = S3_OBJECT_NAME_PREFIX + "." + bucket_name + "." + str(rand_no)
    log.info('s3 object name to create generated: %s' % s3_object_name_to_create)
    return s3_object_name_to_create


class HttpResponseParser(object):
    def __init__(self, http_response):
        log.info('begin response ----------------------')
        log.info('http reponse:\n%s' % http_response)
        log.info('end response ----------------------')

        self.metadata = http_response['ResponseMetadata']
        log.info('metadata: %s' % self.metadata)

        self.headers = self.metadata['HTTPHeaders']
        log.info('headers: %s' % self.headers)

        self.status_code = self.metadata['HTTPStatusCode']
        log.info('status code: %s' % self.status_code)

        self.error = http_response.get('Error', None)
        log.info('Error: %s' % self.error)


def merge_two_dicts(x, y):
    """Given two dicts, merge them into a new dict as a shallow copy."""
    z = x.copy()
    z.update(y)
    return z


def gen_access_key_secret_key(base_str, access_key_len=20, secret_key_len=40):
    # consider base_str as user_id
    log.info('generating access_key and secret_key')
    log.info('base_str: %s' % base_str)
    log.info('access_key_len=%s; secret_key_len=%s' % (access_key_len, secret_key_len))

    generate = lambda len: ''.join(
        random.choice(base_str + string.ascii_uppercase + string.digits) for x in range(len))

    access_key = generate(access_key_len)
    log.info('access_key: %s' % access_key)
    secret_key = generate(secret_key_len)
    log.info('secret_key: %s' % secret_key)

    return {'access_key': access_key,
            'secret_key': secret_key}


def make_mapped_sizes(config):
    log.info('did not get mapped sizes')
    mapped_sizes = {i: get_file_size(config.objects_size_range['min'],
                                     config.objects_size_range['max'])
                    for i in range(config.objects_count)}
    log.info('mapped_sizes: %s' % mapped_sizes)
    return mapped_sizes


"""
d = {'ResponseMetadata': {'HTTPStatusCode': 404, 'RetryAttempts': 0, 'HostId': '',
                          'RequestId': 'tx00000000000000000008b-005ab40ca0-104b-default',
                          'HTTPHeaders': {'date': 'Thu, 22 Mar 2018 20:05:52 GMT', 'content-length': '285',
                                          'x-amz-request-id': 'tx00000000000000000008b-005ab40ca0-104b-default',
                                          'content-type': 'application/xml', 'accept-ranges': 'bytes'}},
     'Error': {'Message': 'The bucket policy does not exist', 'Code': 'NoSuchBucketPolicy',
               'BucketName': 'mariaq.110.bucky.1'}}
"""


def get_hostname_ip():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        log.info("Hostname : %s  " % hostname)
        log.info("IP : %s" % ip)
        return hostname, ip
    except Exception as e:
        log.info(e)
        log.error('unable to get Hostname and IP')


def cmp(val1, val2):
    return (val1 > val2) - (val1 < val2)

def get_ceph_version():
    """
    get the current ceph version
    """
    log.info('get ceph version')
    ceph_version= exec_shell_cmd('sudo ceph version')
    version_info = ceph_version.split()[4]
    return (version_info)

