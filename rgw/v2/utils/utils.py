import configparser
import hashlib
import json
import logging
import os
import random
import shutil
import socket
import string
import subprocess
from random import randint

import yaml
from v2.lib.exceptions import SyncFailedError

BUCKET_NAME_PREFIX = "bucky" + "-" + str(random.randrange(1, 5000))
S3_OBJECT_NAME_PREFIX = "key"
log = logging.getLogger()


def exec_shell_cmd(cmd, debug_info=False):
    try:
        log.info("executing cmd: %s" % cmd)
        pr = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            shell=True,
        )
        out, err = pr.communicate()
        if pr.returncode == 0:
            log.info("cmd excuted")
            if out is not None:
                log.info(out)
                if debug_info == True:
                    log.info(err)
                    return out, err
                else:
                    return out
        else:
            raise Exception("error: %s \nreturncode: %s" % (err, pr.returncode))
    except Exception as e:
        log.error("cmd execution failed")
        log.error(e)
        get_crash_log()
        return False


def get_crash_log():
    # dump the crash log information on to the console, if any
    _, ceph_version_name = get_ceph_version()
    if ceph_version_name in ["luminous", "nautilus"]:
        crash_path = "sudo ls -t /var/lib/ceph/crash/*/log | head -1"
    else:
        crash_path = "sudo ls -t /var/lib/ceph/*/crash/*/log | head -1"
    out = exec_shell_cmd(crash_path)
    crash_file = out.rstrip("\n")
    if os.path.isfile(crash_file):
        cmd = f"cat {crash_file}"
        exec_shell_cmd(cmd)


def get_md5(fname):
    log.info("fname: %s" % fname)
    return hashlib.md5(open(fname, "rb").read()).hexdigest()
    # return "@424242"


def get_file_size(min, max):
    size = lambda x: x if x % 5 == 0 else size(randint(min, max))
    return size(randint(min, max))


def create_file(fname, size):
    # give the size in mega bytes.
    file_size = 1024 * 1024 * size
    with open(fname, "wb") as f:
        f.truncate(file_size)
    fname_with_path = os.path.abspath(fname)
    # md5 = get_md5(fname)
    return fname_with_path


def split_file(fname, size_to_split=5, splitlocation=""):
    # size_to_split should be in MBs
    split_cmd = (
        "split" + " " + "-b" + str(size_to_split) + "m " + fname + " " + splitlocation
    )
    exec_shell_cmd(split_cmd)


def cleanup_test_data_path(test_data_path):
    """
    Deletes all files and directories in mentioned test_data_path
    Args:
        test_data_path(str): Test data path
    """
    for filename in os.listdir(test_data_path):
        file_path = os.path.join(test_data_path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            log.error("Failed to delete %s. Reason: %s" % (file_path, e))


class FileOps(object):
    def __init__(self, filename, type):
        self.type = type
        self.fname = filename

    def get_data(self):
        data = None
        with open(self.fname, "r") as fp:
            if self.type == "json":
                data = json.load(fp)
            if self.type == "txt" or self.type == "ceph.conf":
                raw_data = fp.readlines()
                tmp = lambda x: x.rstrip("\n")
                data = list(map(tmp, raw_data))
            if self.type == "yaml":
                data = yaml.safe_load(fp)
        fp.close()
        return data

    def add_data(self, data):
        with open(self.fname, "w") as fp:
            if self.type == "json":
                json.dump(data, fp, indent=4)
            if self.type == "txt":
                fp.write(data)
            if self.type == "ceph.conf":
                data.write(fp)
            elif self.type is None:
                data.write(fp)
            elif self.type == "yaml":
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
            log.info("section already exists: %s" % e)
            return self.cfg

    def check_if_section_exists(self, section):
        log.info("checking if section: {} exists".format(section))
        exists = self.cfg.has_section(section)
        log.info("section exists status: {}".format(exists))
        return exists


def make_copy_of_file(f1, f2):
    """
    copy f1 to f2 location
    """
    cmd = "sudo cp %s %s" % (f1, f2)
    executed_status = exec_shell_cmd(cmd)
    if not executed_status[0]:
        return executed_status
    else:
        return os.path.abspath(f2)


def get_cluster_fsid():
    cluster_fsid = exec_shell_cmd("sudo ceph config get mon fsid")
    return cluster_fsid.rstrip("\n")


class CephOrch:
    """
    class for constructing ceph orch command
    """

    def __init__(self):
        pass

    def cmd(self, options):
        """

        Args:
            options ([list]): list of options for the command

        Returns:
            str: fully constructed ceph orch command
        """
        options = " ".join(options)
        log.info(f"forming ceph orch command, options: {options}")
        cmd = f"sudo ceph orch {options}"
        return cmd


class SystemCTL:
    """
    class for constructing systemctl command
    """

    """
    TODO : The below logic should be further enhanced to support running
    multiple RGWs on the same node.
    """

    def __init__(self, unit="ceph-radosgw@rgw.`hostname -s`.rgw0.service"):
        _, self.ceph_version_name = get_ceph_version()
        if self.ceph_version_name == "luminous":
            self.unit = "ceph-radosgw.target"
        else:
            self.unit = unit

    def cmd(self, option):
        """

        Args:
            option (str): supports start | stop | restart

        Returns:
            str: fully constructed systemctl command
        """
        return f"sudo systemctl {option} {self.unit}"


class CephOrchRGWSrv:
    """
    class which constructs ceph orch rgw sevice
    """

    def __init__(self):
        self.ceph_orch = CephOrch()
        self.unit = self._unit

    @property
    def _unit(self):
        """
        get the service unit name
        """
        options = ["ls", "rgw", "-f", "json"]
        rgw_orch_ls_cmd = self.ceph_orch.cmd(options)
        rgw_orch_ls = exec_shell_cmd(rgw_orch_ls_cmd)
        rgw_service = json.loads(rgw_orch_ls)
        rgw_service_name = rgw_service[0]["service_name"]
        return rgw_service_name

    def cmd(self, option):
        """

        Args:
            option str: supports start | stop | restart

        Returns:
            str: fully constructed ceph orch service command
        """
        cmd = self.ceph_orch.cmd([option, self.unit])
        return cmd


class RGWService:
    """
    Implements RGW service operation
    """

    def __init__(self):
        _, self.ceph_version_name = get_ceph_version()
        if self.ceph_version_name in ["luminous", "nautilus"]:
            log.info("using systemctl")
            self.srv = SystemCTL()
        else:
            log.info("using ceph orch")
            self.srv = CephOrchRGWSrv()

    def restart(self):
        """
        restarts the service
        """
        log.info("restarting service")
        cmd = self.srv.cmd("restart")
        return exec_shell_cmd(cmd)

    def stop(self):
        """
        stops the service
        """
        log.info("stopping service")
        cmd = self.srv.cmd("stop")
        return exec_shell_cmd(cmd)

    def start(self):
        """
        starts the service
        """
        log.info("starting service")
        cmd = self.srv.cmd("start")
        return exec_shell_cmd(cmd)

    def status(self):
        """
        Get status of the service
        """
        log.info("service status")
        cmd = self.srv.cmd("status")
        return exec_shell_cmd(cmd)


def get_rgw_frontends():
    """Retrieve RGW's frontend configuration."""
    try:
        out = exec_shell_cmd("sudo ceph config dump --format json")
        configs = json.loads(out)

        for config in configs:
            if config.get("name", "").lower() == "rgw_frontends":
                return config.get("value")
    except BaseException as be:
        log.debug(be)


def get_radosgw_port_no():
    """
    Return the RGW gateway port number.

    The port number is retrieved by
        - Using `ceph config dump`. (Supported from 5.0)
        - Using netstat
    """
    frontend_values = get_rgw_frontends()
    if frontend_values:
        configs = frontend_values.split()
        for config in configs:
            if "port" in config:
                return config.split("=")[-1]

    op = exec_shell_cmd("sudo netstat -nltp | grep radosgw")
    log.info(f"output: {op}")

    if not op:
        raise Exception("Unable to determine the RADOSGW port.")

    x = op.split(" ")
    port = [i for i in x if ":" in i][0].split(":")[1]
    log.info(f"RADOSGW port is: {port}")

    return port


def is_rgw_secure():
    """Check if RGW endpoint is secure."""
    frontend_values = get_rgw_frontends()
    if frontend_values:
        configs = frontend_values.split()
        for config in configs:
            if "ssl" in config:
                return True

        return False

    log.info("Unable to determine the if RGW gateway is secure.")
    return None


def get_all_in_dir(path):
    all = []

    for dirName, subdirList, fileList in os.walk(path):
        log.info("%s" % dirName)
        log.info("dir_name: %s" % dirName)
        for fname in fileList:
            log.info("filename: %s" % os.path.join(dirName, fname))
            all.append(os.path.join(dirName, fname))
        log.info("----------------")

    return all


def gen_bucket_name_from_userid(user_id, rand_no=0):
    log.info("generating bucket name or basedir to create")
    # As per S3 and Swift bucket naming rules only lowercase letters, numbers, dots (.), and hyphens (-) are allowed
    if "$" in user_id or ":" in user_id:
        user_id = user_id.replace("$", ".").replace(":", "-")

    # BZ1942136 : In pacific,bucket creation with underscore( _ ) fails with 'InvalidBucketName'
    bucket_name_to_create = user_id + "-" + BUCKET_NAME_PREFIX + "-" + str(rand_no)
    log.info("bucket or basedir name to create generated: %s" % bucket_name_to_create)
    return bucket_name_to_create


def gen_s3_object_name(bucket_name, rand_no=0):
    log.info("generating s3 object name to create")
    s3_object_name_to_create = (
        S3_OBJECT_NAME_PREFIX + "_" + bucket_name + "_" + str(rand_no)
    )
    log.info("s3 object name to create generated: %s" % s3_object_name_to_create)
    return s3_object_name_to_create


def create_psuedo_dir(s3_pseudo_dir, bucket):
    """
    creates a psuedo directory object structure
    :param s3_pseudo_dir_name: name of the pseudo structure to create
    :param bucket: S3Bucket object
    """
    s3_pseudo_dir_created = bucket.put_object(Key=s3_pseudo_dir + "/")
    s3_pseudo_dir_name = s3_pseudo_dir + "/"
    print(s3_pseudo_dir_name)
    return s3_pseudo_dir_created, s3_pseudo_dir_name


def gen_s3_pseudo_object_name(pseudo_dir_name, rand_no=0):
    """
    creates an s3 object in a pseudo directory
    :param s3_pseudo_dir_name: name of the pseudo structure
    :return: s3_pseudo_object_name_to_create
    """
    log.info("generating s3 pseudo object name to create")
    s3_pseudo_object_name_to_create = (
        pseudo_dir_name + "/" + S3_OBJECT_NAME_PREFIX + "_" + str(rand_no)
    )
    log.info(
        "s3 pseudo object name to create generated: %s"
        % s3_pseudo_object_name_to_create
    )
    return s3_pseudo_object_name_to_create


class HttpResponseParser(object):
    def __init__(self, http_response):
        log.info("begin response ----------------------")
        log.info("http reponse:\n%s" % http_response)
        log.info("end response ----------------------")

        self.metadata = http_response["ResponseMetadata"]
        log.info("metadata: %s" % self.metadata)

        self.headers = self.metadata["HTTPHeaders"]
        log.info("headers: %s" % self.headers)

        self.status_code = self.metadata["HTTPStatusCode"]
        log.info("status code: %s" % self.status_code)

        self.error = http_response.get("Error", None)
        log.info("Error: %s" % self.error)


def merge_two_dicts(x, y):
    """Given two dicts, merge them into a new dict as a shallow copy."""
    z = x.copy()
    z.update(y)
    return z


def gen_access_key_secret_key(base_str, access_key_len=20, secret_key_len=40):
    # consider base_str as user_id
    log.info("generating access_key and secret_key")
    log.info("base_str: %s" % base_str)
    log.info("access_key_len=%s; secret_key_len=%s" % (access_key_len, secret_key_len))

    generate = lambda len: "".join(
        random.choice(base_str + string.ascii_uppercase + string.digits)
        for x in range(len)
    )

    access_key = generate(access_key_len)
    log.info("access_key: %s" % access_key)
    secret_key = generate(secret_key_len)
    log.info("secret_key: %s" % secret_key)

    return {"access_key": access_key, "secret_key": secret_key}


def validate_unit(min_u, max_u, min_s, max_s):
    unit = {"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}
    min_u = unit.get(min_u)
    max_u = unit.get(max_u)
    min_size = min_u * min_s
    max_size = max_u * max_s
    if min_size > max_size:
        log.error("MIN size and MAX size is not defined correctly")
    else:
        return min_size, max_size


def make_mapped_sizes(config):
    log.info("did not get mapped sizes")
    min = config.objects_size_range["min"]
    max = config.objects_size_range["max"]
    unit = "M"
    if type(min) and type(max) is str:
        min_unit = min[-1]  # gives min unit
        max_unit = max[-1]  # gives max unit
        min = int(min[:-1])  # gives min number
        max = int(max[:-1])  # gives max number
        min, max = validate_unit(min_unit, max_unit, min, max)

    elif type(min) is not str and type(max) is str:
        min_unit = max[-1]  # gives min unit
        max_unit = max[-1]  # gives max unit
        max = int(max[:-1])  # gives max number
        min, max = validate_unit(min_unit, max_unit, min, max)

    elif type(min) is str and type(max) is not str:
        min_unit = min[-1]  # gives min unit
        max_unit = min[-1]  # gives max unit
        min = int(min[:-1])  # gives min number
        min, max = validate_unit(min_unit, max_unit, min, max)

    else:
        min, max = validate_unit(unit, unit, min, max)

    mapped_sizes = {i: (get_file_size(min, max)) for i in range(config.objects_count)}
    log.info("mapped_sizes: %s" % mapped_sizes)
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


def get_realm_source_zone_info():
    op = exec_shell_cmd("radosgw-admin sync status")
    lst = list(op.split("\n"))
    for l in lst:
        if "realm" in l:
            realm = l[l.find("(") + 1 : l.find(")")]
        if "data sync source" in l:
            source_zone = l[l.find("(") + 1 : l.find(")")]
    return realm, source_zone


def check_bucket_sync(name):
    _, source_zone = get_realm_source_zone_info()
    log.info(f"Source zone name: {source_zone}")
    cmd = f"radosgw-admin bucket sync run --bucket={name} --source-zone={source_zone}"
    out = exec_shell_cmd(cmd)
    return out


def bucket_sync_status(name, retry=10, delay=15):
    log.info(
        f"check if bucket sync is in progress, if bucket sync is in progress retry {retry} times with {delay}secs of sleep between each retry"
    )
    cmd = f"radosgw-admin bucket sync status --bucket={name}"
    out = exec_shell_cmd(cmd)
    if "behind shards" in out:
        log.info("bucket sync is in progress")
        log.info(f"sleep of {delay} secs for sync to complete")
        for retry_count in range(retry):
            time.sleep(delay)
        if (retry_count > retry) and ("behind shards" in out):
            out = utils.check_bucket_sync(bucket.name)
            if out is False:
                raise SyncFailedError(
                    f"Bucket sync status not caught up with source after performing bucket sync run with {retry} retries and sleep of {delay}secs between each retry"
                )
    else:
        log.info("bucket is caught up with source zone.")


def get_hostname_ip():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        log.info("Hostname : %s  " % hostname)
        log.info("IP : %s" % ip)
        return hostname, ip
    except Exception as e:
        log.info(e)
        log.error("unable to get Hostname and IP")


def cmp(val1, val2):
    return (val1 > val2) - (val1 < val2)


def get_ceph_version():
    """
    get the current ceph version
    """
    log.info("get ceph version")
    ceph_version = exec_shell_cmd("sudo ceph version")
    version_id, version_name = ceph_version.split()[2], ceph_version.split()[4]
    return version_id, version_name


def check_dbr_support():
    # checks if the cluster version is greater than 4.3 or not
    ceph_version_id, _ = get_ceph_version()
    ceph_version_id = ceph_version_id.split("-")
    ceph_version_id = ceph_version_id[0].split(".", 1)
    if float(ceph_version_id[0]) == 14 and float(ceph_version_id[1]) >= 2.22:
        return True
    elif float(ceph_version_id[0]) == 16 and float(ceph_version_id[1]) > 2.0:
        return True
    elif float(ceph_version_id[0]) > 16:
        return True
    else:
        return False


def is_cluster_primary():
    # checks if the cluster is primary or not
    # if primary return True or return False if not, assume as secondary
    log.info("verify if cluster is primary or not")
    cmd = "sudo radosgw-admin sync status"
    out = exec_shell_cmd(cmd)
    if "zone is master" in out:
        log.info("cluster is primary")
        return True
    log.info("cluster is not primary")
    return False


def is_cluster_multisite():
    """
    checks if the cluster is single site or multisite
    return: True is multisite else False for single site
    """
    log.info("verify if the cluster is singlesite or multisite")
    cmd = "sudo radosgw-admin sync status"
    out = exec_shell_cmd(cmd)
    if "realm  ()" in out:
        log.info("the cluster is single site")
        return False
    elif "data sync source" in out:
        log.info("the cluster is multisite")
        return True
    else:
        log.info("the cluster is multi realm")
        return False
