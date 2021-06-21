import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import collections
import random
import shutil
import time

import v1.utils.log as log
import v1.utils.utils as utils
from v1.lib.s3.bucket import Bucket
from v1.lib.s3.json_ops import JBucket, JKeys
from v1.lib.s3.objects import KeyOp, PutContentsFromFile
from v1.utils.utils import FileOps

"""
dir_info = {'key_name': 'key_name',
            'size': 0,
            'md5': None,
            'is_type': 'dir',
            'opcode': {'move':   {'new_name': None},
                       'delete': {'deleted': True},
                       'edit': {'new_md5': 0}
                       }
            }
"""


class BaseDir(object):
    def __init__(self, count, json_fname, mount_point, auth):
        self.count = count
        self.json_fname = json_fname
        self.created_dirs = []
        self.mount_point = mount_point
        self.rgw_auth = auth
        self.bucket = Bucket(self.rgw_auth)

    def create(self, uname="default_user"):
        print("uname :%s " % uname)
        log.info("creating base dir")
        base_dir_name = "/" + uname + "." + "base_dir"
        dirs = [
            os.path.abspath(
                self.mount_point
                + base_dir_name
                + str(i)
                + "."
                + str(random.randint(1, 1000))
            )
            for i in range(self.count)
        ]
        [log.info("dir to create : %s" % dir) for dir in dirs]
        jbucket = JBucket(self.json_fname)
        for dir in dirs:
            log.info("creating dir :%s" % dir)
            os.makedirs(dir)
            jbucket.add(os.path.basename(dir))
            self.created_dirs.append(dir)
        [log.info("created dir :%s" % dir) for dir in self.created_dirs]
        return self.created_dirs

    def delete_d(self):
        self.created_dirs.reverse()
        print("deleting dirs")
        [shutil.rmtree(x) for x in self.created_dirs]

    def verify_s3(self):
        fp = FileOps(self.json_fname, type="json")
        json_data = fp.get_data()
        buckets_list = list(json_data["buckets"].keys())
        bstatus = []
        for each_bucket in buckets_list:
            log.info("getting bucket info for base dir: %s" % each_bucket)
            status = {}
            info = self.bucket.get(each_bucket)
            if not info["status"]:
                status["exists"] = False
            else:
                status["exists"] = True
                status["bucket_name"] = info["bucket"]
            bstatus.append(status)
        log.info("bucket verification status :\n")
        [log.info("%s \n" % bs) for bs in bstatus]
        return bstatus

    def verify_nfs(self):
        get_dir_list = lambda dir_path: os.listdir(dir_path)
        compare = lambda x, y: collections.Counter(x) == collections.Counter(y)
        base_dirs = get_dir_list(os.path.abspath(self.mount_point))
        [log.info("base_dirs: %s" % dir) for dir in base_dirs]
        fp = FileOps(self.json_fname, type="json")
        json_data = fp.get_data()
        buckets_list = list(json_data["buckets"].keys())
        [log.info("bucket list: %s" % bucket) for bucket in buckets_list]
        bstatus = compare(base_dirs, buckets_list)
        log.info("bucket comparision status: %s" % bstatus)
        return bstatus


class SubdirAndObjects(object):
    def __init__(
        self, base_dir_list, config, json_fname, auth, download_json_fname=None
    ):
        self.base_dir_list = base_dir_list
        self.config = config
        self.json_fname = json_fname
        self.created = []
        self.download_json_fname = download_json_fname
        self.bucket_conn = Bucket(auth)

    def create(self, file_type=None):
        log.info("in sub dir create")
        nest_level = self.config["sub_dir_count"]
        files = self.config["Files"]
        jkeys = JKeys(self.json_fname)
        for base_dir in self.base_dir_list:
            log.info("base_dir name: %s" % base_dir)
            subdirs = ["dir" + str(i) for i in range(nest_level)]
            log.info("subdirs to create: %s" % subdirs)
            for dir in subdirs:
                nest = os.path.join(base_dir, dir)
                log.info("creating dir  :%s" % nest)
                os.makedirs(nest)
                self.created.append(nest)
                key_name = dir + "/"
                dir_info = {
                    "key_name": key_name,
                    "size": 0,
                    "md5_matched": None,
                    "md5_on_s3": None,
                    "md5_local": None,
                    "is_type": "dir",
                    "opcode": {
                        "move": {"old_name": None},
                        "delete": {"deleted": None},
                        "edit": {"new_md5": 0},
                    },
                }
                log.info(
                    "sub dir info -------------------------------- \n%s" % dir_info
                )
                jkeys.add(os.path.basename(base_dir), **dir_info)
                for no in range(files["files_in_dir"]):
                    fname = os.path.join(nest, "file" + str(no))
                    log.info("creating file :%s" % fname)
                    if file_type == "text":
                        fcreate = "base64 /dev/urandom | head -c %sM > %s" % (
                            files["size"],
                            fname,
                        )
                    else:
                        fcreate = "sudo dd if=/dev/urandom of=%s bs=%sM count=1" % (
                            fname,
                            files["size"],
                        )
                    log.info("fcreate command: %s" % fcreate)
                    os.system(fcreate)
                    fname_created = fname.split(base_dir)[1].lstrip("/")
                    file_info = {
                        "key_name": fname_created,
                        "size": os.stat(fname).st_size,
                        "md5_local": utils.get_md5(fname),
                        "md5_on_s3": None,
                        "is_type": "file",
                        "opcode": {
                            "move": {"old_name": None},
                            "delete": {"deleted": None},
                            "edit": {"new_md5": 0},
                        },
                    }
                    log.info(
                        "file info -------------------------------- \n%s" % file_info
                    )
                    jkeys.add(os.path.basename(base_dir), **file_info)
                    self.created.append(fname)
        [log.info("created :%s" % d) for d in self.created]
        return self.created

    def delete_d(self):
        self.created.reverse()
        print("deleting dirs")
        [shutil.rmtree(x) for x in self.created]

    def verify_s3(self, op_type=None):
        time.sleep(300)  # sleep for 300 secs
        kstatus = []
        fp = FileOps(self.json_fname, type="json")
        json_data = fp.get_data()
        buckets_info = json_data["buckets"]
        for bucket_name, key in list(buckets_info.items()):
            log.info("got bucket_name: %s" % bucket_name)
            bucket = self.bucket_conn.get(bucket_name)
            for key_info in key["keys"]:
                key_name_to_find = key_info["key_name"]
                log.info("verifying key: %s" % key_name_to_find)
                status = {}
                status["bucket_name"] = bucket_name
                keyop = KeyOp(bucket["bucket"])
                info = keyop.get(key_name_to_find)
                status["key_name"] = key_name_to_find
                status["type"] = key_info["is_type"]
                md5_on_s3 = key_info["md5_on_s3"]
                if info is None:
                    status["exists"] = False
                else:
                    status["exists"] = True
                    if key_info["is_type"] == "file":
                        if op_type == "edit":
                            if key_info["md5_local"] == md5_on_s3:
                                status["md5_matched"] = True
                            else:
                                status["md5_matched"] = False
                        else:
                            print(key_info["md5_local"])
                            print(md5_on_s3)
                            if key_info["md5_local"] == info.etag[1:-1]:
                                status["md5_matched"] = True
                            else:
                                status["md5_matched"] = False
                            if key_info["size"] == info.size:
                                status["size_matched"] = True
                            else:
                                status["size_matched"] = False
                kstatus.append(status)
        log.info("keys verification status :\n")
        [log.info("%s \n" % ks) for ks in kstatus]
        return kstatus

    def verify_nfs(self, mount_point, op_type=None):
        time.sleep(300)  # sleep for 300 secs
        kstatus = []
        fp = FileOps(self.json_fname, type="json")
        json_data = fp.get_data()
        buckets_info = json_data["buckets"]
        for bucket_name, key in list(buckets_info.items()):
            log.info("got bucket_name: %s" % bucket_name)
            local_bucket = os.path.abspath(os.path.join(mount_point, bucket_name))
            print("local bucket: --------------- %s" % local_bucket)
            for key_info in key["keys"]:
                log.info("verifying key: %s" % key_info["key_name"])
                status = {}
                # status['bucket_name'] = bucket_name
                local_key = os.path.join(local_bucket, key_info["key_name"])
                if key_info["key_name"] in os.path.basename(local_key):
                    status["key_name"] = key_info["key_name"]
                    status["exists"] = os.path.exists(local_key)
                    log.info("local key: %s" % local_key)
                    if op_type == "edit":
                        log.info("in operation: -----> edit")
                        # size = os.path.getsize(local_key)
                        # md5 = utils.get_md5(local_key)
                        md5_local = key_info["md5_local"]
                        md5_on_s3 = key_info["md5_on_s3"]
                        if md5_local == md5_on_s3:
                            status["md5_matched"] = True
                        else:
                            status["md5_matched"] = False
                    else:
                        if status["exists"]:
                            size = os.path.getsize(local_key)
                            md5 = utils.get_md5(local_key)
                            if size == key_info["size"]:
                                status["size_matched"] = True
                            else:
                                status["size_matched"] = False
                            if md5 == key_info["md5_on_s3"]:
                                status["md5_matched"] = True
                                log.info(key_info["md5_on_s3"])
                                log.info(md5)
                            else:
                                status["md5_matched"] = False
                log.info("status of this key: %s" % status)
                kstatus.append(status)
        [log.info("%s \n" % ks) for ks in kstatus]
        return kstatus

    def operation_on_nfs(self, mount_point, op_code):
        time.sleep(300)  # sleep for 300 secs before operations start
        opstatus = []
        status = {}
        log.info("operation started-------------- : %s" % op_code)
        fp = FileOps(self.json_fname, type="json")
        json_data = fp.get_data()
        buckets_info = json_data["buckets"]
        for bucket_name, key in list(buckets_info.items()):
            log.info("got bucket_name: %s" % bucket_name)
            local_bucket = os.path.abspath(os.path.join(mount_point, bucket_name))
            print("local bucket: --------------- %s" % local_bucket)
            local_keys = utils.get_all_in_dir(local_bucket)
            log.info("local key: %s" % local_bucket)
            log.info("local keys: %s" % local_keys)
            for key_info in key["keys"]:
                local_key = os.path.join(local_bucket, key_info["key_name"])
                if key_info["is_type"] == "file":
                    log.info("operation on  key: %s" % key_info["key_name"])
                    log.info("local key: ------------------ %s" % local_key)
                    if op_code == "move":
                        status["bucket_name"] = bucket_name
                        status["key_name"] = key_info["key_name"]
                        status["op_code"] = op_code
                        new_key_path = local_key + ".moved"
                        new_name = key_info["key_name"] + ".moved"
                        cmd = "sudo mv %s %s" % (
                            os.path.abspath(local_key),
                            os.path.abspath(new_key_path),
                        )
                        log.info("cmd_to_move: %s" % cmd)
                        time.sleep(5)
                        ret_val = os.system(cmd)
                        if ret_val == 0:
                            key_info["opcode"]["move"]["old_name"] = key_info[
                                "key_name"
                            ]
                            key_info["key_name"] = new_name
                            fp.add_data(json_data)
                            status["op_code_status"] = True
                        else:
                            log.info("move failed: %s" % local_key)
                            status["op_code_status"] = False
                    if op_code == "edit":
                        try:
                            log.info("editing file: %s" % local_key)
                            key_modify = open(local_key, "a+")
                            key_modify.write(
                                "file opened from NFS and added this messages"
                            )
                            key_modify.close()
                            key_info["opcode"]["edit"]["new_md5"] = utils.get_md5(
                                os.path.abspath(local_key)
                            )
                            key_info["md5_local"] = utils.get_md5(
                                os.path.abspath(local_key)
                            )
                            key_info["md5_on_s3"] = None
                            status["op_code_status"] = True
                        except Exception as e:
                            log.info("could not edit")
                            log.error(e)
                            status["op_code_status"] = False
                    if op_code == "delete":
                        status["bucket_name"] = bucket_name
                        status["key_name"] = key_info["key_name"]
                        status["op_code"] = op_code
                        log.info("deleting key: %s" % key_info["key_name"])
                        # ret_val = os.system('sudo rm -rf %s' % (local_key))
                        try:
                            os.unlink(local_key)
                            key_info["opcode"]["delete"]["deleted"] = True
                            fp.add_data(json_data)
                            status["op_code_status"] = True
                            log.info("deleted key: %s" % key_info["key_name"])
                        except (Exception, OSError) as e:
                            log.error("deleting key: %s failed" % key_info["key_name"])
                            key_info["opcode"]["delete"]["deleted"] = False
                            log.error("delete failed: %s" % local_key)
                            log.error(e)
                            status["op_code_status"] = False
                opstatus.append(status)
        [log.info(st) for st in opstatus]
        return opstatus

    def operation_on_s3(self, op_code=None):
        time.sleep(300)  # sleep for 300 secs before operation starts
        log.info("operation on s3 started with opcode: %s" % op_code)
        ks_op_status = []
        fp = FileOps(self.json_fname, type="json")
        json_data = fp.get_data()
        buckets_info = json_data["buckets"]
        for bucket_name, key in list(buckets_info.items()):
            log.info("got bucket_name: %s" % bucket_name)
            bucket = self.bucket_conn.get(bucket_name)
            for key_info in key["keys"]:
                key_name = key_info["key_name"]
                log.info("verifying key: %s" % key_name)
                status = dict()
                status["op_code"] = op_code
                status["bucket_name"] = bucket_name
                keyop = KeyOp(bucket["bucket"])
                kinfo = keyop.get(key_name)
                print("got key_info -------------------------- from s3 :%s" % kinfo)
                if op_code == "move":
                    try:
                        log.info("in move operation")
                        new_key_name = key_name + ".moved"
                        kinfo.copy(bucket_name, new_key_name)
                        kinfo.delete()
                        key_info["opcode"]["move"]["old_name"] = key_name
                        key_info["key_name"] = new_key_name
                        fp.add_data(json_data)
                        status["op_code_status"] = True
                    except Exception as e:
                        log.error(e)
                        status["op_code_status"] = False
                if op_code == "delete":
                    try:
                        log.info("in delete operation")
                        kinfo.delete()
                        key_info["opcode"]["delete"]["deleted"] = True
                        fp.add_data(json_data)
                        status["op_code_status"] = True
                    except Exception as e:
                        log.error(e)
                        status["op_code_status"] = False
                if op_code == "edit":

                    try:
                        put_contents_or_download = PutContentsFromFile(
                            kinfo, self.json_fname
                        )
                        log.info("in edit or modify file")
                        # download the file from s3
                        download_fname = key_name + ".downloaded"
                        downloaded_f = put_contents_or_download.get(download_fname)
                        print("-------------------------------%s" % downloaded_f)
                        if not downloaded_f["status"]:
                            raise Exception("download failed")
                        new_text = (
                            "downloded from s3 and uploading back with this message"
                        )
                        log.info("file downloaded, string to add: %s" % new_text)
                        f = open(download_fname, "a")
                        f.write(new_text)
                        f.close()
                        put_contents_or_download.put(download_fname)
                        log.info("file uploaded")
                        status["op_code_status"] = True
                    except Exception as e:
                        log.info("operation could not complete")
                        log.error(e)
                        status["op_code_status"] = False
                ks_op_status.append(status)
        [log.info(st) for st in ks_op_status]
        return ks_op_status
