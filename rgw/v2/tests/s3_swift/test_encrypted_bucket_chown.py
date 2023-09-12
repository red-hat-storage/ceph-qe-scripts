"""

test chown for a bucket encrypted with sse-s3
Usage: test_encrypted_bucket_chown.py -c <input_yaml>
<input_yaml>
    test_encrypted_bucket_chown.yaml

Operation:
    Create 2 users and create a bucket with user1 credentials
    enable per-bucket sse-s3 encryption with vault backend
    change the ownership of the bucket to user2 and then upload objects
    test objects uploaded are encrypted with AES256. 

"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import hashlib
import json
import logging
import random
import time
import traceback
import uuid

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import server_side_encryption_s3 as sse_s3
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # create user
    if config.user_count is 2:
        users_info = s3lib.create_users(config.user_count)
        # user1 is the owner
        user1, user2 = users_info[0], users_info[1]
        auth1 = Auth(user1, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        rgw_conn1 = auth1.do_auth()
        s3_client1 = auth1.do_auth_using_client()
        # user2 auth
        auth2 = Auth(user2, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        rgw_conn2 = auth2.do_auth()
        s3_client2 = auth2.do_auth_using_client()
        # get ceph version
        ceph_version_id, ceph_version_name = utils.get_ceph_version()

        objects_created_list = []
        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    user1["user_id"], rand_no=bc
                )
                log.info("creating bucket with name: %s" % bucket_name)
                bucket = reusable.create_bucket(bucket_name, rgw_conn1, user1)
                if config.test_ops.get("enable_version", False):
                    log.info("enable bucket version")
                    reusable.enable_versioning(
                        bucket, rgw_conn1, user1, write_bucket_io_info
                    )
                # enable per bucket encryption on the bucket
                log.info(
                    f"Encryption type is per-bucket, enable it on bucket : {bucket_name}"
                )
                encryption_method = config.encryption_keys
                sse_s3.put_bucket_encryption(s3_client1, bucket_name, encryption_method)
                # get bucket encryption
                log.info(f"get bucket encryption for bucket : {bucket_name}")
                sse_s3.get_bucket_encryption(s3_client1, bucket_name)

                # change owner of the bucket to user2
                log.info(
                    f"user info for user1 is {user1['user_id']} and user2 is {user2['user_id']}"
                )
                log.info(
                    f"change owner of the bucket {bucket_name} to {user2['user_id']}"
                )
                utils.exec_shell_cmd(
                    f"radosgw-admin bucket list --uid={user1['user_id']}"
                )
                new_uid = user2["user_id"]
                tenant = "default"
                bucket = bucket_name
                reusable.link_chown_nontenant_to_nontenant(new_uid, bucket)
                bucket = reusable.create_bucket(bucket_name, rgw_conn2, user2)
                # create objects
            if config.test_ops["create_object"] is True:
                # uploading data
                log.info("s3 objects to create: %s" % config.objects_count)
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
                    log.info("s3 object name: %s" % s3_object_name)
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info("s3 object path: %s" % s3_object_path)

                    if config.test_ops.get("upload_type") == "multipart":
                        log.info("upload type: multipart")
                        reusable.upload_mutipart_object(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            user2,
                        )
                    else:
                        log.info("upload type: normal")
                        reusable.upload_object(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            user2,
                        )

                    # test the object uploaded is encrypted with AES256
                    sse_s3.get_object_encryption(
                        s3_client2, bucket_name, s3_object_name
                    )
    else:
        raise TestExecError("Need to have atleast 2 users to bucket chown")
    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("test change owner for a sse-s3 encrypted bucket")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        rgw_service = RGWService()
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW- test chown of encrypted buckets does not affect IOs"
        )
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )
        args = parser.parse_args()
        yaml_file = args.config
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        ceph_conf = CephConfOp(ssh_con)
        config.read(ssh_con)
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
