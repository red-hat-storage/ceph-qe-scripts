"""
test_s3_copy_encryption.py - using boto

Usage: test_s3_copy_encryption.py -c <input_yaml>
<input_yaml>
    test_s3_copy_compression_encryption.yaml(implemented)

Operation:
    s1: On a multisite envitonment, create an rgw user
    s2: ensure the default encryption and zlib compression are enabled on all the sites
    s3: If s3-copy-object is true, create 2 buckets and 
    s4: upload object from one bucket to another bucket.
        
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import AddUserInfo, BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_config_set = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        rgw_conn = auth.do_auth()

        # authenticate with s3 client
        s3_client = auth.do_auth_using_client()

        # get ceph version
        ceph_version_id, ceph_version_name = utils.get_ceph_version()
        is_multisite = utils.is_cluster_multisite()
        if is_multisite:
            objects_created_list = []
            buckets_created = []
            if config.test_ops["create_bucket"] is True:
                log.info("no of buckets to create: %s" % config.bucket_count)
                for bc in range(config.bucket_count):
                    bucket_name = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=bc
                    )
                    log.info("creating bucket with name: %s" % bucket_name)
                    bucket = reusable.create_bucket(bucket_name, rgw_conn, each_user)
                    buckets_created.append(bucket)

                if config.test_ops["create_object"] is True:
                    for bucket in buckets_created:
                        # uploading data
                        log.info("s3 objects to create: %s" % config.objects_count)
                        for oc, size in list(config.mapped_sizes.items()):
                            config.obj_size = size
                            s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                            log.info("s3 object name: %s" % s3_object_name)
                            s3_object_path = os.path.join(
                                TEST_DATA_PATH, s3_object_name
                            )
                            log.info("s3 object path: %s" % s3_object_path)
                            log.info(f"print the {each_user}")
                            if config.test_ops.get("upload_type") == "multipart":
                                log.info("upload type: multipart")
                                reusable.upload_mutipart_object(
                                    s3_object_name,
                                    bucket,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                )
                            else:
                                log.info("upload type: normal")
                                reusable.upload_object(
                                    s3_object_name,
                                    bucket,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                )

    if config.test_ops["server_side_copy"] is True:
        bucket1, bucket2 = buckets_created

        # copy object1 from bucket1 to bucket2 with the same name as in bucket1
        log.info("copying first object from bucket1 to bucket2")
        all_keys_in_buck1 = []
        for obj in bucket1.objects.all():
            all_keys_in_buck1.append(obj.key)
        copy_objects = []
        for object_name in all_keys_in_buck1:
            copy_object_name = object_name + "_copied_obj"
            copy_objects.append(copy_object_name)
            log.info(f"copy object name: {copy_object_name}")
            s3_client.copy_object(
                Bucket=bucket2.name,
                Key=copy_object_name,
                CopySource={
                    "Bucket": bucket1.name,
                    "Key": object_name,
                },
            )

        # list the objects in bucket2
        log.info("listing all objects im bucket2 after copy")
        all_bucket2_objs = []
        for obj in bucket2.objects.all():
            log.info(obj.key)
            all_bucket2_objs.append(obj.key)

        # check for object existence in bucket2
        for copy_object_name in copy_objects:
            if copy_object_name in all_bucket2_objs:
                log.info("server side copy successful")
            else:
                raise TestExecError("server side copy operation was not successful")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("Server Side Copy Operation")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="RGW s3 copy with compression-encryption enabled"
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
