"""
test_gc_with_resharding.py - Test resharding and gc operations on bucket
Usage: test_gc_with_resharding.py -c <input_yaml>
<input_yaml>
    Note: any one of these yamls can be used
    test_gc_resharding_bucket.yaml
    test_gc_resharding_versioned_bucket.yaml
Operation:
    Create user
	set gc and objects per shard configuration
    Perform IOs in specific bucket
	list the objects
	delete the objects
	delete the bucket
"""

# test RGW gc with bucket resharding
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()

TEST_DATA_PATH = None


def test_exec(config, ssh_con):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    objects_created_list = []

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    if config.test_ops.get("encryption_algorithm", None) is not None:
        log.info("encryption enabled, making ceph config changes")
        ceph_conf.set_to_ceph_conf(
            "global", ConfigOpts.rgw_crypt_require_ssl, "false", ssh_con
        )
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted")

    # making changes to max_objects_per_shard and rgw_gc_obj_min_wait to ceph.conf
    log.info("making changes to ceph.conf")
    log.info(
        f"rgw_max_objs_per_shard parameter set to {str(config.max_objects_per_shard)}"
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_max_objs_per_shard,
        str(config.max_objects_per_shard),
        ssh_con,
    )
    ceph_conf.set_to_ceph_conf(
        "global", ConfigOpts.rgw_dynamic_resharding, "True", ssh_con
    )
    log.info(
        f"rgw gc obj min wait configuration parameter set to {str(config.rgw_gc_obj_min_wait)}"
    )
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_gc_obj_min_wait,
        str(config.rgw_gc_obj_min_wait),
        ssh_con,
    )
    sleep_time = 10
    log.info(f"Restarting RGW service and waiting for {sleep_time} seconds")
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(sleep_time)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")

    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        if config.use_aws4 is True:
            rgw_conn = auth.do_auth(**{"signature_version": "s3v4"})
        else:
            rgw_conn = auth.do_auth()
        objects_created_list = []
        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                log.info(f"creating {str(bc)} bucket")
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                log.info("creating bucket with name: %s" % bucket_name_to_create)
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user
                )
                if config.test_ops.get("enable_version", False):
                    log.info("enable bucket version")
                    reusable.enable_versioning(
                        bucket, rgw_conn, each_user, write_bucket_io_info
                    )
                if config.test_ops["create_object"] is True:
                    log.info("s3 objects to create: %s" % config.objects_count)
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                        log.info("s3 object name: %s" % s3_object_name)
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info("s3 object path: %s" % s3_object_path)
                        if config.test_ops.get("enable_version", False):
                            log.info("upload versioned objects")
                            reusable.upload_version_object(
                                config,
                                each_user,
                                rgw_conn,
                                s3_object_name,
                                config.obj_size,
                                bucket,
                                TEST_DATA_PATH,
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
                        objects_created_list.append((s3_object_name, s3_object_path))
                # deleting the local file created after upload
                if config.local_file_delete is True:
                    log.info("deleting local file created after the upload")
                    utils.exec_shell_cmd("rm -rf %s" % s3_object_path)

                # listing the objects
                if config.test_ops.get("list_objects", False):
                    if config.test_ops.get("enable_version", False):
                        for name, path in objects_created_list:
                            reusable.list_versioned_objects(
                                bucket, name, path, rgw_conn
                            )
                    else:
                        reusable.list_objects(bucket)

                if config.test_ops.get("delete_bucket_object", False):
                    if config.test_ops.get("enable_version", False):
                        for name, path in objects_created_list:
                            print("name, path", name, path)
                            versions = bucket.object_versions.filter(Prefix=name)
                            log.info("deleting s3_obj keys and its versions")
                            s3_obj = s3lib.resource_op(
                                {
                                    "obj": rgw_conn,
                                    "resource": "Object",
                                    "args": [bucket.name, name],
                                }
                            )
                            log.info("deleting versions for s3 obj: %s" % name)
                            for version in versions:
                                log.info(
                                    "trying to delete obj version: %s"
                                    % version.version_id
                                )
                                del_obj_version = s3lib.resource_op(
                                    {
                                        "obj": s3_obj,
                                        "resource": "delete",
                                        "kwargs": dict(VersionId=version.version_id),
                                    }
                                )
                                log.info("response:\n%s" % del_obj_version)
                                if del_obj_version is not None:
                                    response = HttpResponseParser(del_obj_version)
                                    if response.status_code == 204:
                                        log.info("version deleted ")
                                        reusable.delete_version_object(
                                            bucket,
                                            version.version_id,
                                            path,
                                            rgw_conn,
                                            each_user,
                                        )
                                    else:
                                        raise TestExecError("version  deletion failed")
                                else:
                                    raise TestExecError("version deletion failed")
                    else:
                        reusable.delete_objects(bucket)
                    log.info(f"deleting the bucket {bucket_name_to_create}")
                    reusable.delete_bucket(bucket)

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

    # remove the user
    reusable.remove_user(each_user)


if __name__ == "__main__":

    test_info = AddTestInfo("RGW gc with dynamic resharding test")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 Automation")
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
