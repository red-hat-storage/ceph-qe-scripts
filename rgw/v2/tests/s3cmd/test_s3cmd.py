"""
test_s3cmd - Test s3cmd operation on cluster

Usage: test_s3cmd.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_s3cmd.yaml
    test_multiple_delete_marker_check.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    Upload a file to bucket
    Delete uploaded object
    Delete bucket
    Verification of CEPH-83574806: multiple delete marker not created during object deletion in versioned bucket through s3cmd
"""


import argparse
import logging
import os
import socket
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3_swift import reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    write_bucket_io_info = BucketIoInfo()
    umgmt = UserMgmt()
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)

    # CEPH-83575477 - Verify s3cmd get: Bug 2174863 - [cee/sd][RGW] 's3cmd get' fails with EOF error for few objects
    if config.test_ops.get("s3cmd_get_objects", False):
        log.info(f"Verify 's3cmd get' or download of objects")
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = Auth(user_info[0], ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user_info[0]["user_id"], rand_no=bc
            )
            s3cmd_reusable.create_bucket(bucket_name)
            log.info(f"Bucket {bucket_name} created")
            s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
            object_count = config.objects_count // 2

            log.info(f"uploading some large objects to bucket {bucket_name}")
            utils.exec_shell_cmd(f"fallocate -l 20m obj20m")
            for mobj in range(object_count):
                cmd = f"{s3cmd_path} put obj20m s3://{bucket_name}/multipart-object-{mobj}"
                utils.exec_shell_cmd(cmd)

            log.info(f"uploading some small objects to bucket {bucket_name}")
            utils.exec_shell_cmd(f"fallocate -l 4k obj4k")
            for sobj in range(object_count):
                cmd = f"{s3cmd_path} put obj4k s3://{bucket_name}/small-object-{sobj}"
                utils.exec_shell_cmd(cmd)

            log.info(
                f"perfotm s3cmd get for all objects resides in bucket: {bucket_name}"
            )
            for sobj in range(object_count):
                cmd = f"{s3cmd_path} get s3://{bucket_name}/multipart-object-{sobj} {bucket_name}-multipart-object-{sobj}"
                multi_rc = utils.exec_shell_cmd(cmd)
                if multi_rc is False:
                    raise AssertionError(
                        f"Failed to download object multipart-object-{sobj} from bucket {bucket_name}: {multi_rc}"
                    )

                cmd = f"{s3cmd_path} get s3://{bucket_name}/small-object-{sobj} {bucket_name}-small-object-{sobj}"
                small_rc = utils.exec_shell_cmd(cmd)
                if small_rc is False:
                    raise AssertionError(
                        f"Failed to download object small-object-{sobj} from bucket {bucket_name}: {small_rc}"
                    )

        log.info("Remove downloaded objects from cluster")
        utils.exec_shell_cmd("rm -rf *-object-*")

    # Verifying CEPH-83574806
    if config.delete_marker_check:
        log.info(
            f"verification of TC: Not more than 1 delete marker is created for objects deleted many times using s3cmd"
        )
        user_info = resource_op.create_users(no_of_users_to_create=1)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = Auth(user_info[0], ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        bucket_name = utils.gen_bucket_name_from_userid(
            user_info[0]["user_id"], rand_no=1
        )
        bucket = reusable.create_bucket(bucket_name, rgw_conn, user_info[0])
        reusable.enable_versioning(bucket, rgw_conn, user_info[0], write_bucket_io_info)

        log.info("uploading current and non-current version of object object1")
        for i in range(2):
            uploaded_file_info = s3cmd_reusable.upload_file(
                bucket_name, "object1", test_data_path=TEST_DATA_PATH
            )
            log.info(
                f"Uploaded file {uploaded_file_info['name']} to bucket {bucket_name}"
            )

        cmd1 = f"radosgw-admin bucket stats --bucket {bucket.name} | grep num_objects | cut -d ':' -f 2 | cut -d ' ' -f 2"
        num_obj = utils.exec_shell_cmd(cmd1)
        if int(num_obj) != 2:
            raise AssertionError(f"object upload on version bucket failed!!")

        cmd2 = f"radosgw-admin bucket list --bucket {bucket.name}| grep delete-marker | wc -l"
        out1 = utils.exec_shell_cmd(cmd2)
        del_marker_count_before = out1.split("\n")[0]
        if int(del_marker_count_before) != 0:
            raise AssertionError(
                f"Delete marker should not be present! since object deletion is not performed yet"
            )

        log.info(f"deleting object {uploaded_file_info['name']} multiple times!! ")
        for i in range(5):
            s3cmd_reusable.delete_file(bucket_name, uploaded_file_info["name"])
            log.info(
                f"Deleted file {uploaded_file_info['name']} from bucket {bucket_name}"
            )

        cmd = f"radosgw-admin bucket list --bucket {bucket.name}| grep delete-marker | wc -l"
        out2 = utils.exec_shell_cmd(cmd)
        del_marker_count_after = out2.split("\n")[0]
        if int(del_marker_count_after) != 1:
            raise AssertionError(f"Found multiple delete marker!!")

    else:
        user_name = resource_op.create_users(no_of_users_to_create=1)[0]["user_id"]
        tenant = "tenant"
        tenant_user_info = umgmt.create_tenant_user(
            tenant_name=tenant, user_id=user_name, displayname=user_name
        )
        user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_name)

        s3_auth.do_auth(tenant_user_info, ip_and_port)

        bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)

        # Create a bucket
        s3cmd_reusable.create_bucket(bucket_name)
        log.info(f"Bucket {bucket_name} created")

        # Upload file to bucket
        uploaded_file_info = s3cmd_reusable.upload_file(
            bucket_name, test_data_path=TEST_DATA_PATH
        )
        uploaded_file = uploaded_file_info["name"]
        log.info(f"Uploaded file {uploaded_file} to bucket {bucket_name}")

        # Delete file from bucket
        s3cmd_reusable.delete_file(bucket_name, uploaded_file)
        log.info(f"Deleted file {uploaded_file} from bucket {bucket_name}")

        # Delete bucket
        s3cmd_reusable.delete_bucket(bucket_name)
        log.info(f"Bucket {bucket_name} deleted")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("rgw test using s3cmd")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW s3cmd Automation")
        parser.add_argument("-c", dest="config", help="RGW Test using s3cmd tool")
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
        config = resource_op.Config(yaml_file)
        config.read()
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
