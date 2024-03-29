"""
test_s3cmd - Test s3cmd operation on cluster

Usage: test_s3cmd.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_s3cmd.yaml
    test_multiple_delete_marker_check.yaml
    configs/test_disable_and_enable_dynamic_resharding_with_10k_bucket.yaml
    configs/test_disable_and_enable_dynamic_resharding_with_1k_bucket.yaml
    configs/test_large_object_download_with_s3cmd.yaml
    configs/test_large_object_upload_with_s3cmd.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    Upload a file to bucket
    Delete uploaded object
    Delete bucket
    Verification of CEPH-83574806: multiple delete marker not created during object deletion in versioned bucket through s3cmd
"""


import argparse
import datetime
import json
import logging
import os
import socket
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
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
    s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
    if config.haproxy:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        port = 5000
        ip_and_port = f"{ip}:{port}"

    # CEPH-83575477 - Verify s3cmd get: Bug 2174863 - [cee/sd][RGW] 's3cmd get' fails with EOF error for few objects
    if config.test_ops.get("s3cmd_get_objects", False):
        log.info(f"Verify 's3cmd get' or download of objects")
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = Auth(user_info[0], ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        rgw_conn = auth.do_auth()
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user_info[0]["user_id"], rand_no=bc
            )
            s3cmd_reusable.create_bucket(bucket_name)
            log.info(f"Bucket {bucket_name} created")
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

    # verifying delete lifecycle via s3cmd
    elif config.deletelc:
        log.info(f"delete LC rule from a bucket via s3cmd")
        log.info(
            f"verification of TC: Deleting lifecycle rule via s3cmd should not throw any error"
        )
        user_info = resource_op.create_users(no_of_users_to_create=1)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = Auth(user_info[0], ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()
        bucket_name = utils.gen_bucket_name_from_userid(
            user_info[0]["user_id"], rand_no=1
        )
        bucket = reusable.create_bucket(bucket_name, rgw_conn, user_info[0])

        life_cycle_rule = {"Rules": config.lifecycle_conf}
        reusable.put_bucket_lifecycle(
            bucket,
            rgw_conn,
            rgw_conn2,
            life_cycle_rule,
        )
        cmd = f"{s3cmd_path} dellifecycle s3://{bucket_name}"
        rc = utils.exec_shell_cmd(cmd)
        log.info(rc)
        exit_status = os.system("echo $?")
        if exit_status:
            raise AssertionError(
                f"Deleting LC config via s3cmd for a bucket {bucket_name} Failed"
            )
        else:
            log.info(f"Deleting life cycle rule via s3cmd is successful!")

    elif config.test_ops.get("disable_and_enable_dynamic_reshard", False):
        log.info("making changes to ceph.conf")
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_max_objs_per_shard,
            str(config.max_objects_per_shard),
            ssh_con,
        )

        ceph_conf.set_to_ceph_conf(
            "global", ConfigOpts.rgw_dynamic_resharding, "False", ssh_con
        )
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_max_dynamic_shards,
            str(config.max_rgw_dynamic_shards),
            ssh_con,
        )

        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_reshard_thread_interval,
            str(config.rgw_reshard_thread_interval),
            ssh_con,
        )

        log.info("trying to restart rgw services")
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted sucessfully")

        log.info(
            f"Create buckets {config.bucket_count} and upload objects {config.objects_count}"
        )
        user_info = resource_op.create_users(no_of_users_to_create=1)
        if config.bucket_count > 1000:
            cmd = f"radosgw-admin user modify --uid={user_info[0]['user_id']} --max-buckets {config.bucket_count}"
            utils.exec_shell_cmd(cmd)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = Auth(user_info[0], ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        rgw_conn = auth.do_auth()
        buckets = []

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user_info[0]["user_id"], rand_no=bc
            )
            if bc == 0:
                bucket_prefix = bucket_name[:-2]
            s3cmd_reusable.create_bucket(bucket_name)
            log.info(f"Bucket {bucket_name} created")
            buckets.append(bucket_name)
            log.info(
                f"uploading {config.objects_count} objects to bucket {bucket_name}"
            )
            utils.exec_shell_cmd(f"fallocate -l 1k obj1k")

            for obj in range(config.objects_count):
                cmd = f"{s3cmd_path} put obj1k s3://{bucket_name}/object-{obj}"
                utils.exec_shell_cmd(cmd)

        for bkt in buckets:
            log.info("Expecting num shards of buckets to be a default value")
            json_doc = json.loads(
                utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bkt}")
            )
            num_objects = json_doc["usage"]["rgw.main"]["num_objects"]
            if json_doc["num_shards"] != 11:
                raise AssertionError(
                    f"disabling dynamic Re-sharding FAILED!, found {json_doc['num_shards']} shards expected 11"
                )

        log.info(
            "Verify resharding list should not list the buckets as dynamic reshard is disabled"
        )
        reshard_list_op = json.loads(utils.exec_shell_cmd("radosgw-admin reshard list"))
        if reshard_list_op:
            reshard_list = []
            for reshard in reshard_list_op:
                if reshard["bucket_name"].startswith(bucket_prefix):
                    reshard_list.append(reshard["bucket_name"])
            if len(reshard_list) != 0:
                raise TestExecError(
                    f"Expected reshard list to be empty as dynamic reshard is deisabled {reshard_list}"
                )

        log.info("Set rgw_dynamic_resharding to True")
        ceph_conf.set_to_ceph_conf(
            "global", ConfigOpts.rgw_dynamic_resharding, "True", ssh_con
        )

        log.info("trying to restart rgw services")
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted sucessfully")

        time_now = datetime.datetime.now()
        log.info(f"Upload few more objects to the buckets at {time_now}")
        for bkt in buckets:
            num_obj = config.max_objects_per_shard * 2
            log.info(f"objects to create: {num_obj}")
            for oc in range(num_obj):
                cmd = f"{s3cmd_path} put obj1k s3://{bkt}/new-object-{oc}"
                utils.exec_shell_cmd(cmd)

        time.sleep(config.rgw_reshard_thread_interval)
        for bkt in buckets:
            log.info(
                "Expecting num shards to be a greater than 11 as rgw_dynamic_resharding enabled"
            )
            json_doc = json.loads(
                utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bkt}")
            )
            num_objects = json_doc["usage"]["rgw.main"]["num_objects"]
            if json_doc["num_shards"] == 11:
                raise AssertionError(
                    f"Enabling dynamic Re-sharding FAILED !, found {json_doc['num_shards']} shards expected > 11"
                )

        time_curr = datetime.datetime.now()
        log.info(
            f"sucessfully completed dynamic resharding it took {time_now} to {time_curr}"
        )

        log.info("remove user created")
        reusable.remove_user(user_info[0])

    elif config.test_ops.get("user_name", False):
        log.info("Verify many large objects upload or download")
        user_name = config.test_ops["user_name"]
        if config.test_ops.get("object_upload", False):
            log.info(f"create user {user_name}")
            cmd = f"radosgw-admin user create --uid={user_name} --display-name={user_name}"
            out = json.loads(utils.exec_shell_cmd(cmd))
            if out is False:
                raise TestExecError(f"RGW User with name {user_name} creation failed")

        if config.test_ops.get("object_download", False):
            time.sleep(60)
            log.info(f"get user info{user_name}")
            out = json.loads(
                utils.exec_shell_cmd(f"radosgw-admin user info --uid={user_name}")
            )
            if out is False:
                raise TestExecError(f"Get rgw User with name {user_name} failed")

        user_info = {
            "user_id": out["user_id"],
            "display_name": out["display_name"],
            "access_key": out["keys"][0]["access_key"],
            "secret_key": out["keys"][0]["secret_key"],
        }
        s3_auth.do_auth(user_info, ip_and_port)
        auth = Auth(user_info, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        rgw_conn = auth.do_auth()
        for bc in range(config.bucket_count):
            bucket_name = config.test_ops["bucket_prefix"] + str(bc)
            if config.test_ops.get("object_upload", False):
                s3cmd_reusable.create_bucket(bucket_name)
                log.info(f"Bucket {bucket_name} created")
                log.info(f"uploading some large objects to bucket {bucket_name}")
                utils.exec_shell_cmd(f"fallocate -l 20m obj20m")
                for mobj in range(config.objects_count):
                    cmd = f"{s3cmd_path} put obj20m s3://{bucket_name}/multipart-object-{mobj}"
                    utils.exec_shell_cmd(cmd)

            if config.test_ops.get("object_download", False):
                log.info(
                    f"perfotm s3cmd get for all objects resides in bucket: {bucket_name}"
                )
                for mobj in range(config.objects_count):
                    time.sleep(3)
                    cmd = f"{s3cmd_path} get s3://{bucket_name}/multipart-object-{mobj} {bucket_name}-multipart-object-{mobj}"
                    multi_rc = utils.exec_shell_cmd(cmd)
                    if multi_rc is False:
                        raise AssertionError(
                            f"Failed to download object multipart-object-{mobj} from bucket {bucket_name}: {multi_rc}"
                        )

        if config.test_ops.get("object_download", False):
            log.info("Remove downloaded objects from cluster")
            utils.exec_shell_cmd("rm -rf *-object-*")

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
        object_count = config.objects_count

        if config.full_sync_test:
            utils.exec_shell_cmd(f"fallocate -l 4K obj4K")
            for obj in range(object_count):
                cmd = f"{s3cmd_path} put obj4K s3://{bucket_name}/object-{obj}"
                utils.exec_shell_cmd(cmd)
            s3cmd_reusable.test_full_sync_at_archive(bucket_name, config)

        else:
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
