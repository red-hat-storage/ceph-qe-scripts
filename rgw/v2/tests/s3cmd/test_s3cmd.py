"""
test_s3cmd - Test s3cmd operation on cluster

Usage: test_s3cmd.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_s3cmd.yaml
    test_multiple_delete_marker_check.yaml
    configs/test_disable_and_enable_dynamic_resharding_with_10k_bucket.yaml
    configs/test_disable_and_enable_dynamic_resharding_with_1k_bucket.yaml
    test_multipart_upload_with_failed_parts_using_s3cmd_and_boto3.yaml
    multisite_configs/test_sync_error_list.yaml
    configs/test_setting_public_acl.yaml
    configs/test_create_bucket_for_existing_bucket.yaml
    configs/test_olh_get.yaml

Operation:
    Create an user
    Create a bucket with user credentials
    Upload a file to bucket
    Delete uploaded object
    Delete bucket
    Verification of CEPH-83574806: multiple delete marker not created during object deletion in versioned bucket through s3cmd
    Verify setting public acl to the bucket doesn't result in error
    Verfy olh get on versioned object doesn't throw any error
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

    rgw_service_port = reusable.get_rgw_service_port()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con)
    if config.haproxy and rgw_service_port != 443:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        port = 5000
        ip_and_port = f"{ip}:{port}"

    # CEPH-83575477 - Verify s3cmd get: Bug 2174863 - [cee/sd][RGW] 's3cmd get' fails with EOF error for few objects
    if config.test_ops.get("s3cmd_get_objects", False):
        log.info(f"Verify 's3cmd get' or download of objects")
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = reusable.get_auth(user_info[0], ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user_info[0]["user_id"], rand_no=bc
            )
            s3cmd_reusable.create_bucket(bucket_name, ip_and_port)
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
        auth = reusable.get_auth(user_info[0], ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()
        bucket_name = utils.gen_bucket_name_from_userid(
            user_info[0]["user_id"], rand_no=1
        )
        bucket = reusable.create_bucket(
            bucket_name, rgw_conn, user_info[0], ip_and_port
        )
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
        auth = reusable.get_auth(user_info[0], ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()
        bucket_name = utils.gen_bucket_name_from_userid(
            user_info[0]["user_id"], rand_no=1
        )
        bucket = reusable.create_bucket(
            bucket_name, rgw_conn, user_info[0], ip_and_port
        )

        life_cycle_rule = {"Rules": config.lifecycle_conf}
        reusable.put_bucket_lifecycle(
            bucket,
            rgw_conn,
            rgw_conn2,
            life_cycle_rule,
        )
        cmd = f"/home/cephuser/venv/bin/s3cmd dellifecycle s3://{bucket_name}"
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
        auth = reusable.get_auth(user_info[0], ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()
        s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
        buckets = []

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user_info[0]["user_id"], rand_no=bc
            )
            if bc == 0:
                bucket_prefix = bucket_name[:-2]
            s3cmd_reusable.create_bucket(bucket_name, ip_and_port)
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

    # CEPH-83589550 - Bug 2262650 - [GSS]Missing Objects in RGW S3 bucket while making GET request - 404 not found error
    elif config.test_ops.get("test_multipart_upload_with_failed_upload_parts", False):
        log.info("Verify multipart upload with failed upload parts in parallel")
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = reusable.get_auth(user_info[0], ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth_using_client()
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user_info[0]["user_id"], rand_no=bc
            )
            s3cmd_reusable.create_bucket(bucket_name, ip_and_port)
            log.info(f"Bucket {bucket_name} created")
            s3cmd_path = "/home/cephuser/venv/bin/s3cmd"

            # removing local files if present already
            utils.exec_shell_cmd(
                "rm -rf /tmp/obj1 && rm -rf /tmp/obj2 && rm -rf /tmp/obj20MB && rm -rf /tmp/obj30MB"
            )
            # create local parts with 8MB and 100MB
            utils.exec_shell_cmd("fallocate -l 8388608 /tmp/obj1")
            utils.exec_shell_cmd("fallocate -l 104857600 /tmp/obj2")
            # create local temp files with 20MB and 30MB for failed part2 uploads
            utils.exec_shell_cmd("fallocate -l 20971520 /tmp/obj20MB")
            utils.exec_shell_cmd("fallocate -l 31457280 /tmp/obj30MB")

            for oc in range(config.objects_count):
                log.info(
                    f"------------------------iteration-{oc}------------------------"
                )
                s3_object_name = f"Key_{bucket_name}"
                reusable.test_multipart_upload_failed_parts(
                    rgw_conn,
                    s3_object_name,
                    bucket_name,
                    "/tmp/obj1",
                    "/tmp/obj2",
                )
                cmd = f"{s3cmd_path} get s3://{bucket_name}/{s3_object_name} /tmp/ --force && {s3cmd_path} rm s3://{bucket_name}/{s3_object_name}"
                out = utils.exec_shell_cmd(cmd)
                if out is False:
                    raise Exception("Multipart object download failed")

            # removing local downloaded file
            utils.exec_shell_cmd(f"rm -rf /tmp/{s3_object_name}")

            # check if gc process + bucket check fix workaround removes failed parts on 5.3
            # BZ: https://bugzilla.redhat.com/show_bug.cgi?id=2266680
            utils.exec_shell_cmd(
                f"radosgw-admin gc process --bucket={bucket_name} --include-all"
            )
            utils.exec_shell_cmd(
                f"radosgw-admin bucket check --fix --bucket={bucket_name} &> bc.log"
            )
            log.info("sleeping for 10 seconds")
            time.sleep(10)
            out = utils.exec_shell_cmd(
                f"radosgw-admin bucket list --bucket={bucket_name}"
            )
            bkt_list_json = json.loads(out)
            if len(bkt_list_json) != 0:
                raise Exception(
                    "failed upload parts are not deleted and still listing in bucket list"
                )
            else:
                log.info("bucket list is empty as expected")

    elif config.test_ops.get("set_public_acl", False):
        log.info("Verify setting public acl to the bucket doesn't result in error")
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = Auth(user_info[0], ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        rgw_conn = auth.do_auth()
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user_info[0]["user_id"], rand_no=bc
            )
            s3cmd_reusable.create_bucket(bucket_name, ip_and_port)
            log.info(f"Bucket {bucket_name} created")
            s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
            cmd = f"{s3cmd_path} setacl --acl-public s3://{bucket_name}"
            err = utils.exec_shell_cmd(cmd, return_err=True)
            if "ERROR:" in err:
                raise AssertionError(
                    f"setting public acl for bucket {bucket_name} failed with err {err}"
                )

    elif config.test_ops.get("is_not_master_zone", False):
        log.info("This is not the master zone. Skipping tenant user creation.")

    elif config.test_ops.get("sync_error_list", False) is True:
        is_multisite = utils.is_cluster_multisite()
        if is_multisite:
            check_sync_status = utils.exec_shell_cmd("radosgw-admin sync status")
            if not check_sync_status:
                raise AssertionError("Sync status output is empty")
            log.info(f"sync status op is: {check_sync_status}")
            if "failed" in check_sync_status or "ERROR" in check_sync_status:
                log.info("sync is in error state")
            if "behind" in check_sync_status or "recovering" in check_sync_status:
                log.info("sync is in progress")
            log.info("check cluster for sync error list")
            sync_error_list = utils.exec_shell_cmd("sudo radosgw-admin sync error list")
            sync_error_json = json.loads(sync_error_list)
            error_exist = False
            for ent in sync_error_json:
                if len(ent["entries"]) != 0:
                    error_exist = True
                    break
            if error_exist:
                log.error(
                    f"To trim error manullay try running radosgw-admin sync error trim, since error could be an issue. So trim is not recommanded"
                )
                log.error(
                    f"Post clearing sync error trim, run sync error list to verify errors are trimmed"
                )
                raise AssertionError(f"Sync error data exist in cluster")
            else:
                log.info(f"Sync error list is empty")

    elif config.test_ops.get("create_existing_bucket", False):
        log.info(
            "Verify with and without rgw_bucket_eexist_override set bucket creation"
        )
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = reusable.get_auth(user_info[0], ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth_using_client()
        bucket_name = utils.gen_bucket_name_from_userid(
            user_info[0]["user_id"], rand_no=0
        )
        s3cmd_reusable.create_bucket(bucket_name, ip_and_port)
        log.info(f"Bucket {bucket_name} created")
        log.info(f"list bucket under user {user_info[0]['user_id']}")
        resp = utils.exec_shell_cmd("/home/cephuser/venv/bin/s3cmd ls")
        log.info(f"bucket list s3mcd ls data {resp}")
        log.info(f"Create bucket {bucket_name} which is alreday exist")
        s3cmd_reusable.create_bucket(bucket_name, ip_and_port)
        log.info("BucketAlreadyExists error not seen as expected")
        log.info("set config rgw_bucket_eexist_override for rgw daemon service")
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_bucket_eexist_override,
            "True",
            ssh_con,
        )
        reusable.restart_and_wait_until_daemons_up(ssh_con)

        log.info(f"Create existing bucket {bucket_name} post enabling config")
        try:
            resp = utils.exec_shell_cmd(
                f"/home/cephuser/venv/bin/s3cmd mb s3://{bucket_name}", return_err=True
            )
        except Exception as e:
            log.info(f"cmd execution failed as expected {resp}")
        log.info(f"cmd execution failed as expected {resp}")
        if "409" not in resp:
            raise TestExecError(
                "with config, expected error code 409 for creation ofexiting bucket for same user"
            )
        if "BucketAlreadyExists" not in resp:
            raise TestExecError(
                "with config, expected error msg BucketAlreadyExists for creation ofexiting bucket for same user"
            )
        log.info("Error seen as expected for creting existing bucket from same owner")
        log.info(
            "reset config rgw_bucket_eexist_override to default for rgw daemon service"
        )
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_bucket_eexist_override,
            "False",
            ssh_con,
        )
        reusable.restart_and_wait_until_daemons_up(ssh_con)

    elif config.test_ops.get("test_olh_get", False):
        log.info("Verifying decode olh info while performing radosgw-admin olh get")
        s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)
        s3_auth.do_auth(user_info[0], ip_and_port)
        auth = reusable.get_auth(user_info[0], ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                user_info[0]["user_id"], rand_no=bc
            )
            # Create bucket
            s3cmd_reusable.create_bucket(bucket_name, ip_and_port)
            log.info(f"Bucket {bucket_name} created")

            # Enable versioning
            s3cmd_reusable.enable_versioning_for_a_bucket(
                user_info[0], bucket_name, ip_and_port, ssl=None
            )

            object_name = "obj5m"
            utils.exec_shell_cmd(f"fallocate -l 5m {object_name}")
            log.info(f"Now Upload the objects to the bucket {bucket_name}")

            log.info(
                f"Now Upload 2 versions of the object: {object_name} to the bucket:{bucket_name}"
            )
            for i in range(2):
                cmd = f"{s3cmd_path} put {object_name} s3://{bucket_name}/{object_name}"
                out = utils.exec_shell_cmd(cmd)
            stat = json.loads(
                utils.exec_shell_cmd(
                    f"radosgw-admin bucket stats --bucket {bucket_name}"
                )
            )
            if int(stat["usage"]["rgw.main"]["num_objects"]) != 2:
                raise AssertionError(f"Objects upload is not consisitent")

            olh_out = utils.exec_shell_cmd(
                f"radosgw-admin olh get --bucket {bucket_name} --object {object_name}",
                return_err=True,
            )

            if "ERROR: failed reading olh:" in str(olh_out):
                raise AssertionError(f"olh decode failed for object {object_name}")

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
        s3cmd_reusable.create_bucket(bucket_name, ip_and_port)
        log.info(f"Bucket {bucket_name} created")
        object_count = config.objects_count

        if config.full_sync_test:
            s3cmd_path = "/home/cephuser/venv/bin/s3cmd"
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
