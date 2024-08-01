"""
# test list bucket multipart uploads

usage : test_list_all_multipart_uploads.py -c <input_yaml>

<input_yaml>
    Note: any one of these yamls can be used
    configs/test_list_all_multipart_uploads.yaml
    configs/test_listbucketversion_with_bucketpolicy_for_tenant_user.yaml
    configs/test_bucketlocation_using_bucketpolicy_with_tenantuser.yaml
    configs/test_bucket_put_get_lifecycle_configuration_with_tenant_users.yaml
    configs/get_object_and_its_versions_tenat_user.yaml
    configs/test_put_get_bucket_notification_with_tenant_same_and_different_user.yaml
    configs/test_put_bucket_website_with_tenant_same_and_different_user.yaml
    configs/test_get_bucket_website_with_tenant_same_and_different_user.yaml

Operation:
- Create users in the same tenant, user1 and user2 (if required user3)
- Create buckets user1
- Using user1 credentials, set bucket policy for user2(if required user3) to access objects of
  bucket1 created with user1
- upload objects to bucket1.
- Verify
    - user2(user3 if created and given access) can access the objects of bucket1
    - Verify permission denied for user2 to list objects in bucket2
    - Verify get bucket location from all users of same tenant


"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import random
import string
import time
import traceback
import uuid

import v2.lib.resource_op as s3lib
import v2.lib.s3.bucket_policy as s3_bucket_policy
import v2.utils.utils as utils
from botocore.exceptions import ClientError
from botocore.handlers import validate_bucket_name
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import bucket_notification as notification
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()


TEST_DATA_PATH = None


def get_svc_time(ssh_con=None):
    cmd = "pidof radosgw"
    if ssh_con:
        _, pid, _ = ssh_con.exec_command(cmd)
        pid = pid.readline()
        log.info(pid)
    else:
        pid = utils.exec_shell_cmd(cmd)
    pid = pid.strip()
    cmd = "ps -p " + pid + " -o etimes"
    if ssh_con:
        _, srv_time, _ = ssh_con.exec_command(cmd)
        _ = srv_time.readline()
        srv_time = srv_time.readline()
        srv_time = srv_time.replace("\n", "")
        srv_time = srv_time.replace(" ", "")
        srv_time = int(srv_time)
    else:
        srv_time = utils.exec_shell_cmd(cmd)
        srv_time = srv_time.replace("\n", "")
        srv_time = srv_time.replace(" ", "")
        srv_time = int(srv_time[7:])
    return srv_time


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    if config.rgw_enable_static_website:
        ceph_conf = CephConfOp(ssh_con)
        rgw_service = RGWService()
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_enable_static_website,
            str(config.rgw_enable_static_website),
            ssh_con,
        )
        log.info("trying to restart services")
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted")

    additional_aws_principle = []
    location = None
    if config.test_ops.get("list_bucket_multipart_uploads", False):
        srv_time_pre_op = get_svc_time(ssh_con)
        config.test_ops["users_count"] = 2
        action_list = ["ListBucketMultiPartUploads"]

    # create user
    tenant1 = "tenant_" + random.choice(string.ascii_letters)
    tenant1_user_info = s3lib.create_tenant_users(
        tenant_name=tenant1, no_of_users_to_create=config.test_ops["users_count"]
    )

    if not config.test_ops.get("list_bucket_multipart_uploads", False):
        tenant1_user3_info = tenant1_user_info[2]
        tenant1_user3_auth = Auth(tenant1_user3_info, ssh_con, ssl=config.ssl)
        rgw_tenant1_user3_c = tenant1_user3_auth.do_auth_using_client()
        if config.test_ops.get("list_bucket_versions", False):
            action_list = ["ListBucketVersions"]
        elif config.test_ops.get("get_bucket_location", False):
            action_list = ["GetBucketLocation"]
        elif config.test_ops.get("lifecycle_configuration", False):
            action_list = ["PutLifecycleConfiguration", "GetLifecycleConfiguration"]
        elif config.test_ops.get("get_obj_and_its_versions", False):
            action_list = ["GetObject", "GetObjectVersion"]
        elif config.test_ops.get("put_get_bucket_notification", False):
            action_list = ["GetBucketNotification", "PutBucketNotification"]
        if config.test_ops.get("put_bucket_website", False):
            action_list = ["PutBucketWebsite"]
        if config.test_ops.get("get_bucket_website", False):
            action_list = ["GetBucketWebsite"]
        additional_aws_principle = [
            f"arn:aws:iam::{tenant1}:user/{tenant1_user3_info['user_id']}"
        ]
        if config.test_ops.get("new_tenant_user", False):
            # create user
            tenant2 = "tenant_" + random.choice(string.ascii_letters)
            tenant2_user_info = s3lib.create_tenant_users(
                tenant_name=tenant2,
                no_of_users_to_create=config.test_ops["users_count"],
            )
            tenant2_user1_auth = Auth(tenant2_user_info[0], ssh_con, ssl=config.ssl)
            rgw_tenant2_user1_c = tenant2_user1_auth.do_auth_using_client()
            tenant2_user2_auth = Auth(tenant2_user_info[1], ssh_con, ssl=config.ssl)
            rgw_tenant2_user2_c = tenant2_user2_auth.do_auth_using_client()
            tenant2_user3_auth = Auth(tenant2_user_info[2], ssh_con, ssl=config.ssl)
            rgw_tenant2_user3_c = tenant2_user3_auth.do_auth_using_client()
            additional_aws_principle += [
                f"arn:aws:iam::{tenant2}:user/{tenant2_user_info[0]['user_id']}",
                f"arn:aws:iam::{tenant2}:user/{tenant2_user_info[1]['user_id']}",
                f"arn:aws:iam::{tenant2}:user/{tenant2_user_info[2]['user_id']}",
            ]

    tenant1_user1_info = tenant1_user_info[0]
    tenant1_user2_info = tenant1_user_info[1]

    tenant1_user1_auth = Auth(tenant1_user1_info, ssh_con, ssl=config.ssl)
    tenant1_user2_auth = Auth(tenant1_user2_info, ssh_con, ssl=config.ssl)

    rgw_tenant1_user1 = tenant1_user1_auth.do_auth()
    rgw_tenant1_user1_c = tenant1_user1_auth.do_auth_using_client()
    rgw_tenant1_user2_c = tenant1_user2_auth.do_auth_using_client()

    if config.test_ops.get("create_bucket", False):
        log.info(f"no of buckets to create: {config.bucket_count}")
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                tenant1_user1_info["user_id"], rand_no=bc
            )
            bucket = reusable.create_bucket(
                bucket_name, rgw_tenant1_user1, tenant1_user1_info, location=location
            )
            if config.test_ops.get("enable_version", False):
                log.info(f"bucket versionig test on bucket: {bucket.name}")
                reusable.enable_versioning(
                    bucket, rgw_tenant1_user1, tenant1_user1_info, write_bucket_io_info
                )

            # create topic with endpoint
            if config.test_ops.get("create_topic", False):
                # authenticate sns client.
                rgw_sns_conn = tenant1_user1_auth.do_auth_sns_client()
                security_type = config.test_ops.get("security_type", "PLAINTEXT")
                ceph_version_id, ceph_version_name = utils.get_ceph_version()
                mechanism = config.test_ops.get("mechanism", None)
                endpoint = config.test_ops.get("endpoint")
                ack_type = config.test_ops.get("ack_type")
                topic_id = str(uuid.uuid4().hex[:16])
                topic_name = "cephci-kafka-" + ack_type + "-ack-type-" + topic_id
                log.info(
                    f"creating a topic with {endpoint} endpoint with ack type {ack_type}"
                )
                topic = notification.create_topic(
                    rgw_sns_conn,
                    endpoint,
                    ack_type,
                    topic_name,
                    False,
                    security_type,
                    mechanism,
                )

                # get topic attributes
                if config.test_ops.get("get_topic_info", False):
                    log.info("get topic attributes")
                    get_topic_info = notification.get_topic(
                        rgw_sns_conn, topic, ceph_version_name
                    )

                    log.info("get kafka topic using rgw cli")
                    extra_topic_args = {}
                    if config.user_type == "tenanted":
                        extra_topic_args = {
                            "tenant": tenant1_user1_info["tenant"],
                            "uid": tenant1_user1_info["user_id"],
                        }

                    get_rgw_topic = notification.rgw_admin_topic_notif_ops(
                        op="get", args={"topic": topic_name, **extra_topic_args}
                    )
                    if get_rgw_topic is False:
                        raise TestExecError(
                            "radosgw-admin topic get failed for kafka topic"
                        )

            bucket_policy_generated = s3_bucket_policy.gen_bucket_policy(
                tenants_list=[tenant1],
                userids_list=[tenant1_user2_info["user_id"]],
                actions_list=action_list,
                resources=[bucket_name, f"{bucket_name}/*"],
            )

            bucket_policy_generated["Statement"][0]["Principal"][
                "AWS"
            ] += additional_aws_principle

            bucket_policy = json.dumps(bucket_policy_generated)
            log.info(f"bucket_policy_generated :{bucket_policy}")
            bucket_policy_obj = s3lib.resource_op(
                {
                    "obj": rgw_tenant1_user1,
                    "resource": "BucketPolicy",
                    "args": [bucket_name],
                }
            )
            put_policy = s3lib.resource_op(
                {
                    "obj": bucket_policy_obj,
                    "resource": "put",
                    "kwargs": dict(
                        ConfirmRemoveSelfBucketAccess=True, Policy=bucket_policy
                    ),
                }
            )
            log.info(f"put policy response: {put_policy}\n")
            if put_policy is False:
                raise TestExecError(f"Set bucket policy failed with {put_policy}")
            if put_policy is not None:
                response = HttpResponseParser(put_policy)
                if response.status_code == 200 or response.status_code == 204:
                    log.info("bucket policy created")
                else:
                    raise TestExecError("bucket policy creation failed")
            else:
                raise TestExecError("bucket policy creation failed")

            if config.test_ops.get("put_bucket_website", False):
                reusable.put_bucket_website(rgw_tenant1_user1_c, bucket.name)

                log.info(
                    "perform put bucket website with non bucket owner of same tenant"
                )
                reusable.put_bucket_website(rgw_tenant1_user2_c, bucket.name)
                reusable.put_bucket_website(rgw_tenant1_user3_c, bucket.name)

                log.info(
                    "perform put bucket website with non bucket owner of different tenant"
                )
                bucket_name_verify_policy = f"{tenant1}:{bucket.name}"
                rgw_tenant2_user1_c.meta.events.unregister(
                    "before-parameter-build.s3", validate_bucket_name
                )
                rgw_tenant2_user2_c.meta.events.unregister(
                    "before-parameter-build.s3", validate_bucket_name
                )
                rgw_tenant2_user3_c.meta.events.unregister(
                    "before-parameter-build.s3", validate_bucket_name
                )
                reusable.put_bucket_website(
                    rgw_tenant2_user1_c, bucket_name_verify_policy
                )
                reusable.put_bucket_website(
                    rgw_tenant2_user2_c, bucket_name_verify_policy
                )
                reusable.put_bucket_website(
                    rgw_tenant2_user3_c, bucket_name_verify_policy
                )

            if config.test_ops.get("get_bucket_website", False):
                reusable.put_bucket_website(rgw_tenant1_user1_c, bucket.name)
                log.info("perform get bucket website with bucket owner")
                reusable.get_bucket_website(rgw_tenant1_user1_c, bucket.name)

                log.info(
                    "perform get bucket website with non bucket owner of same tenant"
                )
                reusable.get_bucket_website(rgw_tenant1_user2_c, bucket.name)
                reusable.get_bucket_website(rgw_tenant1_user3_c, bucket.name)

                log.info(
                    "perform get bucket website with non bucket owner of different tenant"
                )
                bucket_name_verify_policy = f"{tenant1}:{bucket.name}"
                rgw_tenant2_user1_c.meta.events.unregister(
                    "before-parameter-build.s3", validate_bucket_name
                )
                rgw_tenant2_user2_c.meta.events.unregister(
                    "before-parameter-build.s3", validate_bucket_name
                )
                rgw_tenant2_user3_c.meta.events.unregister(
                    "before-parameter-build.s3", validate_bucket_name
                )
                reusable.get_bucket_website(
                    rgw_tenant2_user1_c, bucket_name_verify_policy
                )
                reusable.get_bucket_website(
                    rgw_tenant2_user2_c, bucket_name_verify_policy
                )
                reusable.get_bucket_website(
                    rgw_tenant2_user3_c, bucket_name_verify_policy
                )

            if config.test_ops.get("list_bucket_multipart_uploads", False):
                bucket2_name = tenant1_user1_info["user_id"] + "bkt-multipart-0"
                bucket2 = reusable.create_bucket(
                    bucket2_name, rgw_tenant1_user1, tenant1_user1_info
                )
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    for bkt in [bucket, bucket2]:
                        s3_object_name = utils.gen_s3_object_name(bkt.name, oc)
                        log.info(f"s3 objects to create: {config.objects_count}")
                        reusable.upload_mutipart_object(
                            s3_object_name,
                            bkt,
                            TEST_DATA_PATH,
                            config,
                            tenant1_user1_info,
                        )
                srv_time_post_op = get_svc_time(ssh_con)
                log.info(srv_time_pre_op)
                log.info(srv_time_post_op)

                if srv_time_post_op > srv_time_pre_op:
                    log.info("Service is running without crash")
                else:
                    raise TestExecError("Service got crashed")

                # get policy
                get_policy = rgw_tenant1_user1_c.get_bucket_policy(Bucket=bucket.name)
                log.info(f"got bucket policy: {get_policy['Policy']}\n")

                # List multipart uploads with tenant1_user2 user with bucket t1_u1_bucket1
                multipart_object1 = rgw_tenant1_user2_c.list_multipart_uploads(
                    Bucket=bucket.name
                )
                log.info(f"Multipart object :{multipart_object1}")

                # Verify tenant1_user2 not having permission for listing multipart uploads in t1_u1_bucket2
                try:
                    multipart_object2 = rgw_tenant1_user2_c.list_multipart_uploads(
                        Bucket=bucket2.name
                    )
                    raise Exception(
                        f"{tenant1_user2_info['user_id']} user should not list multipart uploads in bucket: {bucket2.name}"
                    )
                except ClientError as err:
                    log.error(f"Listing failed as expected with exception: {err}")

            if config.test_ops.get("list_bucket_versions", False):
                log.info(f"s3 versioned objects to create: {config.objects_count}")
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                    log.info(f"s3 object name: {s3_object_name}")
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info(f"s3 object path: {s3_object_path}")
                    log.info("upload versioned objects")
                    reusable.upload_version_object(
                        config,
                        tenant1_user1_info,
                        rgw_tenant1_user1,
                        s3_object_name,
                        config.obj_size,
                        bucket,
                        TEST_DATA_PATH,
                    )
                # listing the objects
                try:
                    rgw_tenant1_user1_c.list_object_versions(Bucket=bucket.name)
                    rgw_tenant1_user2_c.list_object_versions(Bucket=bucket.name)
                    rgw_tenant1_user3_c.list_object_versions(Bucket=bucket.name)
                except ClientError as err:
                    raise AssertionError(
                        f"Failed to perform object version listing: {err}"
                    )

            if config.test_ops.get("get_obj_and_its_versions", False):
                log.info(f"s3 versioned objects to create: {config.objects_count}")
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                    log.info(f"s3 object name: {s3_object_name}")
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info(f"s3 object path: {s3_object_path}")
                    log.info("upload versioned objects")
                    reusable.upload_version_object(
                        config,
                        tenant1_user1_info,
                        rgw_tenant1_user1,
                        s3_object_name,
                        config.obj_size,
                        bucket,
                        TEST_DATA_PATH,
                    )
                    # get the object
                    try:
                        log.info(
                            "with bucket owner perform get object and its versions"
                        )
                        resp = rgw_tenant1_user1_c.get_object(
                            Bucket=bucket.name, Key=s3_object_name
                        )
                        rgw_tenant1_user1_c.get_object(
                            Bucket=bucket.name,
                            Key=s3_object_name,
                            VersionId=resp["VersionId"],
                        )
                        log.info(
                            "with non bucket owner of same tenant, perform get object and its versions"
                        )
                        rgw_tenant1_user2_c.get_object(
                            Bucket=bucket.name, Key=s3_object_name
                        )
                        rgw_tenant1_user3_c.get_object(
                            Bucket=bucket.name, Key=s3_object_name
                        )
                        rgw_tenant1_user2_c.get_object(
                            Bucket=bucket.name,
                            Key=s3_object_name,
                            VersionId=resp["VersionId"],
                        )
                        rgw_tenant1_user3_c.get_object(
                            Bucket=bucket.name,
                            Key=s3_object_name,
                            VersionId=resp["VersionId"],
                        )
                        log.info(
                            "with non bucket owner of different tenant, perform get object and its versions"
                        )
                        bucket_name_verify_policy = f"{tenant1}:{bucket.name}"
                        rgw_tenant2_user1_c.meta.events.unregister(
                            "before-parameter-build.s3", validate_bucket_name
                        )
                        rgw_tenant2_user2_c.meta.events.unregister(
                            "before-parameter-build.s3", validate_bucket_name
                        )
                        rgw_tenant2_user3_c.meta.events.unregister(
                            "before-parameter-build.s3", validate_bucket_name
                        )
                        rgw_tenant2_user1_c.get_object(
                            Bucket=bucket_name_verify_policy, Key=s3_object_name
                        )
                        rgw_tenant2_user2_c.get_object(
                            Bucket=bucket_name_verify_policy, Key=s3_object_name
                        )
                        rgw_tenant2_user3_c.get_object(
                            Bucket=bucket_name_verify_policy, Key=s3_object_name
                        )
                        rgw_tenant2_user1_c.get_object(
                            Bucket=bucket_name_verify_policy,
                            Key=s3_object_name,
                            VersionId=resp["VersionId"],
                        )
                        rgw_tenant2_user2_c.get_object(
                            Bucket=bucket_name_verify_policy,
                            Key=s3_object_name,
                            VersionId=resp["VersionId"],
                        )
                        rgw_tenant2_user3_c.get_object(
                            Bucket=bucket_name_verify_policy,
                            Key=s3_object_name,
                            VersionId=resp["VersionId"],
                        )
                    except ClientError as err:
                        raise AssertionError(
                            f"Failed to perform get object with: {err}"
                        )

            if config.test_ops.get("get_bucket_location", False):
                log.info("Perform get bucket location: from users of same tenant")
                try:
                    rgw_tenant1_user1_c.get_bucket_location(Bucket=bucket.name)
                    rgw_tenant1_user2_c.get_bucket_location(Bucket=bucket.name)
                    rgw_tenant1_user3_c.get_bucket_location(Bucket=bucket.name)
                except ClientError as err:
                    raise AssertionError(
                        f"Failed to perform get_bucket_location: {err}"
                    )
            if config.test_ops.get("lifecycle_configuration", False):
                log.info(
                    "Perform put and get lifecycle configuration: from users of same tenant"
                )
                life_cycle_rule = {"Rules": config.lifecycle_conf}
                log.info(
                    "Perform put lifecycle configuration: from one user of same tenant"
                )
                reusable.put_bucket_lifecycle(
                    bucket,
                    rgw_tenant1_user1,
                    rgw_tenant1_user1_c,
                    life_cycle_rule,
                    get_lc=False,
                )

                try:
                    log.info(
                        "Perform get lifecycle configuration: from all users of same tenant"
                    )
                    rgw_clients = [
                        rgw_tenant1_user1_c,
                        rgw_tenant1_user2_c,
                        rgw_tenant1_user3_c,
                    ]
                    for rgw_client in rgw_clients:
                        reusable.put_bucket_lifecycle(
                            bucket,
                            rgw_tenant1_user1,
                            rgw_client,
                            life_cycle_rule,
                            put_lc=False,
                        )
                except ClientError as err:
                    raise AssertionError(
                        f"Failed to perform lifecycle configuration operation: {err}"
                    )

            if config.test_ops.get("put_get_bucket_notification", False):
                event_types = config.test_ops.get("event_type")
                if type(event_types) == str:
                    event_types = [event_types]
                notification_name = "notification-" + "-".join(event_types)
                bkt_notif_topic_name = f"{notification_name}_{topic_name}"
                notification.put_bucket_notification(
                    rgw_tenant1_user1_c,
                    bucket_name,
                    notification_name,
                    topic,
                    ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                    config,
                )

                # get bucket notification
                try:
                    log.info(
                        f"with non bucket owner of same tenant, perform get notification on bucket: {bucket_name}"
                    )
                    notification.get_bucket_notification(
                        rgw_tenant1_user1_c, bucket_name
                    )
                    notification.get_bucket_notification(
                        rgw_tenant1_user2_c, bucket_name
                    )
                    notification.get_bucket_notification(
                        rgw_tenant1_user3_c, bucket_name
                    )
                    log.info(
                        f"with non bucket owner of different tenant, perform get notification on bucket: {bucket_name}"
                    )
                    bucket_name_verify_policy = f"{tenant1}:{bucket_name}"
                    rgw_tenant2_user1_c.meta.events.unregister(
                        "before-parameter-build.s3", validate_bucket_name
                    )
                    rgw_tenant2_user2_c.meta.events.unregister(
                        "before-parameter-build.s3", validate_bucket_name
                    )
                    rgw_tenant2_user3_c.meta.events.unregister(
                        "before-parameter-build.s3", validate_bucket_name
                    )
                    notification.get_bucket_notification(
                        rgw_tenant2_user1_c, bucket_name_verify_policy
                    )
                    notification.get_bucket_notification(
                        rgw_tenant2_user2_c, bucket_name_verify_policy
                    )
                    notification.get_bucket_notification(
                        rgw_tenant2_user3_c, bucket_name_verify_policy
                    )

                except ClientError as err:
                    raise AssertionError(
                        f"Failed to perform get notification on same and different tenat users with: {err}"
                    )

                if config.test_ops.get("Filter", False) is False:
                    config.test_ops["Filter"] = notification.Filter
                # create objects
                if config.test_ops.get("create_object", False):
                    # uploading data
                    log.info("s3 objects to create: %s" % config.objects_count)
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
                        obj_name_temp = s3_object_name
                        if config.test_ops.get("Filter"):
                            s3_object_name = notification.get_affixed_obj_name(
                                config, obj_name_temp
                            )
                        log.info("s3 object name: %s" % s3_object_name)
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info("s3 object path: %s" % s3_object_path)
                        log.info("upload type: normal")
                        reusable.upload_object(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            tenant1_user1_info,
                        )

                # copy objects
                if config.test_ops.get("copy_object", False):
                    log.info("copy object")
                    obj_name = notification.get_affixed_obj_name(
                        config, "copy_of_object" + obj_name_temp
                    )
                    status = rgw_tenant1_user1_c.copy_object(
                        Bucket=bucket_name,
                        Key=obj_name,
                        CopySource={
                            "Bucket": bucket_name,
                            "Key": s3_object_name,
                        },
                    )
                    if status is None:
                        raise TestExecError("copy object failed")

                # start kafka broker and consumer
                event_record_path = "/tmp/event_record"
                start_consumer = notification.start_kafka_broker_consumer(
                    topic_name, event_record_path
                )
                if start_consumer is False:
                    raise TestExecError("Kafka consumer not running")

                # verify all the attributes of the event record. if event not received abort testcase
                log.info("verify event record attributes")
                bucket_name_for_verification = (
                    tenant1_user1_info["tenant"] + "/" + bucket_name
                )
                for event in event_types:
                    verify = notification.verify_event_record(
                        event,
                        bucket_name_for_verification,
                        event_record_path,
                        ceph_version_name,
                    )
                    if verify is False:
                        raise EventRecordDataError(
                            "Event record is empty! notification is not seen"
                        )

                # delete topic logs on kafka broker
                notification.del_topic_from_kafka_broker(topic_name)

    tenant_info = (
        (tenant1_user_info + tenant2_user_info)
        if config.test_ops.get("new_tenant_user", False)
        else tenant1_user_info
    )
    for i in tenant_info:
        reusable.remove_user(i, tenant=i["tenant"])

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("test bucket policy")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
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
