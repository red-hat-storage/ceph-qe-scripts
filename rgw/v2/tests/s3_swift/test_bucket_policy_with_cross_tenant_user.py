"""
# test cross-tenant user bucket notification management

usage : test_bucket_policy_with_cross_tenant_user.py -c <input_yaml>

<input_yaml>
    rgw/v2/tests/s3_swift/configs/test_bucket_policy.yaml

Operation:
- Create users in different tenants, user1 and user2
- Create topic and bucket for user1
- Using user1 credentials, set bucket policy for user2 to access objects of
  bucket1 created with user1
- Configure bucket notifications from user2 client using the topic ARN
- Upload objects to bucket and verify user2 can access objects from bucket
  created by user1
- Verify notification events are recorded via Kafka consumer


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
from v2.lib.exceptions import EventRecordDataError, RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import bucket_notification as notification
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()


TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    ceph_config_set = CephConfOp(ssh_con)
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)
    if config.test_ops.get("verify_policy"):
        ceph_config_set.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_enable_static_website,
            True,
            ssh_con,
        )
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")

    event_types = config.test_ops.get("event_type")
    if type(event_types) == str:
        event_types = [event_types]

    # create user
    config.user_count = 1
    tenant1 = "MountEverest"
    tenant2 = "Himalayas"
    tenant1_user_info = s3lib.create_tenant_users(
        tenant_name=tenant1, no_of_users_to_create=config.user_count
    )
    tenant1_user1_info = tenant1_user_info[0]
    for each_user in tenant1_user_info:
        tenant1_user1_information = each_user
    tenant2_user_info = s3lib.create_tenant_users(
        tenant_name=tenant2, no_of_users_to_create=config.user_count
    )
    tenant2_user1_info = tenant2_user_info[0]
    tenant1_user1_auth = reusable.get_auth(
        tenant1_user1_info, ssh_con, config.ssl, config.haproxy
    )
    tenant2_user1_auth = reusable.get_auth(
        tenant2_user1_info, ssh_con, config.ssl, config.haproxy
    )
    rgw_tenant1_user1 = tenant1_user1_auth.do_auth()
    rgw_tenant1_user1_c = tenant1_user1_auth.do_auth_using_client()
    rgw_tenant1_user1_sns_client = tenant1_user1_auth.do_auth_sns_client()
    rgw_tenant2_user1 = tenant2_user1_auth.do_auth()
    rgw_tenant2_user1_c = tenant2_user1_auth.do_auth_using_client()
    rgw_tenant2_user1_sns_client = tenant2_user1_auth.do_auth_sns_client()
    bucket_name1 = utils.gen_bucket_name_from_userid(
        tenant1_user1_info["user_id"], rand_no=1
    )
    if config.haproxy:
        t1_u1_bucket1 = reusable.create_bucket(
            bucket_name1,
            rgw_tenant1_user1,
            tenant1_user1_info,
        )
    else:
        t1_u1_bucket1 = reusable.create_bucket(
            bucket_name1,
            rgw_tenant1_user1,
            tenant1_user1_info,
            ip_and_port,
        )

    if config.test_ops.get("policy_document", False):
        log.info("=== Starting cross-tenant bucket notification test ===")

        # 1. Create topic1 with tenant1 user
        endpoint = config.test_ops.get("endpoint")
        ack_type = config.test_ops.get("ack_type")
        topic_id = str(uuid.uuid4().hex[:16])
        topic_name = f"cephci-kafka-{ack_type}-ack-type-{topic_id}"
        log.info(f"Creating a topic with {endpoint} endpoint with ack type {ack_type}")
        ceph_version_id, ceph_version_name = utils.get_ceph_version()
        # create topic at kafka side
        notification.create_topic_from_kafka_broker(topic_name)
        # create topic at rgw side
        topic_arn = notification.create_topic(
            rgw_tenant1_user1_sns_client,
            endpoint,
            ack_type,
            topic_name,
        )

        # get topic attributes
        if config.test_ops.get("get_topic_info", False):
            log.info("get topic attributes")
            get_topic_info = notification.get_topic(
                rgw_tenant1_user1_sns_client, topic_arn, ceph_version_name
            )

            log.info("get kafka topic using rgw cli")
            extra_topic_args = {}
            if config.user_type == "tenanted":
                extra_topic_args = {
                    "tenant": tenant1_user1_info["tenant"],
                    "uid": tenant1_user1_info["user_id"],
                }
            get_rgw_topic = notification.rgw_admin_topic_notif_ops(
                config, op="get", args={"topic": topic_name, **extra_topic_args}
            )
            if get_rgw_topic is False:
                raise TestExecError("radosgw-admin topic get failed for kafka topic")

        # 3. Apply bucket policy to allow tenant2 put bucket notifications
        if config.test_ops.get("policy_document", False):
            bucket_policy = json.dumps(config.test_ops["policy_document"])
            bucket_policy = bucket_policy.replace("<tenant_name>", tenant1)
            bucket_policy = bucket_policy.replace("<bucket_name>", t1_u1_bucket1.name)
            bucket_policy_generated = json.loads(bucket_policy)
            log.info(f"Bucket policy: {bucket_policy}")
            log.info(bucket_policy_generated)
            # Apply the policy using tenant1 credentials
            log.info(
                f"Applying bucket policy to {t1_u1_bucket1.name} to allow tenant2 user to put bucket notification"
            )
            rgw_tenant1_user1_c.put_bucket_policy(
                Bucket=t1_u1_bucket1.name, Policy=bucket_policy
            )

        # put bucket notification
        rgw_tenant2_user1_c.meta.events.unregister(
            "before-parameter-build.s3", validate_bucket_name
        )
        bucket_name = f"{tenant1}:{t1_u1_bucket1.name}"
        if config.test_ops.get("put_get_bucket_notification", False):
            log.info(
                f"Putting bucket notification from tenant2 to tenant1's bucket {t1_u1_bucket1.name}"
            )
            events = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
            notification_name = f"notif-{uuid.uuid4().hex[:8]}"
            notification.put_bucket_notification(
                rgw_tenant2_user1_c,
                bucket_name,
                notification_name,
                topic_arn,
                events,
                config,
            )

            # get bucket notification
            log.info(f"get bucket notification for bucket : {bucket_name}")
            get_bucket_notification = notification.get_bucket_notification(
                rgw_tenant2_user1_c, bucket_name
            )

            if get_bucket_notification is False:
                raise TestExecError(
                    f"Failed to get bucket notification for {bucket_name}"
                )
        # Upload objects using tenant1 client

        if config.test_ops.get("upload_type") == "normal":
            for oc, size in list(config.mapped_sizes.items()):
                config.obj_size = size
                s3_object_name = utils.gen_s3_object_name(t1_u1_bucket1.name, oc)
                log.info("s3 object name: %s" % s3_object_name)
                s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                log.info("s3 object path: %s" % s3_object_path)
                log.info("upload type: normal")
                reusable.upload_object(
                    s3_object_name,
                    t1_u1_bucket1,
                    TEST_DATA_PATH,
                    config,
                    tenant1_user1_info,
                )

        # Accessing objects from tenant2
        response = rgw_tenant2_user1_c.list_objects_v2(Bucket=bucket_name)
        log.info(
            f"Tenant2 accessed bucket {tenant1}:{t1_u1_bucket1.name}: {response.get('Contents', [])}"
        )

        # start kafka server
        if config.test_ops.get("verify_persistence_with_kafka_stop", False):
            notification.start_stop_kafka_server("start")

        # start kafka broker and consumer
        event_record_path = "/tmp/event_record"
        start_consumer = notification.start_kafka_broker_consumer(
            topic_name, event_record_path
        )
        if start_consumer is False:
            raise TestExecError("Kafka consumer not running")

        # verify all the attributes of the event record
        bucket_for_stats = f"{tenant1}/{t1_u1_bucket1.name}"
        log.info("verify event record attributes")

        for event in event_types:
            verify = notification.verify_event_record(
                event,
                bucket_for_stats,
                event_record_path,
                ceph_version_name,
                config,
            )

            if verify is False:
                raise EventRecordDataError(
                    "Event record is empty! notification is not seen"
                )


if __name__ == "__main__":
    test_info = AddTestInfo("test bucket policy")
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
        if config.test_ops.get("upload_type"):
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
