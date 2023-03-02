"""
test_bucket_notification - Test bucket notifcations 
Usage: test_bucket_notification.py -c <input_yaml>
<input_yaml>
    Note: any one of these yamls can be used
    test_bucket_notification_kafka_broker_persistent_delete.yaml
    test_bucket_notification_kafka_broker_persistent_copy.yaml
    test_bucket_notification_kafka_broker_persistent_multipart.yaml
    test_bucket_notification_kafka_none_persistent_delete.yaml
    test_bucket_notification_kafka_none_persistent_copy.yaml
    test_bucket_notification_kafka_none_persistent_multipart.yaml
    test_bucket_notification_kafka_broker_delete.yaml		
    test_bucket_notification_kafka_broker_copy.yaml
    test_bucket_notification_kafka_broker_multipart.yaml
    test_bucket_notification_kafka_none_delete.yaml
    test_bucket_notification_kafka_none_copy.yaml
    test_bucket_notification_kafka_none_mulitpart.yaml
    test_bucket_notification_sasl_plaintext_plain_.*.yaml
    test_bucket_notification_sasl_plaintext_scram_sha_256_.*.yaml
    test_bucket_notification_sasl_ssl_plain_.*.yaml
    test_bucket_notification_sasl_ssl_scram_sha_256_.*.yaml
    test_bucket_notification_ssl_.*.yaml
Operation:
    Create topic 
    put bucket notifcation and get bucket notification
    create, copy objects, multipart uploads, delete objects in the yaml
    verify events are generated on the broker.
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
from v2.lib.exceptions import EventRecordDataError, RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import bucket_notification as notification
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
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()

        # authenticate sns client.
        rgw_sns_conn = auth.do_auth_sns_client()

        # authenticate with s3 client
        rgw_s3_client = auth.do_auth_using_client()

        # get ceph version
        ceph_version_id, ceph_version_name = utils.get_ceph_version()

        objects_created_list = []
        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user
                )
                if config.test_ops.get("enable_version", False):
                    log.info("enable bucket version")
                    reusable.enable_versioning(
                        bucket, rgw_conn, each_user, write_bucket_io_info
                    )

                event_types = config.test_ops.get("event_type")
                if type(event_types) == str:
                    event_types = [event_types]
                security_type = config.test_ops.get("security_type", "PLAINTEXT")
                mechanism = config.test_ops.get("mechanism", None)
                # create topic with endpoint
                if config.test_ops["create_topic"] is True:
                    endpoint = config.test_ops.get("endpoint")
                    ack_type = config.test_ops.get("ack_type")
                    topic_id = str(uuid.uuid4().hex[:16])
                    persistent = False
                    topic_name = "cephci-kafka-" + ack_type + "-ack-type-" + topic_id
                    log.info(
                        f"creating a topic with {endpoint} endpoint with ack type {ack_type}"
                    )
                    if config.test_ops.get("persistent_flag", False):
                        log.info("topic with peristent flag enabled")
                        persistent = config.test_ops.get("persistent_flag")
                    topic = notification.create_topic(
                        rgw_sns_conn,
                        endpoint,
                        ack_type,
                        topic_name,
                        persistent,
                        security_type,
                        mechanism,
                    )

                # get topic attributes
                if config.test_ops.get("get_topic_info", False):
                    log.info("get topic attributes")
                    get_topic_info = notification.get_topic(
                        rgw_sns_conn, topic, ceph_version_name
                    )

                # put bucket notification with topic configured for event
                if config.test_ops["put_get_bucket_notification"] is True:
                    events = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
                    notification_name = "notification-" + "-".join(event_types)
                    notification.put_bucket_notification(
                        rgw_s3_client,
                        bucket_name_to_create,
                        notification_name,
                        topic,
                        events,
                    )

                    # get bucket notification
                    log.info(
                        f"get bucket notification for bucket : {bucket_name_to_create}"
                    )
                    notification.get_bucket_notification(
                        rgw_s3_client, bucket_name_to_create
                    )

                # create objects
                if config.test_ops["create_object"] is True:
                    # uploading data
                    log.info("s3 objects to create: %s" % config.objects_count)
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, oc
                        )
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
                # copy objects
                if config.test_ops.get("copy_object", False):
                    log.info("copy object")
                    status = rgw_s3_client.copy_object(
                        Bucket=bucket_name_to_create,
                        Key="copy_of_object" + s3_object_name,
                        CopySource={
                            "Bucket": bucket_name_to_create,
                            "Key": s3_object_name,
                        },
                    )
                    if status is None:
                        raise TestExecError("copy object failed")

                # delete objects
                if config.test_ops.get("delete_bucket_object", False):
                    if config.test_ops.get("enable_version", False):
                        for name, path in objects_created_list:
                            reusable.delete_version_object(
                                bucket, name, path, rgw_conn, each_user
                            )
                    else:
                        reusable.delete_objects(bucket)

                # start kafka broker and consumer
                event_record_path = "/tmp/event_record"
                start_consumer = notification.start_kafka_broker_consumer(
                    topic_name, event_record_path
                )
                if start_consumer is False:
                    raise TestExecError("Kafka consumer not running")

                # verify all the attributes of the event record. if event not received abort testcase
                log.info("verify event record attributes")
                for event in event_types:
                    verify = notification.verify_event_record(
                        event,
                        bucket_name_to_create,
                        event_record_path,
                        ceph_version_name,
                    )
                    if verify is False:
                        raise EventRecordDataError(
                            "Event record is empty! notification is not seen"
                        )
                # put empty bucket notification to remove existing configuration
                if config.test_ops.get("put_empty_bucket_notification", False):
                    notification.put_empty_bucket_notification(
                        rgw_s3_client,
                        bucket_name_to_create,
                    )

        # delete topic logs on kafka broker
        notification.del_topic_from_kafka_broker(topic_name)

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test bucket notification")
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
