"""
test_bucket_notifications_1k_topics - Test that RGW does not enter an infinite
loop when more than 1K topics are configured per tenant/account.

Usage: test_bucket_notifications_1k_topics.py -c <input_yaml>
<input_yaml>
    test_bucket_notification_kafka_broker_persistent_1k_topics.yaml

Operation:
    1. Create a tenanted user.
    2. Create more than 1K persistent SNS topics.
    3. Create Kafka broker topics only for consume.
    4. Attach notifications and generate Delete events.
    5. Consume Kafka and verify events.
    6. Create a new topic after refresh and verify it is picked up.
    7. Clean up topics, buckets, and user.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import v2.utils.utils as utils
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import EventRecordDataError, RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
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
    io_info_initialize.initialize(basic_io_structure.initial())

    # create tenanted user
    umgmt = UserMgmt()
    all_users_info = []
    for i in range(config.user_count):
        user_name = "user" + str(uuid.uuid4().hex[:16])
        tenant_name = "tenant" + str(i)
        tenant_user = umgmt.create_tenant_user(
            tenant_name=tenant_name, user_id=user_name, displayname=user_name
        )
        all_users_info.append(tenant_user)

    event_types = config.test_ops.get("event_type")
    if type(event_types) == str:
        event_types = [event_types]

    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()

        # authenticate sns client
        rgw_sns_conn = auth.do_auth_sns_client()

        # authenticate with s3 client
        rgw_s3_client = auth.do_auth_using_client()

        # get ceph version
        ceph_version_id, ceph_version_name = utils.get_ceph_version()
        ceph_version_id = ceph_version_id.split("-")
        ceph_version_id = ceph_version_id[0].split(".")

        extra_topic_args = {
            "tenant": each_user["tenant"],
            "uid": each_user["user_id"],
        }

        endpoint = config.test_ops.get("endpoint")
        ack_type = config.test_ops.get("ack_type")
        persistent = config.test_ops.get("persistent_flag", False)
        security_type = config.test_ops.get("security_type", "PLAINTEXT")
        mechanism = config.test_ops.get("mechanism", None)
        topic_count = config.test_ops.get("topic_count")
        thread_pool_size = 30
        if "reef" in str(ceph_version_name).lower():
            thread_pool_size = 5
        log_progress_interval = 100
        # notify manager lists queues in pages of 1024 (rgw_notify.cc) and
        # sleeps queues_update_period (30s) before looking for new topics
        queue_list_max = 1024
        queues_update_period = 35

        if topic_count is None or topic_count <= queue_list_max:
            raise TestExecError(
                f"topic_count must be greater than {queue_list_max} so that "
                f"queue listing is not truncated to the first page"
            )

        # zero-padded names so index 1024 sorts after the first page
        run_id = uuid.uuid4().hex[:8]
        created_topic_names = [
            "cephci-kafka-" + ack_type + "-ack-type-" + run_id + "-" + str(idx).zfill(4)
            for idx in range(topic_count)
        ]
        created_topic_arns = [None] * topic_count
        verify_indexes = sorted(set([0, queue_list_max, topic_count - 1]))
        kafka_topic_names = [created_topic_names[idx] for idx in verify_indexes]

        log.info(
            f"creating {topic_count} topics for tenant {each_user['tenant']} "
            f"to reproduce the > 1K topics infinite loop scenario; "
            f"verify indexes {verify_indexes}"
        )
        for kafka_topic in kafka_topic_names:
            notification.create_topic_from_kafka_broker(kafka_topic)
        with ThreadPoolExecutor(max_workers=thread_pool_size) as executor:
            futures = {
                executor.submit(
                    notification.create_topic,
                    rgw_sns_conn,
                    endpoint,
                    ack_type,
                    topic_name,
                    persistent,
                    security_type,
                    mechanism,
                ): idx
                for idx, topic_name in enumerate(created_topic_names)
            }
            done = 0
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    created_topic_arns[idx] = future.result()
                except Exception as e:
                    log.info(
                        "create_topic failed for %s: %s; retrying"
                        % (created_topic_names[idx], e)
                    )
                    retry = 0
                    while retry < 3:
                        retry += 1
                        time.sleep(2)
                        try:
                            created_topic_arns[idx] = notification.create_topic(
                                rgw_sns_conn,
                                endpoint,
                                ack_type,
                                created_topic_names[idx],
                                persistent,
                                security_type,
                                mechanism,
                            )
                            break
                        except Exception as retry_e:
                            log.info(
                                "create_topic retry %s failed for %s: %s"
                                % (retry, created_topic_names[idx], retry_e)
                            )
                            if retry == 3:
                                raise
                done += 1
                if done % log_progress_interval == 0 or done == topic_count:
                    log.info(f"created {done}/{topic_count} rgw topics")

        log.info(f"all {topic_count} topics created successfully")
        log.info(
            f"waiting {queues_update_period}s for notify manager to list all "
            f"queues (30s queues_update_period plus buffer)"
        )
        time.sleep(queues_update_period)

        # create one bucket per verification topic (first, past first page, last)
        if config.test_ops.get("create_bucket", False):
            log.info(
                "no of buckets to create for verification topics: %s"
                % len(verify_indexes)
            )
            buckets_to_verify = []
            for bc, topic_idx in enumerate(verify_indexes):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user
                )

                notification_name = "notification-" + "-".join(event_types)
                events = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
                log.info(
                    f"put bucket notification on {bucket_name_to_create} using "
                    f"topic index {topic_idx} ({created_topic_names[topic_idx]})"
                )
                notification.put_bucket_notification(
                    rgw_s3_client,
                    bucket_name_to_create,
                    notification_name,
                    created_topic_arns[topic_idx],
                    events,
                    config,
                )
                notification.get_bucket_notification(
                    rgw_s3_client, bucket_name_to_create
                )

                # create objects
                if config.test_ops.get("create_object", False):
                    log.info("s3 objects to create: %s" % config.objects_count)
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, oc
                        )
                        log.info("s3 object name: %s" % s3_object_name)
                        log.info("upload type: normal")
                        reusable.upload_object(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            each_user,
                        )

                # delete objects to trigger ObjectRemoved events before consuming
                if config.test_ops.get("delete_bucket_object", False):
                    reusable.delete_objects(bucket)

                buckets_to_verify.append(
                    (bucket, bucket_name_to_create, created_topic_names[topic_idx])
                )

            # start kafka consumer and verify events for first, 1024th, and last
            for bucket, bucket_name_to_create, topic_name in buckets_to_verify:
                event_record_path = "/tmp/event_record_" + topic_name
                log.info(
                    f"consume kafka events for topic {topic_name} "
                    f"(bucket {bucket_name_to_create})"
                )
                start_consumer = notification.start_kafka_broker_consumer(
                    topic_name, event_record_path
                )
                if start_consumer is False:
                    raise TestExecError("Kafka consumer not running")

                log.info("verify event record attributes")
                bucket_name_for_verification = (
                    each_user["tenant"] + "/" + bucket_name_to_create
                )
                for event in event_types:
                    verify = notification.verify_event_record(
                        event,
                        bucket_name_for_verification,
                        event_record_path,
                        ceph_version_name,
                        config,
                    )
                    if verify is False:
                        raise EventRecordDataError(
                            "Event record is empty! notification is not seen "
                            f"for topic {topic_name}. RGW did not process topics "
                            f"beyond the first 1K queues"
                        )

            # create one more topic after the refresh window and verify it is picked up
            extra_topic_name = (
                "cephci-kafka-"
                + ack_type
                + "-ack-type-"
                + run_id
                + "-"
                + str(topic_count).zfill(4)
            )
            log.info(
                f"creating extra topic {extra_topic_name} after the 30s refresh "
                f"window to verify new topics are picked up"
            )
            notification.create_topic_from_kafka_broker(extra_topic_name)
            extra_topic_arn = None
            retry = 0
            while extra_topic_arn is None:
                try:
                    extra_topic_arn = notification.create_topic(
                        rgw_sns_conn,
                        endpoint,
                        ack_type,
                        extra_topic_name,
                        persistent,
                        security_type,
                        mechanism,
                    )
                except Exception as e:
                    retry += 1
                    log.info(
                        "create_topic failed for %s: %s; retrying"
                        % (extra_topic_name, e)
                    )
                    if retry == 3:
                        raise
                    time.sleep(2)
            created_topic_names.append(extra_topic_name)
            created_topic_arns.append(extra_topic_arn)
            kafka_topic_names.append(extra_topic_name)

            extra_bucket_name = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=len(verify_indexes)
            )
            extra_bucket = reusable.create_bucket(
                extra_bucket_name, rgw_conn, each_user
            )
            notification_name = "notification-" + "-".join(event_types)
            events = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
            notification.put_bucket_notification(
                rgw_s3_client,
                extra_bucket_name,
                notification_name,
                extra_topic_arn,
                events,
                config,
            )
            notification.get_bucket_notification(rgw_s3_client, extra_bucket_name)

            log.info(
                f"waiting {queues_update_period}s for notify manager to pick up "
                f"the new topic"
            )
            time.sleep(queues_update_period)

            if config.test_ops.get("create_object", False):
                log.info("s3 objects to create: %s" % config.objects_count)
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(extra_bucket_name, oc)
                    log.info("s3 object name: %s" % s3_object_name)
                    log.info("upload type: normal")
                    reusable.upload_object(
                        s3_object_name,
                        extra_bucket,
                        TEST_DATA_PATH,
                        config,
                        each_user,
                    )

            if config.test_ops.get("delete_bucket_object", False):
                reusable.delete_objects(extra_bucket)

            event_record_path = "/tmp/event_record_" + extra_topic_name
            start_consumer = notification.start_kafka_broker_consumer(
                extra_topic_name, event_record_path
            )
            if start_consumer is False:
                raise TestExecError("Kafka consumer not running")

            log.info("verify event record attributes for extra topic after refresh")
            bucket_name_for_verification = each_user["tenant"] + "/" + extra_bucket_name
            for event in event_types:
                verify = notification.verify_event_record(
                    event,
                    bucket_name_for_verification,
                    event_record_path,
                    ceph_version_name,
                    config,
                )
                if verify is False:
                    raise EventRecordDataError(
                        "Event record is empty! notification is not seen "
                        f"for extra topic {extra_topic_name}. RGW did not pick up "
                        f"new topics after the 30s refresh window"
                    )

            buckets_to_verify.append(
                (extra_bucket, extra_bucket_name, extra_topic_name)
            )

            # verify all topics appear in radosgw-admin topic list
            log.info(
                f"verifying all {len(created_topic_names)} topics appear in "
                f"radosgw-admin topic list"
            )
            topics_list = notification.rgw_admin_topic_notif_ops(
                config, op="list", args={**extra_topic_args}
            )
            if topics_list is False:
                raise TestExecError("radosgw-admin topic list failed")

            # handle both list and dict response shapes across ceph versions
            if isinstance(topics_list, list):
                topics_page = topics_list
            else:
                topics_page = topics_list.get("topics", [])

            total_listed = len(topics_page)
            if total_listed < len(created_topic_names):
                raise TestExecError(
                    f"radosgw-admin topic list returned only {total_listed} topics; "
                    f"expected {len(created_topic_names)}"
                )

            log.info(
                f"radosgw-admin topic list returned {total_listed} topics; "
                f"RGW processed topics beyond the first 1K queues"
            )

            # delete buckets after verification
            if config.test_ops.get("delete_bucket_object", False):
                for bucket, bucket_name_to_create, topic_name in buckets_to_verify:
                    reusable.delete_bucket(bucket)

        # remove all created topics
        log.info(f"deleting {len(created_topic_names)} rgw topics")
        rm_failures = []
        with ThreadPoolExecutor(max_workers=thread_pool_size) as executor:
            futures = {
                executor.submit(
                    notification.rgw_admin_topic_notif_ops,
                    config,
                    "rm",
                    {"topic": topic_name, **extra_topic_args},
                ): topic_name
                for topic_name in created_topic_names
            }
            done = 0
            total_to_delete = len(created_topic_names)
            for future in as_completed(futures):
                topic_name = futures[future]
                result = future.result()
                if result is False:
                    rm_failures.append(topic_name)
                done += 1
                if done % log_progress_interval == 0 or done == total_to_delete:
                    log.info(f"deleted {done}/{total_to_delete} rgw topics")
        retry = 0
        while rm_failures and retry < 3:
            retry += 1
            log.info(
                "retrying topic rm for %s topics, attempt %s"
                % (len(rm_failures), retry)
            )
            time.sleep(2)
            still_failed = []
            for topic_name in rm_failures:
                result = notification.rgw_admin_topic_notif_ops(
                    config,
                    "rm",
                    {"topic": topic_name, **extra_topic_args},
                )
                if result is False:
                    still_failed.append(topic_name)
            rm_failures = still_failed
        if rm_failures:
            raise TestExecError(
                f"radosgw-admin topic rm failed for {len(rm_failures)} topics; "
                f"first: {rm_failures[0]}"
            )
        for kafka_topic in kafka_topic_names:
            notification.del_topic_from_kafka_broker(kafka_topic)

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

    if config.user_remove:
        for i in all_users_info:
            reusable.remove_user(i, tenant=i["tenant"])


if __name__ == "__main__":
    test_info = AddTestInfo("test bucket notifications with over 1K topics per tenant")
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
