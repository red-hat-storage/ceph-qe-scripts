import json
import logging
import os
import random
import time
import timeit
from urllib import parse as urlparse

import v2.utils.utils as utils
from v2.lib.exceptions import EventRecordDataError

log = logging.getLogger()


def start_kafka_broker_consumer(topic_name, event_record_path, ceph_version):
    """
    start kafka consumer
    topic_name: name of the topic to listen to
    event_record_path: path to store the event records
    """

    if os.path.isfile(event_record_path):
        log.info(
            "stale event record file exists, deleting it before creating a new file."
        )
        cmd = f"rm -f {event_record_path}"
        t = utils.exec_shell_cmd(cmd)
        print("path exists :", t)

    KAFKA_HOME = "/usr/local/kafka"

    # start kafka consumer
    if "nautilus" in ceph_version:
        cmd = f"sudo {KAFKA_HOME}/bin/kafka-console-consumer.sh --bootstrap-server kafka://localhost:9092 --from-beginning --topic {topic_name} --timeout-ms 30000 >> {event_record_path}"
    else:
        cmd = f"sudo {KAFKA_HOME}/bin/kafka-console-consumer.sh --bootstrap-server kafka://localhost:9092 --from-beginning --topic {topic_name} --zookeeper localhost:2181 --timeout-ms 30000 >> {event_record_path}"
    start_consumer_kafka = utils.exec_shell_cmd(cmd)


def create_topic(sns_client, endpoint, ack_type, topic_name, persistent_flag=False):
    """
    to create topic with specified endpoint , ack_level
    return: topic ARN
    """
    endpoint_args = (
        "push-endpoint="
        + endpoint
        + "://localhost&verify-ssl=False&kafka-ack-level="
        + ack_type
    )
    if persistent_flag:
        endpoint_args = endpoint_args + "&persistent=true"
    attributes = {
        nvp[0]: nvp[1]
        for nvp in urlparse.parse_qsl(endpoint_args, keep_blank_values=True)
    }
    get_topic = sns_client.create_topic(Name=topic_name, Attributes=attributes)
    topic_arn = get_topic["TopicArn"]

    log.info(f"topic_ARN is : {topic_arn}")
    return topic_arn


def get_topic(client, topic_arn, ceph_version):
    """
    get the topic with spedified topic_arn
    """
    if "nautilus" in ceph_version:
        pass
    else:
        get_topic_info = client.get_topic_attributes(TopicArn=topic_arn)
        get_topic_info_json = json.dumps(get_topic_info, indent=2)
        if get_topic_info is False:
            raise TestExecError("topic creation failed")
        else:
            log.info(f"get topic attributes: {get_topic_info_json}")


def put_bucket_notification(
    rgw_s3_client, bucketname, notification_name, topic_arn, event
):
    """
    put bucket notification on bucket for specified events with given endpoint and topic
    """
    log.info(f"put bucket notification on {bucketname}")
    put_bkt_notification = rgw_s3_client.put_bucket_notification_configuration(
        Bucket=bucketname,
        NotificationConfiguration={
            "TopicConfigurations": [
                {
                    "Id": notification_name,
                    "TopicArn": topic_arn,
                    "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                }
            ]
        },
    )
    if put_bkt_notification is False:
        raise TestExecError("put bucket notification failed")


def get_bucket_notification(rgw_s3_client, bucketname):
    """
    get bucket notification for a given bucket
    """
    get_bkt_notification = rgw_s3_client.get_bucket_notification_configuration(
        Bucket=bucketname
    )
    if get_bkt_notification is False:
        raise TestExecError(
            f"failed to get bucket notification for bucket : {bucketname}"
        )
    get_bucket_notification_json = json.dumps(get_bkt_notification, indent=2)
    log.info(
        f"bucket notification for bucket: {bucketname} is {get_bucket_notification_json}"
    )


def verify_event_record(event_type, bucket, event_record_path, ceph_version):
    """
    verify event records
    """
    if os.path.getsize(event_record_path) == 0:
        raise EventRecordDataError("event record not generated! File is empty")

    # read the file event_record
    with open(event_record_path, "r") as records:
        for record in records:
            event_record = record.strip()
            log.info(f" event record \n {record}")
            event_record_json = json.loads(event_record)

            # verify "eventTime" attribute
            eventTime = event_record_json["Records"][0]["eventTime"]

            # verify eventTime reflects correct timestamp. BZ:https://bugzilla.redhat.com/show_bug.cgi?id=1959254
            if "0.000000" in eventTime:
                raise EventRecordDataError("eventTime 0.000000 in event record")
            if "T" in eventTime:
                log.info(f"eventTime: {eventTime},Timestamp format validated")
            else:
                raise EventRecordDataError("eventTime: Incorrect timestamp format")

            # verify "eventName" attribute
            eventName = event_record_json["Records"][0]["eventName"]
            # s3Prefix removed with BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1966676
            if "s3:" in eventName and "nautilus" not in ceph_version:
                raise EventRecordDataError("eventName: s3 prefix present in eventName")

            # verify event record for a particular event type
            if "Delete" in event_type:
                events = ["Put", "Delete"]
            if "Copy" in event_type:
                events = ["Put", "Copy"]
            if "Multipart" in event_type:
                events = ["Post", "Put", "CompleteMultipartUpload"]
            for event in events:
                if event in eventName:
                    log.info(f"eventName: {eventName} in event record")

            # fetch bucket details and verify bucket attributes in event record
            bucket_stats = utils.exec_shell_cmd(
                "radosgw-admin bucket stats --bucket  %s" % bucket
            )
            bucket_stats_json = json.loads(bucket_stats)
            log.info("verify bucket attributes in event record")
            # verify bucket name in event record
            bucket_name = event_record_json["Records"][0]["s3"]["bucket"]["name"]
            if bucket in bucket_name:
                log.info(f"Bucket-name: {bucket_name}")
            else:
                raise EventRecordDataError("BucketName not in event record")

            # verify bucket id in event record
            bucket_id = bucket_stats_json["id"]
            bucket_id_evnt = event_record_json["Records"][0]["s3"]["bucket"]["id"]
            if bucket_id in bucket_id_evnt:
                log.info(f"Bucket-id: {bucket_id}")
            else:
                raise EventRecordDataError("BucketID not in event record")

            # verify bucket owner in event record
            bucket_owner = bucket_stats_json["owner"]
            bkt_owner_evnt = event_record_json["Records"][0]["s3"]["bucket"][
                "ownerIdentity"
            ]["principalId"]
            if bucket_owner == bkt_owner_evnt:
                log.info(f"Bucket-owner: {bucket_owner}")
            else:
                raise EventRecordDataError("BucketOwner not in event record")

            log.info("verify object attributes")
            # verify object size attribute
            size = event_record_json["Records"][0]["s3"]["object"]["size"]
            # verify object size is not 0, for the object. BZ:https://bugzilla.redhat.com/show_bug.cgi?id=1960648
            if size == 0:
                if "Post" in eventName:
                    log.info("Expected behavior")
                elif "nautilus" not in ceph_version:
                    raise EventRecordDataError("size: Object size is 0")
            else:
                log.info(f"size: {size}")

    # delete event record
    log.info("deleting local file to verify event record")
    utils.exec_shell_cmd("rm -rf %s" % event_record_path)
