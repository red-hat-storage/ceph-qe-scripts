"""
S3 Object Restore Notification Support for RGW

Handles setup and verification of ObjectRestore event notifications
(s3:ObjectRestore:Post, s3:ObjectRestore:Completed, s3:ObjectRestore:Delete)
using a podman-based Kafka container via KafkaContainer.

Does not modify or depend on the existing bucket_notification.py module.

Usage:
    from v2.tests.s3_swift.reusables.kafka_container import KafkaContainer
    from v2.tests.s3_swift.reusables.restore_notification import (
        RestoreNotificationService,
    )

    kafka = KafkaContainer()
    kafka.setup()

    service = RestoreNotificationService(config, auth, kafka)
    service.subscribe(bucket_name)
    # ... perform restore operations ...
    service.verify(bucket_name)

    kafka.teardown()
"""

import json
import logging
import os
import uuid
from urllib import parse as urlparse

import v2.utils.utils as utils
from v2.lib.exceptions import EventRecordDataError, TestExecError

log = logging.getLogger()

RESTORE_EVENT_RECORD_PATH = "/tmp/event_record_restore"

RESTORE_EVENTS = [
    "s3:ObjectRestore:Initiated",
    "s3:ObjectRestore:Completed",
    "s3:ObjectRestore:Expired",
]

RESTORE_EVENT_NAMES = [
    "ObjectRestore:Initiated",
    "ObjectRestore:Completed",
    "ObjectRestore:Expired",
]


class RestoreNotificationService:
    def __init__(self, config, auth, kafka_container):
        self.config = config
        self.auth = auth
        self.kafka = kafka_container

        self.rgw_sns_conn = auth.do_auth_sns_client()
        self.rgw_s3_client = auth.do_auth_using_client()
        self.ceph_version_id, self.ceph_version_name = utils.get_ceph_version()

        self.bucket_topic_map = {}

    def subscribe(self, bucket_name):
        """
        Create a Kafka topic for restore events and configure bucket notification
        to send ObjectRestore events to it.
        """
        endpoint = self.config.test_ops.get("endpoint", "kafka")
        ack_type = self.config.test_ops.get("restore_ack_type", "broker")
        persistent = self.config.test_ops.get("restore_persistent_flag", True)

        topic_id = str(uuid.uuid4().hex[:16])
        topic_name = f"restore-notif-{ack_type}-{topic_id}"

        log.info(f"Creating SNS topic '{topic_name}' for restore notifications")
        topic_arn = self._create_sns_topic(endpoint, ack_type, topic_name, persistent)

        self.bucket_topic_map[bucket_name] = {
            "topic_name": topic_name,
            "topic_arn": topic_arn,
            "events": RESTORE_EVENTS,
        }

        self._get_topic_attributes(topic_arn)

        notification_name = f"notification-restore-{topic_id}"
        self._put_bucket_notification(
            bucket_name, notification_name, topic_arn, RESTORE_EVENTS
        )

        self._get_bucket_notification(bucket_name)
        log.info(
            f"Restore notifications subscribed for bucket '{bucket_name}' "
            f"on topic '{topic_name}'"
        )

    def verify(self, bucket_name, event_record_path=None):
        """
        Start Kafka consumer for the restore topic and verify received events.
        """
        if bucket_name not in self.bucket_topic_map:
            raise TestExecError(
                f"No restore notification topic for bucket '{bucket_name}'. "
                f"Call subscribe() first."
            )

        record_path = event_record_path or RESTORE_EVENT_RECORD_PATH
        topic_name = self.bucket_topic_map[bucket_name]["topic_name"]

        log.info(f"Starting Kafka consumer for restore events on topic '{topic_name}'")
        result = self.kafka.start_consumer(topic_name, record_path)
        if result is False:
            raise TestExecError("Kafka consumer failed for restore events")

        log.info("Verifying restore event records")
        self._verify_restore_events(bucket_name, record_path)
        log.info(f"Restore notification verification passed for '{bucket_name}'")

    def cleanup_topic(self, bucket_name):
        """
        Delete the Kafka topic for a bucket's restore notifications.
        """
        if bucket_name in self.bucket_topic_map:
            topic_name = self.bucket_topic_map[bucket_name]["topic_name"]
            topic_arn = self.bucket_topic_map[bucket_name]["topic_arn"]
            try:
                self.kafka.delete_topic(topic_name)
            except Exception as e:
                log.warning(f"Failed to delete Kafka topic '{topic_name}': {e}")
            try:
                self.rgw_sns_conn.delete_topic(TopicArn=topic_arn)
            except Exception as e:
                log.warning(f"Failed to delete SNS topic '{topic_arn}': {e}")
            del self.bucket_topic_map[bucket_name]

    def _create_sns_topic(self, endpoint, ack_type, topic_name, persistent):
        kafka_ip = self.kafka.broker_ip or utils.get_localhost_ip_address()
        kafka_port = self.kafka.kafka_port

        endpoint_args = (
            f"push-endpoint={endpoint}://{kafka_ip}:{kafka_port}"
            f"&use-ssl=false&verify-ssl=false"
            f"&kafka-ack-level={ack_type}"
        )
        if persistent:
            endpoint_args += "&persistent=true"

        attributes = {
            nvp[0]: nvp[1]
            for nvp in urlparse.parse_qsl(endpoint_args, keep_blank_values=True)
        }
        response = self.rgw_sns_conn.create_topic(
            Name=topic_name, Attributes=attributes
        )
        topic_arn = response["TopicArn"]
        log.info(f"SNS topic created, ARN: {topic_arn}")
        return topic_arn

    def _get_topic_attributes(self, topic_arn):
        if "nautilus" in self.ceph_version_name:
            return
        info = self.rgw_sns_conn.get_topic_attributes(TopicArn=topic_arn)
        log.info(f"Topic attributes: {json.dumps(info, indent=2)}")

    def _put_bucket_notification(
        self, bucket_name, notification_name, topic_arn, events
    ):
        log.info(f"Configuring bucket notification on '{bucket_name}'")
        self.rgw_s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                "TopicConfigurations": [
                    {
                        "Id": notification_name,
                        "TopicArn": topic_arn,
                        "Events": events,
                    }
                ]
            },
        )

    def _get_bucket_notification(self, bucket_name):
        response = self.rgw_s3_client.get_bucket_notification_configuration(
            Bucket=bucket_name
        )
        log.info(
            f"Bucket notification config for '{bucket_name}': "
            f"{json.dumps(response, indent=2)}"
        )

    def _verify_restore_events(self, bucket_name, event_record_path):
        if not os.path.exists(event_record_path):
            raise EventRecordDataError(
                f"Event record file not found: {event_record_path}"
            )

        if os.path.getsize(event_record_path) == 0:
            raise EventRecordDataError(
                "Restore event record file is empty — no notifications received"
            )

        bucket_stats = utils.exec_shell_cmd(
            f"radosgw-admin bucket stats --bucket {bucket_name}"
        )
        bucket_stats_json = json.loads(bucket_stats)

        zonegroup_get = utils.exec_shell_cmd("radosgw-admin zonegroup get")
        zonegroup_json = json.loads(zonegroup_get)
        zonegroup_name = zonegroup_json["name"]

        ceph_version_id = self.ceph_version_id.split("-")[0].split(".")

        events_found = set()
        with open(event_record_path, "r") as records:
            for record in records:
                event_record = record.strip()
                if not event_record:
                    continue
                log.info(f"Restore event record: {event_record}")
                event_json = json.loads(event_record)

                event_name = event_json["Records"][0]["eventName"]

                matched = False
                for expected in RESTORE_EVENT_NAMES:
                    if expected in event_name:
                        events_found.add(expected)
                        matched = True
                        break

                if not matched:
                    log.info(f"Skipping non-restore event: {event_name}")
                    continue

                if "s3:" in event_name and "nautilus" not in self.ceph_version_name:
                    raise EventRecordDataError(
                        f"eventName has s3: prefix: {event_name}"
                    )

                event_time = event_json["Records"][0]["eventTime"]
                if "0.000000" in event_time:
                    raise EventRecordDataError(
                        f"eventTime is 0.000000 in restore event record"
                    )
                if "T" not in event_time:
                    raise EventRecordDataError(
                        f"eventTime incorrect format: {event_time}"
                    )

                bucket_info = event_json["Records"][0]["s3"]["bucket"]
                bkt_name = (
                    bucket_name.split("/")[-1] if "/" in bucket_name else bucket_name
                )
                if bkt_name != bucket_info["name"]:
                    raise EventRecordDataError(
                        f"Bucket name mismatch: expected {bkt_name}, "
                        f"got {bucket_info['name']}"
                    )

                bucket_id = bucket_stats_json["id"]
                if bucket_id not in bucket_info["id"]:
                    raise EventRecordDataError(
                        f"Bucket ID mismatch: expected {bucket_id}"
                    )

                bucket_owner = bucket_stats_json["owner"]
                if "$" in bucket_owner and int(ceph_version_id[0]) < 19:
                    bucket_owner = bucket_owner.split("$")[-1]
                evnt_owner = bucket_info["ownerIdentity"]["principalId"]
                if bucket_owner != evnt_owner:
                    raise EventRecordDataError(
                        f"Bucket owner mismatch: expected {bucket_owner}, "
                        f"got {evnt_owner}"
                    )

                aws_region = event_json["Records"][0]["awsRegion"]
                if aws_region != zonegroup_name:
                    raise EventRecordDataError(
                        f"awsRegion mismatch: expected {zonegroup_name}, "
                        f"got {aws_region}"
                    )

        if not events_found:
            raise EventRecordDataError("No ObjectRestore events found in event records")

        log.info(f"Restore events verified: {events_found}")

        permanent = self.config.test_ops.get("permanent_restore", False)
        if permanent:
            expected = {"ObjectRestore:Initiated", "ObjectRestore:Completed"}
        else:
            expected = set(RESTORE_EVENT_NAMES)

        missing = expected - events_found
        if missing:
            log.warning(
                f"Expected restore events not received: {missing}. "
                f"Received: {events_found}"
            )
        else:
            log.info(f"All expected restore events received: {expected}")
