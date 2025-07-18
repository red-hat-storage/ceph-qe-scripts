import json
import logging
import os
import random
import time
import timeit
import uuid
from urllib import parse as urlparse

import v2.utils.utils as utils
from v2.lib.exceptions import EventRecordDataError, TestExecError
from v2.tests.s3_swift.reusables import rgw_accounts as accounts

log = logging.getLogger()


KAFKA_HOME = "/usr/local/kafka"
Filter = {
    "Key": {
        "FilterRules": [
            {"Name": "prefix", "Value": "prefix1"},
        ]
    }
}


def get_affixed_obj_name(config, obj_name):
    filter_rules = config.test_ops["Filter"]["Key"]["FilterRules"]
    for rule in filter_rules:
        if rule["Name"] == "prefix":
            obj_name = f"{rule['Value']}{obj_name}"
        if rule["Name"] == "suffix":
            obj_name = f"{obj_name}{rule['Value']}"
    return obj_name


def start_stop_kafka_server(option):
    """
    stop/start kafka and zookeeper servers based on option provided
    """
    log.info(f"Performing kafka and zookeeper servers {option}")
    zookeeper_cmd = f"sudo {KAFKA_HOME}/bin/zookeeper-server-{option}.sh"
    kafka_cmd = f"sudo {KAFKA_HOME}/bin/kafka-server-{option}.sh"
    commands = [kafka_cmd, zookeeper_cmd]
    if option == "start":
        zookeeper_cmd = (
            f"{zookeeper_cmd} -daemon {KAFKA_HOME}/config/zookeeper.properties"
        )
        kafka_cmd = f"{kafka_cmd} -daemon {KAFKA_HOME}/config/server.properties"
        commands = [zookeeper_cmd, kafka_cmd]
    for cmd in commands:
        utils.exec_shell_cmd(cmd)
        log.info("sleeping for 30 seconds")
        time.sleep(30)
    log.info(f"kafka and zookeeper servers {option} successful")


def add_acl_authorizer_config_in_kafka_properties():
    """
    add acl authorizer config in kafka server.properties to configure acl security.
    """
    acl_config = "authorizer.class.name=kafka.security.authorizer.AclAuthorizer"
    log.info(
        f"adding acl config to {KAFKA_HOME}/config/server.properties : '{acl_config}'"
    )
    cmd = f"echo '{acl_config}' >> {KAFKA_HOME}/config/server.properties"
    utils.exec_shell_cmd(cmd)
    log.info(f"acl config added successfully to {KAFKA_HOME}/config/server.properties")


def start_kafka_broker_consumer(topic_name, event_record_path):
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

    local_ip = utils.get_localhost_ip_address()

    # start kafka consumer
    cmd = f"sudo {KAFKA_HOME}/bin/kafka-console-consumer.sh --bootstrap-server kafka://{local_ip}:9092 --from-beginning --topic {topic_name} --timeout-ms 30000 >> {event_record_path}"
    start_consumer_kafka = utils.exec_shell_cmd(cmd)
    return start_consumer_kafka


def create_topic(
    sns_client,
    endpoint,
    ack_type,
    topic_name,
    persistent_flag=False,
    security_type="PLAINTEXT",
    mechanism="PLAIN",
):
    """
    to create topic with specified endpoint , ack_level
    return: topic ARN
    """
    brokers_list = get_kafka_brokers_list()
    kafka_ip = brokers_list[0]
    kafka_port = 9092
    if security_type == "PLAINTEXT":
        endpoint_args = (
            "push-endpoint="
            + endpoint
            + f"://{kafka_ip}:9092&use-ssl=false&verify-ssl=false&kafka-ack-level="
            + ack_type
        )
        kafka_port = 9092
    elif security_type == "SSL":
        endpoint_args = (
            "push-endpoint="
            + endpoint
            + f"://{kafka_ip}:9093&use-ssl=true&verify-ssl=false&kafka-ack-level="
            + ack_type
            + "&ca-location=/usr/local/kafka/y-ca.crt"
        )
        kafka_port = 9093
    elif security_type == "SASL_SSL":
        endpoint_args = (
            "push-endpoint="
            + endpoint
            + f"://alice:alice-secret@{kafka_ip}:9094&use-ssl=true&verify-ssl=false&kafka-ack-level="
            + ack_type
            + "&ca-location=/usr/local/kafka/y-ca.crt&mechanism="
            + mechanism
        )
        kafka_port = 9094
    elif security_type == "SASL_PLAINTEXT":
        endpoint_args = (
            "push-endpoint="
            + endpoint
            + f"://alice:alice-secret@{kafka_ip}:9095&use-ssl=false&verify-ssl=false&kafka-ack-level="
            + ack_type
            + "&mechanism="
            + mechanism
        )
        kafka_port = 9095
    if persistent_flag:
        endpoint_args = endpoint_args + "&persistent=true"
    if len(brokers_list) > 1:
        brokers_with_port_list = [f"{ip}:{kafka_port}" for ip in brokers_list]
        kafka_brokers_string = ", ".join(brokers_with_port_list)
        kafka_brokers_string = f"[{kafka_brokers_string}]"
        log.info(f"kafka_brokers_list: {kafka_brokers_string}")
        endpoint_args = f"{endpoint_args}&kafka-brokers='{kafka_brokers_string}'"
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
    get the topic with specified topic_arn
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


def rgw_admin_topic_notif_ops(config, op, args, sub_command="topic"):
    """
    Perform radosgw-admin topic/notification operation with arguments passed.

    Args:
        config: Test configuration object.
        op: One of get, list, rm.
        args: Arguments for the command.
        sub_command: "topic" or "notification" (default: "topic").
    """

    if config.test_ops.get("test_via_rgw_accounts", False):
        # Fetch RGW account ID
        rgw_account_id = accounts.get_rgw_account()
        log.info(f"Testing topic {op} with RGW account: {rgw_account_id}")
        cmd = f"radosgw-admin --account-id {rgw_account_id} {sub_command} {op}"
    else:
        cmd = f"radosgw-admin {sub_command} {op}"

    # Modify bucket_name_to_create if tenant_name is present
    if config.test_ops.get("tenant_name") and "bucket" in args:
        tenant_name = config.test_ops.get("tenant_name")
        args["bucket"] = f"{tenant_name}/{args['bucket']}"

    for arg, val in args.items():
        cmd = f"{cmd} --{arg} {val}"

    out = utils.exec_shell_cmd(cmd)
    log.info(out)

    if out is False:
        log.info(f"{sub_command} {op} using rgw CLI failed")
        return False

    log.info(f"{sub_command} {op} using rgw CLI is successful")

    if out:
        out = json.loads(out)

    return out


def get_kafka_brokers_list():
    """
    returns kafka brokers ip as list based on 'zookeepers.connect' config in server.properties
    """
    log.info(
        "get kafka brokers list from server.properties based on zookeeper.connect config"
    )
    local_ip = utils.get_localhost_ip_address()
    cmd = "cat /usr/local/kafka/config/server.properties | grep 'zookeeper.connect='"
    zookeeper_connect_string = utils.exec_shell_cmd(cmd)
    zookeeper_connect_string = zookeeper_connect_string.strip()
    zookeeper_connect_string = zookeeper_connect_string.replace(
        "zookeeper.connect=", "", 1
    )
    ip_and_port_list = zookeeper_connect_string.split(",")
    kafka_brokers_list = []
    for ip_and_port in ip_and_port_list:
        kafka_broker_ip = ip_and_port.replace(":2181", "")
        if kafka_broker_ip == "localhost":
            kafka_broker_ip = local_ip
        kafka_brokers_list.append(kafka_broker_ip)
    return kafka_brokers_list


def create_topic_from_kafka_broker(topic_name, partitions=2, replication_factor=2):
    """
    delete topic from kafka broker
    """
    log.info(f"create partitioned topic {topic_name} using kafka-cli")
    kafka_brokers = get_kafka_brokers_list()
    kafka_broker1_ip = kafka_brokers[0]
    cmd = f"/usr/local/kafka/bin/kafka-topics.sh --create --topic {topic_name} --bootstrap-server kafka://{kafka_broker1_ip}:9092"
    if len(kafka_brokers) > 1:
        cmd = (
            f"{cmd} --partitions {partitions} --replication-factor {replication_factor}"
        )
    out = utils.exec_shell_cmd(cmd)
    log.info(f"create topic response: {out}")
    if out is False:
        raise TestExecError(f"create topic using kafka-cli failed")
    cmd = f"/usr/local/kafka/bin/kafka-topics.sh --describe --topic {topic_name} --bootstrap-server kafka://{kafka_broker1_ip}:9092"
    out = utils.exec_shell_cmd(cmd)
    log.info(f"describe topic response: {out}")
    if out is False:
        raise TestExecError(f"describe topic using kafka-cli failed")


def del_topic_from_kafka_broker(topic_name):
    """
    delete topic from kafka broker
    """
    log.info(f"delete topic {topic_name} from kafka broker")
    cmd = f"rm -rf /tmp/kafka-logs/{topic_name}"
    utils.exec_shell_cmd(cmd)


def put_bucket_notification(
    rgw_s3_client, bucketname, notification_name, topic_arn, events, config=None
):
    """
    put bucket notification on bucket for specified events with given endpoint and topic
    """
    log.info(f"put bucket notification on {bucketname}")
    TopicConfigurations = [
        {
            "Id": notification_name,
            "TopicArn": topic_arn,
            "Events": events,
        }
    ]
    if config and config.test_ops.get("Filter"):
        TopicConfigurations[0]["Filter"] = config.test_ops.get("Filter")
    put_bkt_notification = rgw_s3_client.put_bucket_notification_configuration(
        Bucket=bucketname,
        NotificationConfiguration={"TopicConfigurations": TopicConfigurations},
    )
    if put_bkt_notification is False:
        raise TestExecError("put bucket notification failed")


def put_empty_bucket_notification(rgw_s3_client, bucketname):
    """
    put empty bucket notification. Ref BZ: https://bugzilla.redhat.com/show_bug.cgi?id=2017389
    """
    log.info(f"put empty bucket notification on {bucketname}")
    put_empty_bkt_notification = rgw_s3_client.put_bucket_notification_configuration(
        Bucket=bucketname,
        NotificationConfiguration={},
    )
    if put_empty_bkt_notification is False:
        raise TestExecError("put empty bucket notifcation failed")
    get_bucket_notification(rgw_s3_client, bucketname, empty=True)


def get_bucket_notification(rgw_s3_client, bucketname, empty=False):
    """
    get bucket notification for a given bucket
    """
    get_bkt_notification = rgw_s3_client.get_bucket_notification_configuration(
        Bucket=bucketname
    )
    if get_bkt_notification is False:
        if not empty:
            raise TestExecError(
                f"failed to get bucket notification for bucket : {bucketname}"
            )
    get_bucket_notification_json = json.dumps(get_bkt_notification, indent=2)
    log.info(
        f"bucket notification for bucket: {bucketname} is {get_bucket_notification_json}"
    )


def verify_event_record(
    event_type, bucket, event_record_path, ceph_version, config=None
):
    """
    verify event records
    """
    if os.path.getsize(event_record_path) == 0:
        if config and config.test_ops.get("test_delete_object_sync_archive", False):
            log.info("event record not generated! File is empty, expected behavior")
        elif config and config.test_ops.get("expected_event_record_empty", False):
            log.info("event record not generated! File is empty, expected behavior")
            return
        else:
            raise EventRecordDataError("event record not generated! File is empty")

    # verify event record for a particular event type
    ceph_version_id, _ = utils.get_ceph_version()
    ceph_version_id = ceph_version_id.split("-")
    ceph_version_id = ceph_version_id[0].split(".")
    if float(ceph_version_id[0]) >= 19:
        non_current = "NonCurrent"
    else:
        non_current = "Noncurrent"
    notifications_received = False
    events = []
    if "Delete" in event_type:
        events = [
            "ObjectRemoved:Delete",
            "ObjectRemoved:DeleteMarkerCreated",
        ]
    if "Copy" in event_type:
        events = ["ObjectCreated:Copy"]
    if "Multipart" in event_type:
        events = [
            "ObjectCreated:Post",
            "ObjectCreated:Put",
            "ObjectCreated:CompleteMultipartUpload",
        ]
    if "LifecycleExpiration" in event_type:
        events = [
            "ObjectLifecycle:Expiration:Current",
            f"ObjectLifecycle:Expiration:{non_current}",
            "ObjectLifecycle:Expiration:DeleteMarker",
            "ObjectLifecycle:Expiration:AbortMultipartUpload",
        ]
    if "LifecycleTransition" in event_type:
        events = [
            "ObjectLifecycle:Transition:Current",
            f"ObjectLifecycle:Transition:{non_current}",
        ]
    if "MultisiteReplication" in event_type:
        events = ["ObjectSynced:Create"]
    log.info(f"verifying event record for event type {event_type}")
    log.info(f"valid event names are :{events}")

    # Determine if the bucket has a tenant
    if "." in bucket and "tenant" in bucket:
        tenant_name, bucket_short_name = bucket.split(".", 1)
        if "/" in bucket:
            bucket_stats_name = bucket
        else:
            bucket_stats_name = f"{tenant_name}/{bucket}"
    else:
        bucket_stats_name = bucket

    # fetch bucket details and verify bucket attributes in event record
    bucket_stats = utils.exec_shell_cmd(
        "radosgw-admin bucket stats --bucket %s" % bucket_stats_name
    )
    bucket_stats_json = json.loads(bucket_stats)

    # to verify the zonegroup with awsregion in event record
    zonegroup_get = utils.exec_shell_cmd("radosgw-admin zonegroup get")
    zonegroup_get_json = json.loads(zonegroup_get)
    zonegroup_name = zonegroup_get_json["name"]

    # read the file event_record
    with open(event_record_path, "r") as records:
        for record in records:
            event_record = record.strip()
            log.info(f" event record \n {record}")
            event_record_json = json.loads(event_record)

            # verify "eventName" attribute
            eventName = event_record_json["Records"][0]["eventName"]
            for event in events:
                if event in eventName:
                    log.info(f"eventName: {eventName} in event record")
                    notifications_received = True
                    break
            else:
                log.info(
                    f"skipping this event record as this is not of event_type: {event_type}"
                )
                continue
            # s3Prefix removed with BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1966676
            if "s3:" in eventName and "nautilus" not in ceph_version:
                raise EventRecordDataError("eventName: s3 prefix present in eventName")

            # verify "eventTime" attribute
            eventTime = event_record_json["Records"][0]["eventTime"]

            # verify eventTime reflects correct timestamp. BZ:https://bugzilla.redhat.com/show_bug.cgi?id=1959254
            if "0.000000" in eventTime:
                raise EventRecordDataError("eventTime 0.000000 in event record")
            if "T" in eventTime:
                log.info(f"eventTime: {eventTime},Timestamp format validated")
            else:
                raise EventRecordDataError("eventTime: Incorrect timestamp format")

            log.info("verify bucket attributes in event record")
            # verify bucket name in event record
            bucket_name = event_record_json["Records"][0]["s3"]["bucket"]["name"]

            bkt_name = bucket.split("/")[-1] if "/" in bucket else bucket
            if bkt_name == bucket_name:
                log.info(f"Bucket-name: {bucket_name}")
            else:
                raise EventRecordDataError(f"BucketName {bkt_name} not in event record")

            # verify bucket id in event record
            bucket_id = bucket_stats_json["id"]
            bucket_id_evnt = event_record_json["Records"][0]["s3"]["bucket"]["id"]
            if bucket_id in bucket_id_evnt:
                log.info(f"Bucket-id: {bucket_id}")
            else:
                raise EventRecordDataError(f"BucketID {bucket_id} not in event record")

            # verify bucket owner in event record
            bucket_owner = bucket_stats_json["owner"]

            if "$" in bucket_owner and int(ceph_version_id[0]) < 19:
                bucket_owner = bucket_owner.split("$")[-1]

            bkt_owner_evnt = event_record_json["Records"][0]["s3"]["bucket"][
                "ownerIdentity"
            ]["principalId"]
            if bucket_owner == bkt_owner_evnt:
                log.info(f"Bucket-owner: {bucket_owner}")
            else:
                raise EventRecordDataError(
                    f"BucketOwner {bucket_owner} not in event record"
                )

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
            log.info(f"size: {size}")

            awsRegion = event_record_json["Records"][0]["awsRegion"]
            # verify awsRegion in event record is the zonegroup ref BZ: https://bugzilla.redhat.com/show_bug.cgi?id=2004171
            if awsRegion == zonegroup_name:
                log.info(f"awsRegion: {awsRegion}")
            else:
                raise EventRecordDataError("awsRegion not in event record")
    if notifications_received is False:
        if config.test_ops.get("test_delete_object_sync_archive", False):
            log.info("Deletion event does not occur in archive zone")
            log.info(
                "Notifications not received for event type {event_type}, expected behavior with archive zone"
            )
        else:
            raise EventRecordDataError(
                f"Notifications not received for event type {event_type}"
            )


class NotificationService:
    config = None
    auth = None
    rgw_sns_conn = None
    rgw_s3_client = None
    ceph_version_id = None
    ceph_version_name = None
    topic_detials = lambda topic_name, events: {
        "topic_name": topic_name,
        "events": events,
    }
    bucket_topic_map = {}

    def __init__(self, config, auth):
        self.config = config
        self.auth = auth
        # authenticate sns client.
        self.rgw_sns_conn = auth.do_auth_sns_client()

        # authenticate with s3 client
        self.rgw_s3_client = auth.do_auth_using_client()

        # get ceph version
        self.ceph_version_id, self.ceph_version_name = utils.get_ceph_version()

    def apply(self, bucket_name, events):
        endpoint = self.config.test_ops.get("endpoint")
        ack_type = self.config.test_ops.get("ack_type")
        topic_id = str(uuid.uuid4().hex[:16])
        persistent = False
        topic_name = "cephci-kafka-" + ack_type + "-ack-type-" + topic_id
        log.info(f"creating a topic with {endpoint} endpoint with ack type {ack_type}")
        if self.config.test_ops.get("persistent_flag", False):
            log.info("topic with peristent flag enabled")
            persistent = self.config.test_ops.get("persistent_flag")
        topic = create_topic(
            self.rgw_sns_conn, endpoint, ack_type, topic_name, persistent
        )
        self.bucket_topic_map[bucket_name] = self.__class__.topic_detials(
            topic_name, events
        )

        # get topic attributes
        log.info("get topic attributes")
        get_topic(self.rgw_sns_conn, topic, self.ceph_version_name)

        # put bucket notification with topic configured for event
        event = self.config.test_ops.get("event_type")
        notification_name = "notification-" + str(event)
        put_bucket_notification(
            self.rgw_s3_client,
            bucket_name,
            notification_name,
            topic,
            events,
        )

        # get bucket notification
        log.info(f"get bucket notification for bucket : {bucket_name}")
        get_bucket_notification(self.rgw_s3_client, bucket_name)

    def verify(self, bucket_name):
        # start kafka broker and consumer
        event_record_path = "/tmp/event_record"
        topic_name = self.bucket_topic_map[bucket_name]["topic_name"]
        event = self.config.test_ops.get("event_type")
        start_consumer = start_kafka_broker_consumer(topic_name, event_record_path)
        if start_consumer is False:
            raise Exception("Kafka consumer not running")

        # verify all the attributes of the event record. if event not received abort testcase
        log.info("verify event record attributes")
        verify = verify_event_record(
            event, bucket_name, event_record_path, self.ceph_version_name, self.config
        )
        if verify is False:
            raise EventRecordDataError(
                "Event record is empty! notification is not seen"
            )
