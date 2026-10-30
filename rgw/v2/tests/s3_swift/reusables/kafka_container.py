"""
Kafka Container Management for RGW Event Notification Tests

Provides podman-based Kafka broker setup with ZooKeeper, consistent with
the bare-metal Kafka setup used in cephci (utility/utils.py).

Uses the same port conventions:
  - ZooKeeper: 2181
  - Kafka PLAINTEXT: 9092

Self-contained — does not modify or depend on the bare-metal Kafka setup
in bucket_notification.py or cephci.

Usage:
    from v2.tests.s3_swift.reusables.kafka_container import KafkaContainer

    kafka = KafkaContainer()
    kafka.setup()
    # ... run tests ...
    kafka.teardown()
"""

import logging
import os
import time

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError

log = logging.getLogger()

ZOOKEEPER_IMAGE = "docker.io/confluentinc/cp-zookeeper:7.6.0"
KAFKA_IMAGE = "docker.io/confluentinc/cp-kafka:7.6.0"
KAFKA_BIN_PATH = "/usr/bin"


class KafkaContainer:
    def __init__(
        self,
        zookeeper_name="zookeeper",
        kafka_name="kafka-broker",
        zookeeper_port=2181,
        kafka_port=9092,
        zookeeper_image=None,
        kafka_image=None,
    ):
        self.zookeeper_name = zookeeper_name
        self.kafka_name = kafka_name
        self.zookeeper_port = zookeeper_port
        self.kafka_port = kafka_port
        self.zookeeper_image = zookeeper_image or ZOOKEEPER_IMAGE
        self.kafka_image = kafka_image or KAFKA_IMAGE
        self.broker_ip = None
        self._running = False

    def setup(self):
        log.info(
            f"Setting up podman Kafka + ZooKeeper containers "
            f"(ZK port: {self.zookeeper_port}, Kafka port: {self.kafka_port})"
        )

        which_podman = utils.exec_shell_cmd("which podman")
        if which_podman is False or not str(which_podman).strip():
            raise TestExecError("podman is not installed on this node")

        self._cleanup_existing()
        self.broker_ip = utils.get_localhost_ip_address()

        # Start ZooKeeper container
        log.info(f"Starting ZooKeeper container '{self.zookeeper_name}'")
        zk_cmd = (
            f"podman run -d --name {self.zookeeper_name} --network host"
            f" -e ZOOKEEPER_CLIENT_PORT={self.zookeeper_port}"
            f" -e ZOOKEEPER_TICK_TIME=2000"
            f" {self.zookeeper_image}"
        )
        out = utils.exec_shell_cmd(zk_cmd)
        if out is False:
            raise TestExecError("Failed to start ZooKeeper container")

        log.info("Waiting 15s for ZooKeeper to start...")
        time.sleep(15)

        # Start Kafka broker container
        log.info(f"Starting Kafka broker container '{self.kafka_name}'")
        kafka_cmd = (
            f"podman run -d --name {self.kafka_name} --network host"
            f" -e KAFKA_BROKER_ID=0"
            f" -e KAFKA_ZOOKEEPER_CONNECT={self.broker_ip}:{self.zookeeper_port}"
            f" -e KAFKA_LISTENERS=PLAINTEXT://{self.broker_ip}:{self.kafka_port}"
            f" -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://{self.broker_ip}:{self.kafka_port}"
            f" -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1"
            f" -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1"
            f" -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1"
            f" {self.kafka_image}"
        )
        out = utils.exec_shell_cmd(kafka_cmd)
        if out is False:
            raise TestExecError("Failed to start Kafka broker container")

        self._wait_for_ready()
        self._running = True
        log.info(
            f"Kafka container ready at {self.broker_ip}:{self.kafka_port} "
            f"(ZooKeeper at {self.broker_ip}:{self.zookeeper_port})"
        )
        return self.broker_ip

    def teardown(self):
        log.info(
            f"Tearing down Kafka container '{self.kafka_name}' "
            f"and ZooKeeper container '{self.zookeeper_name}'"
        )
        self._cleanup_existing()
        self._running = False
        log.info("Kafka and ZooKeeper containers removed")

    def is_running(self):
        out = utils.exec_shell_cmd(
            f"podman inspect --format '{{{{.State.Running}}}}' "
            f"{self.kafka_name} 2>/dev/null"
        )
        return out and "true" in str(out).lower()

    def get_bootstrap_server(self):
        if not self.broker_ip:
            self.broker_ip = utils.get_localhost_ip_address()
        return f"{self.broker_ip}:{self.kafka_port}"

    def create_topic(self, topic_name):
        log.info(f"Creating Kafka topic '{topic_name}' via container CLI")
        cmd = (
            f"podman exec {self.kafka_name} {KAFKA_BIN_PATH}/kafka-topics"
            f" --create --topic {topic_name}"
            f" --bootstrap-server {self.broker_ip}:{self.kafka_port}"
            f" --partitions 1 --replication-factor 1"
        )
        out = utils.exec_shell_cmd(cmd)
        if out is False:
            raise TestExecError(f"Failed to create Kafka topic '{topic_name}'")
        log.info(f"Topic '{topic_name}' created successfully")

    def delete_topic(self, topic_name):
        log.info(f"Deleting Kafka topic '{topic_name}' via container CLI")
        cmd = (
            f"podman exec {self.kafka_name} {KAFKA_BIN_PATH}/kafka-topics"
            f" --delete --topic {topic_name}"
            f" --bootstrap-server {self.broker_ip}:{self.kafka_port}"
        )
        utils.exec_shell_cmd(cmd)
        log.info(f"Topic '{topic_name}' deleted")

    def start_consumer(self, topic_name, output_path, timeout_ms=30000):
        if os.path.isfile(output_path):
            log.info(f"Removing stale event record file: {output_path}")
            os.remove(output_path)

        log.info(
            f"Starting Kafka consumer for topic '{topic_name}', "
            f"output to {output_path}"
        )
        cmd = (
            f"podman exec {self.kafka_name} {KAFKA_BIN_PATH}/"
            f"kafka-console-consumer"
            f" --bootstrap-server {self.broker_ip}:{self.kafka_port}"
            f" --from-beginning --topic {topic_name}"
            f" --timeout-ms {timeout_ms} >> {output_path}"
        )
        result = utils.exec_shell_cmd(cmd)
        return result

    def _wait_for_ready(self, max_wait=90, poll_interval=5):
        log.info("Waiting for Kafka broker readiness...")
        elapsed = 0
        while elapsed < max_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval
            check = utils.exec_shell_cmd(
                f"podman exec {self.kafka_name} "
                f"{KAFKA_BIN_PATH}/kafka-broker-api-versions"
                f" --bootstrap-server {self.broker_ip}:{self.kafka_port}"
                f" 2>/dev/null"
            )
            if check and check is not False:
                log.info(f"Kafka broker ready after {elapsed}s")
                return
            log.info(f"Kafka not ready yet... ({elapsed}s/{max_wait}s)")
        raise TestExecError(f"Kafka container did not become ready within {max_wait}s")

    def _cleanup_existing(self):
        for name in [self.kafka_name, self.zookeeper_name]:
            utils.exec_shell_cmd(f"podman stop {name} 2>/dev/null || true")
            utils.exec_shell_cmd(f"podman rm {name} 2>/dev/null || true")
