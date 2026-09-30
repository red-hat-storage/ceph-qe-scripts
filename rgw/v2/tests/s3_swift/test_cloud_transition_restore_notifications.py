"""
Test S3 Object Restore Notifications with AWS Cloud Transition

This test combines the AWS cloud transition restore multipart flow with
ObjectRestore notification verification using a podman-based Kafka container.

Flow:
1. Set up podman Kafka container (KRaft mode, no ZooKeeper)
2. Create user, bucket, upload multipart objects
3. Apply LC rule → transition objects to CLOUDAWS
4. Subscribe to ObjectRestore events (Post, Completed, Delete)
5. Perform permanent restore of transitioned objects
6. Verify restore notifications received via Kafka
7. Run cloud transition bug verification
8. Tear down Kafka container

Usage:
    python test_cloud_transition_restore_notifications.py \
        -c multisite_configs/test_lc_aws_cloud_transition_restore_multipart_notifications.yaml \
        --rgw-node <IP>

Does not modify any existing test files or reusable modules.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3 import lifecycle_validation as lc_ops
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import cloud_transition_bug_checks
from v2.tests.s3_swift.reusables import s3_object_restore as reusables_s3_restore
from v2.tests.s3_swift.reusables.kafka_container import KafkaContainer
from v2.tests.s3_swift.reusables.restore_notification import RestoreNotificationService
from v2.tests.s3cmd import reusable as s3cmd_reusable
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
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    # --- Phase 1: Kafka container setup ---
    kafka = None
    if config.test_ops.get("install_kafka_container", False):
        log.info("=" * 80)
        log.info("Phase 1: Setting up podman Kafka container")
        log.info("=" * 80)
        kafka = KafkaContainer()
        kafka.setup()
        log.info(f"Kafka broker available at {kafka.get_bootstrap_server()}")

    try:
        # --- Phase 2: Ceph config and LC prerequisites ---
        log.info("=" * 80)
        log.info("Phase 2: Configuring Ceph and LC prerequisites")
        log.info("=" * 80)
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_lc_debug_interval,
            str(config.rgw_lc_debug_interval),
            ssh_con,
            set_to_all=config.test_ops.get("set_ceph_configs_to_all_daemons", False),
        )
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_lifecycle_work_time,
            str(config.rgw_lifecycle_work_time),
            ssh_con,
            set_to_all=config.test_ops.get("set_ceph_configs_to_all_daemons", False),
        )
        _, version_name = utils.get_ceph_version()
        if "nautilus" in version_name:
            ceph_conf.set_to_ceph_conf(
                "global",
                ConfigOpts.rgw_lc_max_worker,
                str(config.rgw_lc_max_worker),
                ssh_con,
            )
        else:
            ceph_conf.set_to_ceph_conf(
                section=None,
                option=ConfigOpts.rgw_lc_max_worker,
                value=str(config.rgw_lc_max_worker),
                ssh_con=ssh_con,
                set_to_all=config.test_ops.get(
                    "set_ceph_configs_to_all_daemons", False
                ),
            )
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_lc_max_wp_worker,
            str(config.rgw_lc_max_wp_worker),
            ssh_con,
            set_to_all=config.test_ops.get("set_ceph_configs_to_all_daemons", False),
        )

        if config.test_lc_transition:
            reusable.prepare_for_bucket_lc_transition(config)
        if config.enable_resharding and config.sharding_type == "dynamic":
            reusable.set_dynamic_reshard_ceph_conf(config, ssh_con)

        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")

        # --- Phase 3: Create user and bucket ---
        log.info("=" * 80)
        log.info("Phase 3: Creating user and bucket")
        log.info("=" * 80)
        config.user_count = config.user_count if config.user_count else 1
        config.bucket_count = config.bucket_count if config.bucket_count else 1

        user_info = s3lib.create_users(
            config.user_count, config.user_names, config=config
        )

        if config.test_ops.get("install_kafka_container", False):
            utils.add_service2_sdk_extras()

        for each_user in user_info:
            auth = reusable.get_auth(each_user, ssh_con, config.ssl, config.haproxy)
            rgw_conn = auth.do_auth()
            rgw_conn2 = auth.do_auth_using_client()

            for bc in range(config.bucket_count):
                if config.bucket_names:
                    bucket_name = config.bucket_names[bc]
                else:
                    bucket_name = utils.gen_bucket_name_from_userid(
                        each_user["user_id"], rand_no=bc
                    )

                if config.haproxy:
                    bucket = reusable.create_bucket(bucket_name, rgw_conn, each_user)
                else:
                    bucket = reusable.create_bucket(
                        bucket_name, rgw_conn, each_user, ip_and_port
                    )

                if config.enable_resharding and config.sharding_type == "manual":
                    reusable.bucket_reshard_manual(bucket, config)

                # Enable versioning if configured
                if config.test_ops.get("enable_versioning", False) is True:
                    log.info(f"Enabling versioning on bucket {bucket_name}")
                    reusable.enable_versioning(
                        bucket, rgw_conn, each_user, write_bucket_io_info
                    )

                # --- Phase 4: Upload objects ---
                log.info("=" * 80)
                log.info(f"Phase 4: Uploading objects to bucket {bucket_name}")
                log.info("=" * 80)
                prefix = []
                if config.lifecycle_conf:
                    prefix = list(
                        map(
                            lambda x: x,
                            [
                                rule["Filter"].get("Prefix")
                                or rule["Filter"]["And"].get("Prefix")
                                for rule in config.lifecycle_conf
                            ],
                        )
                    )
                    prefix = prefix if prefix else ["dummy1"]
                else:
                    prefix = ["dummy1"]

                obj_list = []
                object_checksums = {}
                upload_start_time = time.time()

                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    key = prefix.pop()
                    prefix.insert(0, key)
                    s3_object_name = key + "." + bucket.name + "." + str(oc)
                    obj_list.append(s3_object_name)

                    if config.test_ops.get("upload_type") == "multipart":
                        log.info(f"Uploading multipart object: {s3_object_name}")
                        reusable.upload_mutipart_object(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            each_user,
                        )
                    elif (
                        config.test_ops.get("enable_versioning", False)
                        and config.test_ops.get("version_count", 0) > 0
                    ):
                        for vc in range(config.test_ops["version_count"]):
                            log.info(f"Uploading version {vc} of {s3_object_name}")
                            reusable.upload_object(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                each_user,
                                append_data=True,
                                append_msg="hello object for version: %s\n" % str(vc),
                            )
                    else:
                        reusable.upload_object(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            each_user,
                        )

                upload_end_time = time.time()

                # Store checksums before transition
                log.info("=" * 80)
                log.info("Storing object checksums BEFORE cloud transition")
                log.info("=" * 80)
                bucket_list_op = utils.exec_shell_cmd(
                    f"radosgw-admin bucket list --bucket={bucket_name}"
                )
                json_doc_list = json.loads(bucket_list_op)

                for item in json_doc_list:
                    if item.get("tag") != "delete-marker" and "instance" in item:
                        object_key = item["name"]
                        version_id = item["instance"]
                        checksum_key = f"{object_key}:{version_id}"
                        object_checksums[
                            checksum_key
                        ] = reusables_s3_restore.store_object_checksum(
                            rgw_conn2, bucket_name, object_key, version_id
                        )

                # --- Phase 5: Apply LC rule and wait for transition ---
                log.info("=" * 80)
                log.info("Phase 5: Applying LC rule and waiting for cloud transition")
                log.info("=" * 80)
                life_cycle_rule = {"Rules": config.lifecycle_conf}
                reusable.put_get_bucket_lifecycle_test(
                    bucket,
                    rgw_conn,
                    rgw_conn2,
                    life_cycle_rule,
                    config,
                    upload_start_time,
                    upload_end_time,
                )

                target_storage_class = None
                for rule in config.lifecycle_conf:
                    if "Transitions" in rule:
                        target_storage_class = rule["Transitions"][0]["StorageClass"]
                        break

                if target_storage_class:
                    max_wait_time = 3600
                    poll_interval = 30
                    elapsed = 0
                    while elapsed < max_wait_time:
                        bucket_list_op = utils.exec_shell_cmd(
                            f"radosgw-admin bucket list --bucket={bucket_name}"
                        )
                        json_doc_list = json.loads(bucket_list_op)
                        total_objects = sum(
                            1
                            for item in json_doc_list
                            if "instance" in item and item.get("tag") != "delete-marker"
                        )
                        transitioned_objects = sum(
                            1
                            for item in json_doc_list
                            if "instance" in item
                            and item.get("tag") != "delete-marker"
                            and item.get("meta", {}).get("storage_class")
                            == target_storage_class
                        )
                        log.info(
                            f"Transition progress: {transitioned_objects}/"
                            f"{total_objects} to {target_storage_class} "
                            f"(elapsed: {elapsed}s)"
                        )
                        if transitioned_objects >= total_objects:
                            log.info(
                                f"All {total_objects} objects transitioned "
                                f"to {target_storage_class}"
                            )
                            break
                        time.sleep(poll_interval)
                        elapsed += poll_interval
                    else:
                        raise TestExecError(
                            f"Cloud transition did not complete within "
                            f"{max_wait_time}s. Only "
                            f"{transitioned_objects}/{total_objects} done."
                        )

                # Delete LC policy after transition
                if config.test_ops.get("delete_lc_after_transition", False):
                    log.info(f"Deleting LC policy for bucket {bucket_name}")
                    try:
                        rgw_conn2.delete_bucket_lifecycle(Bucket=bucket_name)
                    except Exception as e:
                        log.warning(f"Failed to delete LC policy: {e}")

                # --- Phase 6: Subscribe to restore notifications ---
                restore_notif_service = None
                if config.test_ops.get("send_restore_notifications", False) and kafka:
                    log.info("=" * 80)
                    log.info("Phase 6: Subscribing to ObjectRestore notifications")
                    log.info("=" * 80)
                    restore_notif_service = RestoreNotificationService(
                        config, auth, kafka
                    )
                    restore_notif_service.subscribe(bucket_name)
                    log.info(
                        "ObjectRestore notifications subscribed for "
                        f"bucket {bucket_name}"
                    )

                # --- Phase 7: Perform restore ---
                log.info("=" * 80)
                log.info(f"Phase 7: Restoring objects from cloud for {bucket_name}")
                log.info("=" * 80)

                bucket_list_op = utils.exec_shell_cmd(
                    f"radosgw-admin bucket list --bucket={bucket_name}"
                )
                json_doc_list = json.loads(bucket_list_op)
                objs_total = sum(1 for item in json_doc_list if "instance" in item)

                restore_tasks = []
                for i in range(objs_total):
                    if json_doc_list[i]["tag"] != "delete-marker":
                        object_key = json_doc_list[i]["name"]
                        version_id = json_doc_list[i]["instance"]
                        checksum_key = f"{object_key}:{version_id}"
                        restore_tasks.append(
                            {
                                "object_key": object_key,
                                "version_id": version_id,
                                "original_metadata": object_checksums.get(checksum_key),
                            }
                        )

                # Check restore status before restore
                restore_list_cmd = f"radosgw-admin restore list --bucket={bucket_name}"
                log.info(f"Executing: {restore_list_cmd}")
                stdin, stdout, stderr = ssh_con.exec_command(restore_list_cmd)
                restore_list_output = stdout.read().decode()
                if restore_list_output:
                    log.info(f"Restore list output:\n{restore_list_output}")

                max_workers = getattr(config, "restore_parallel_workers", 10)
                log.info(
                    f"Starting parallel restore of {len(restore_tasks)} "
                    f"objects with {max_workers} workers"
                )

                def restore_object_wrapper(task):
                    try:
                        if config.test_ops.get("permanent_restore", False):
                            log.info(
                                f"Permanent restore for {task['object_key']} "
                                f"(version: {task['version_id']})"
                            )
                            reusables_s3_restore.permanent_restore_s3_object(
                                rgw_conn2,
                                bucket_name,
                                task["object_key"],
                                task["version_id"],
                                target_storage_class="STANDARD",
                                original_metadata=task.get("original_metadata"),
                                max_wait_time=getattr(config, "restore_wait_time", 600),
                                poll_interval=getattr(
                                    config, "restore_poll_interval", 30
                                ),
                            )
                        else:
                            log.info(
                                f"Temporary restore for {task['object_key']} "
                                f"(version: {task['version_id']})"
                            )
                            reusables_s3_restore.restore_s3_object(
                                rgw_conn2,
                                each_user,
                                config,
                                bucket_name,
                                task["object_key"],
                                task["version_id"],
                                days=7,
                                max_wait_time=getattr(config, "restore_wait_time", 600),
                                poll_interval=getattr(
                                    config, "restore_poll_interval", 30
                                ),
                                original_metadata=task.get("original_metadata"),
                            )
                        return {
                            "success": True,
                            "object": task["object_key"],
                            "version": task["version_id"],
                        }
                    except Exception as e:
                        log.error(
                            f"Restore failed for {task['object_key']} "
                            f"version {task['version_id']}: {e}"
                        )
                        return {
                            "success": False,
                            "object": task["object_key"],
                            "version": task["version_id"],
                            "error": str(e),
                        }

                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {
                        executor.submit(restore_object_wrapper, task): task
                        for task in restore_tasks
                    }
                    completed = 0
                    failed = 0
                    for future in as_completed(futures):
                        result = future.result()
                        completed += 1
                        if result["success"]:
                            log.info(
                                f"Restore progress: {completed}/"
                                f"{len(restore_tasks)} - "
                                f"{result['object']}"
                            )
                        else:
                            failed += 1
                            log.error(
                                f"Restore failed: {result['object']} - "
                                f"{result['error']}"
                            )

                log.info(
                    f"Restore completed: {completed - failed}/"
                    f"{len(restore_tasks)} successful, {failed} failed"
                )
                if failed > 0:
                    raise TestExecError(
                        f"Restore failed for {failed}/" f"{len(restore_tasks)} objects"
                    )

                # Check restore status after restore
                log.info(f"Executing: {restore_list_cmd}")
                stdin, stdout, stderr = ssh_con.exec_command(restore_list_cmd)
                restore_list_output = stdout.read().decode()
                if restore_list_output:
                    log.info(f"Restore list after restore:\n{restore_list_output}")

                # --- Phase 8: Verify restore notifications ---
                if restore_notif_service:
                    log.info("=" * 80)
                    log.info("Phase 8: Verifying restore notifications")
                    log.info("=" * 80)
                    log.info("Waiting 30s for notification delivery to Kafka...")
                    time.sleep(30)
                    restore_notif_service.verify(bucket_name)
                    log.info("Restore notification verification PASSED")

                # --- Phase 9: Cloud transition bug verification ---
                if config.test_ops.get("verify_cloud_bugs", False):
                    log.info("=" * 80)
                    log.info("Phase 9: Cloud Transition Bug Verification")
                    log.info("=" * 80)

                    storage_class = None
                    for rule in config.lifecycle_conf:
                        if "Transitions" in rule:
                            storage_class = rule["Transitions"][0]["StorageClass"]
                            break

                    if storage_class:
                        sample_tasks = restore_tasks[: min(3, len(restore_tasks))]
                        for task in sample_tasks:
                            log.info(
                                f"Verifying bugs for {task['object_key']} "
                                f"(version: {task['version_id']})"
                            )
                            bug_results = cloud_transition_bug_checks.verify_cloud_transition_bugs(
                                s3_client=rgw_conn2,
                                ssh_con=ssh_con,
                                bucket_name=bucket_name,
                                object_key=task["object_key"],
                                storage_class=storage_class,
                                version_id=task["version_id"],
                                check_multipart=config.test_ops.get(
                                    "verify_multipart_bug", True
                                ),
                                check_etag=config.test_ops.get("verify_etag_bug", True),
                                check_days_zero=config.test_ops.get(
                                    "verify_days_zero_bug", False
                                ),
                            )
                            log.info(f"Bug verification results: {bug_results}")
                            for bug_name, result in bug_results.items():
                                if "FAILED" in str(result):
                                    raise TestExecError(
                                        f"Bug check failed: " f"{bug_name}: {result}"
                                    )

                        log.info("Cloud Transition Bug Verification: ALL PASSED")

                # --- Phase 10: Restore expiry check (temporary restore only) ---
                if not config.test_ops.get("permanent_restore", False):
                    log.info(
                        "Checking restored objects are not available "
                        "after restore interval"
                    )
                    time.sleep(240)
                    for task in restore_tasks:
                        reusables_s3_restore.check_restore_expiry(
                            rgw_conn2,
                            each_user,
                            config,
                            bucket_name,
                            task["object_key"],
                            task["version_id"],
                        )
                else:
                    log.info("Permanent restore — skipping expiry check")

                # Cleanup notification topic
                if restore_notif_service:
                    restore_notif_service.cleanup_topic(bucket_name)

                # Cleanup downloaded files
                log.info("Cleaning up downloaded restore files")
                for item in os.listdir("."):
                    if item.startswith(
                        ("original-", "restored-", "permanently-restored-")
                    ):
                        try:
                            os.remove(item)
                        except Exception:
                            pass

            if config.user_remove:
                reusable.remove_user(each_user)

            crash_info = reusable.check_for_crash()
            if crash_info:
                raise TestExecError("ceph daemon crash found!")

    finally:
        if kafka:
            log.info("=" * 80)
            log.info("Tearing down Kafka container")
            log.info("=" * 80)
            try:
                kafka.teardown()
            except Exception as e:
                log.warning(f"Kafka teardown failed: {e}")


if __name__ == "__main__":
    test_info = AddTestInfo("cloud transition restore with notifications")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(
            description="RGW S3 Cloud Transition Restore Notifications"
        )
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node",
            dest="rgw_node",
            help="RGW Node",
            default="127.0.0.1",
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
