""" test_Mbuckets_with_Nobjects.py - Test with M buckets and N objects

Usage: test_Mbuckets_with_Nobjects.py -c <input_yaml>

<input_yaml>
	Note: Any one of these yamls can be used
	test_Mbuckets_with_Nobjects.yaml
	test_Mbuckets_with_Nobjects_download.yaml
	test_Mbuckets_with_Nobjects_aws4.yaml
	test_Mbuckets_with_Nobjects_compression.yaml
	test_Mbuckets_with_Nobjects_delete.yaml
	test_Mbuckets_with_Nobjects_enc.yaml
	test_Mbuckets_with_Nobjects_multipart.yaml
	test_Mbuckets_with_Nobjects_sharding.yaml
	test_gc_list.yaml
	test_multisite_manual_resharding_greenfield.yaml
	test_multisite_dynamic_resharding_greenfield.yaml
	test_gc_list_multipart.yaml
	test_Mbuckets_with_Nobjects_etag.yaml
	test_changing_data_log_num_shards_cause_no_crash.yaml
    test_bi_put_with_incomplete_multipart_upload.yaml

Operation:
	Creates M bucket and N objects
	Creates M bucket and N objects. Verify checksum of the downloaded objects
	Creates M bucket and N objects. Verify authentication signature_version:s3v4
	Creates M bucket and N objects. With compression enabled.
	Creates M bucket and N objects. Verify object delete succeeds.
	Creates M bucket and N objects. With encryption enabled.
	Creates M bucket and N objects. Upload multipart object.
	Creates M bucket and N objects. With sharding set to max_shards as specified in the config
	Verify gc command
	Verify eTag
 	Verify bi put on incomplete multipart upload
"""
# test basic creation of buckets with objects
import os
import subprocess as sp
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import hashlib
import json
import logging
import time
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None
password = "32characterslongpassphraseneeded".encode("utf-8")
encryption_key = hashlib.md5(password).hexdigest()


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # create user
    if config.dbr_scenario == "brownfield":
        user_brownfiled = "brownfield_user"
        all_users_info = s3lib.create_users(config.user_count, user_brownfiled)
    else:
        if config.user_type == "tenanted":
            all_users_info = s3lib.create_tenant_users(
                no_of_users_to_create=config.user_count, tenant_name="tenant1"
            )
        else:
            all_users_info = s3lib.create_users(config.user_count)

    if config.test_ops.get("encryption_algorithm", None) is not None:
        log.info("encryption enabled, making ceph config changes")
        ceph_conf.set_to_ceph_conf(
            "global", ConfigOpts.rgw_crypt_require_ssl, "false", ssh_con
        )
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted")
    if config.test_ops.get("change_data_log_num_shards", False) is True:
        data_log_num_shards = config.test_ops.get("data_log_num_shards")
        log.info(f"changing value of rgw_data_log_num_shards to {data_log_num_shards}")
        log.info("making changes to ceph.conf")
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_data_log_num_shards,
            int(data_log_num_shards),
            ssh_con,
        )
        log.info("trying to restart services ")
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted")
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl, haproxy=config.haproxy)
        if config.use_aws4 is True:
            rgw_conn = auth.do_auth(**{"signature_version": "s3v4"})
        else:
            rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()
        # Test multisite sync with 0 shards bugs 2188022, 2180549 Hot Fix for Square eCommerce
        if config.test_sync_0_shards:
            reusable.sync_test_0_shards(config)

        # enabling sharding
        if config.test_ops["sharding"]["enable"] is True:
            log.info("enabling sharding on buckets")
            max_shards = config.test_ops["sharding"]["max_shards"]
            log.info("making changes to ceph.conf")
            ceph_conf.set_to_ceph_conf(
                "global",
                ConfigOpts.rgw_override_bucket_index_max_shards,
                str(max_shards),
                ssh_con,
            )
            log.info("trying to restart services ")
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(30)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")
        if config.test_ops["compression"]["enable"] is True:
            compression_type = config.test_ops["compression"]["type"]
            log.info("enabling compression")
            cmd = "radosgw-admin zone get"
            out = utils.exec_shell_cmd(cmd)
            zone = json.loads(out)
            zone = zone.get("name")
            cmd = (
                "radosgw-admin zone placement modify --rgw-zone=%s "
                "--placement-id=default-placement --compression=%s"
                % (zone, compression_type)
            )
            out = utils.exec_shell_cmd(cmd)
            ceph_version = utils.exec_shell_cmd("ceph version").split()[4]
            try:
                data = json.loads(out)
                if ceph_version == "luminous":
                    if (
                        data["placement_pools"][0]["val"]["compression"]
                        == compression_type
                    ):
                        log.info("Compression enabled successfully")
                    else:
                        log.error("Compression is not enabled on cluster")
                        raise TestExecError("Compression is not enabled on cluster")

                else:
                    if (
                        data["placement_pools"][0]["val"]["storage_classes"][
                            "STANDARD"
                        ]["compression_type"]
                        == compression_type
                    ):
                        log.info("Compression enabled successfully")
                    else:
                        log.error("Compression is not enabled on cluster")
                        raise TestExecError("Compression is not enabled on cluster")

            except ValueError as e:
                log.error(e)
                exit(str(e))
            log.info("trying to restart rgw services ")
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(10)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")
        if config.gc_verification is True:
            conf = config.ceph_conf
            reusable.set_gc_conf(ceph_conf, conf)
        if config.dynamic_resharding is True:
            if utils.check_dbr_support():
                log.info("making changes to ceph.conf")
                ceph_conf.set_to_ceph_conf(
                    "global",
                    ConfigOpts.rgw_max_objs_per_shard,
                    str(config.max_objects_per_shard),
                    ssh_con,
                )
                srv_restarted = rgw_service.restart(ssh_con)
        if config.bucket_sync_run_with_disable_sync_thread:
            log.info("making changes to ceph.conf")
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_run_sync_thread, "false", ssh_con
            )
            srv_restarted = rgw_service.restart(ssh_con)

        if config.test_aync_data_notifications:
            log.info("Testing asyc data notifications")
            ceph_version_id, _ = utils.get_ceph_version()
            if (
                float(ceph_version_id[1]) >= 6 and float(ceph_version_id[5]) >= 8
            ) or float(ceph_version_id[1]) >= 7:
                set_log = "ceph config set global log_to_file true"
                out = utils.exec_shell_cmd(set_log)
                cmd = " ceph orch ps | grep rgw"
                out = utils.exec_shell_cmd(cmd)
                rgw_process_name = out.split()[0]
                utils.exec_shell_cmd(
                    f"ceph config set client.{rgw_process_name} rgw_data_notify_interval_msec 0"
                )
            ceph_conf.set_to_ceph_conf(
                "global",
                ConfigOpts.log_to_file,
                "true",
            )
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.debug_rgw, str(config.debug_rgw), ssh_con
            )

        # create buckets
        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                if config.bucket_sync_crash is True:
                    is_primary = utils.is_cluster_primary()
                    if is_primary:
                        bucket_name_to_create = "bkt-crash-check"
                if config.dbr_scenario == "brownfield":
                    bucket_name_to_create = (
                        "brownfield-dynamic-bkt"
                        if config.dynamic_resharding
                        else "brownfield-manual-bkt"
                    )
                if config.test_ops.get("upload_type") == "read_only_upload":
                    reusable.create_bucket_readonly(
                        bucket_name_to_create, rgw_conn, each_user
                    )
                    return
                log.info("creating bucket with name: %s" % bucket_name_to_create)
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user
                )
                bkt = (
                    "tenant1/" + bucket.name
                    if config.user_type == "tenanted"
                    else bucket.name
                )
                if config.retain_bucket_pol:
                    log.info(
                        "Test bucket policy retained at archive site after writing IOs bug-1937618"
                    )
                    reusable.retain_bucket_policy(
                        rgw_conn2, bucket_name_to_create, config
                    )

                if config.dynamic_resharding is True:
                    if config.test_ops.get("enable_version", False):
                        log.info("Enable bucket versioning")
                        reusable.enable_versioning(
                            bucket, rgw_conn, each_user, write_bucket_io_info
                        )
                    reusable.check_sync_status()
                    op = utils.exec_shell_cmd(
                        f"radosgw-admin bucket stats --bucket {bkt}"
                    )
                    json_doc = json.loads(op)
                    old_num_shards = json_doc["num_shards"]
                    log.info(f"no_of_shards_created: {old_num_shards}")
                if config.test_ops["sharding"]["enable"] is True:
                    op = utils.exec_shell_cmd(
                        f"radosgw-admin bucket stats --bucket {bkt}"
                    )
                    json_doc = json.loads(op)
                    default_num_shards = json_doc["num_shards"]
                    log.info(f"no_of_shards_created: {default_num_shards}")
                    if config.test_ops["sharding"]["max_shards"] != default_num_shards:
                        raise TestExecError("Default shards are not changed")

                if config.test_ops["create_object"] is True:
                    # uploading data
                    log.info("s3 objects to create: %s" % config.objects_count)
                    if utils.check_dbr_support():
                        if bucket_name_to_create in [
                            "brownfield-dynamic-bkt",
                            "brownfield-manual-bkt",
                        ]:
                            op = utils.exec_shell_cmd(
                                f"radosgw-admin bucket stats --bucket {bkt}"
                            )
                            json_doc = json.loads(op)
                            old_num_shards = json_doc["num_shards"]
                            if config.dynamic_resharding is True:
                                config.objects_count = (
                                    old_num_shards * config.max_objects_per_shard + 5
                                )
                            config.mapped_sizes = utils.make_mapped_sizes(config)

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
                            abort_multipart = config.abort_multipart
                            log.info(f"value of abort_multipart {abort_multipart}")
                            reusable.upload_mutipart_object(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                each_user,
                                abort_multipart=abort_multipart,
                            )
                            if abort_multipart:
                                log.info(f"verifying abort multipart")
                                bkt_stat_output = json.loads(
                                    utils.exec_shell_cmd(
                                        f"radosgw-admin bucket stats --bucket {bucket_name_to_create}"
                                    )
                                )
                                if (
                                    bkt_stat_output["usage"]["rgw.multimeta"][
                                        "num_objects"
                                    ]
                                    > 0
                                ):
                                    log.info(f"In complete multipart found")
                                else:
                                    raise AssertionError("Abort multipart failed")

                        else:
                            if config.test_ops.get("enable_version", False):
                                reusable.upload_version_object(
                                    config,
                                    each_user,
                                    rgw_conn,
                                    s3_object_name,
                                    config.obj_size,
                                    bucket,
                                    TEST_DATA_PATH,
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
                        if config.test_ops["download_object"] is True:
                            log.info("trying to download object: %s" % s3_object_name)
                            s3_object_download_name = s3_object_name + "." + "download"
                            s3_object_download_path = os.path.join(
                                TEST_DATA_PATH, s3_object_download_name
                            )
                            log.info(
                                "s3_object_download_path: %s" % s3_object_download_path
                            )
                            log.info(
                                "downloading to filename: %s" % s3_object_download_name
                            )
                            if (
                                config.test_ops.get("encryption_algorithm", None)
                                is not None
                            ):
                                log.info("encryption download")
                                log.info(
                                    "encryption algorithm: %s"
                                    % config.test_ops["encryption_algorithm"]
                                )
                                object_downloaded_status = bucket.download_file(
                                    s3_object_name,
                                    s3_object_download_path,
                                    ExtraArgs={
                                        "SSECustomerKey": encryption_key,
                                        "SSECustomerAlgorithm": config.test_ops[
                                            "encryption_algorithm"
                                        ],
                                    },
                                )
                            else:
                                object_downloaded_status = s3lib.resource_op(
                                    {
                                        "obj": bucket,
                                        "resource": "download_file",
                                        "args": [
                                            s3_object_name,
                                            s3_object_download_path,
                                        ],
                                    }
                                )
                            if object_downloaded_status is False:
                                raise TestExecError(
                                    "Resource execution failed: object download failed"
                                )
                            if object_downloaded_status is None:
                                log.info("object downloaded")
                            s3_object_downloaded_md5 = utils.get_md5(
                                s3_object_download_path
                            )
                            s3_object_uploaded_md5 = utils.get_md5(s3_object_path)
                            log.info(
                                "s3_object_downloaded_md5: %s"
                                % s3_object_downloaded_md5
                            )
                            log.info(
                                "s3_object_uploaded_md5: %s" % s3_object_uploaded_md5
                            )
                            if str(s3_object_uploaded_md5) == str(
                                s3_object_downloaded_md5
                            ):
                                log.info("md5 match")
                                utils.exec_shell_cmd(
                                    "rm -rf %s" % s3_object_download_path
                                )
                            else:
                                raise TestExecError("md5 mismatch")

                        if config.test_ops.get("colocate_archive", False):
                            log.info(
                                "Test bucket stats for 'versioning' and num_objects for a colocated archive zone."
                            )
                            reusable.test_bucket_stats_colocated_archive_zone(
                                bucket_name_to_create, each_user, config
                            )

                        if config.local_file_delete is True:
                            log.info("deleting local file created after the upload")
                            utils.exec_shell_cmd("rm -rf %s" % s3_object_path)

                        if config.etag_verification is True:
                            log.info(f"Verification of eTag is started!!! ")
                            object_ptr = s3lib.resource_op(
                                {
                                    "obj": bucket,
                                    "resource": "Object",
                                    "args": [s3_object_name],
                                }
                            )
                            object_info = object_ptr.get()
                            log.info(f"object info is {object_info}")
                            if object_info["ResponseMetadata"]["HTTPStatusCode"] != 200:
                                raise AssertionError(
                                    f"failed to get response of objects"
                                )
                            eTag_aws = object_info["ETag"].split('"')[1]
                            log.info(f"etag from aws is :{eTag_aws}")
                            cmd = f"radosgw-admin bucket list --bucket {bkt}"
                            out = utils.exec_shell_cmd(cmd)
                            data = json.loads(out)
                            for object in data:
                                if str(s3_object_name) == str(object["name"]):
                                    eTag_radosgw = object["meta"]["etag"]
                                    log.info(f"etag from radosgw is :{eTag_radosgw}")
                                    if str(eTag_aws) == str(eTag_radosgw):
                                        log.info(f"eTag matched!!")
                                    else:
                                        raise AssertionError(
                                            f"mismatch found in the eTAG from aws and radosgw"
                                        )

                    if config.reshard_cancel_cmd:
                        if utils.check_dbr_support():
                            op = utils.exec_shell_cmd(
                                f"radosgw-admin reshard add --bucket {bkt} --num-shards 29"
                            )
                            op = utils.exec_shell_cmd(f"radosgw-admin reshard list")
                            if bkt in op:
                                op = utils.exec_shell_cmd(
                                    f"radosgw-admin reshard cancel --bucket {bkt}"
                                )
                                cancel_op = utils.exec_shell_cmd(
                                    f"radosgw-admin reshard list"
                                )
                                if bkt in cancel_op:
                                    raise TestExecError(
                                        "bucket is still in reshard queue"
                                    )
                            else:
                                raise TestExecError(
                                    "Command failed....Bucket is not added into reshard queue"
                                )
                    if config.bucket_sync_run:
                        out = utils.check_bucket_sync(bkt)
                        if out is False:
                            raise TestExecError(
                                "Command is throwing error while running bucket sync run"
                            )

                    if config.bucket_sync_status:
                        out = utils.wait_till_bucket_synced(bkt)
                        if not out:
                            log.info("Bucket sync is not caught up with source.")
                    if config.test_sync_consistency_bucket_stats:
                        log.info("Wait for sync lease period of 120 seconds")
                        time.sleep(150)
                        reusable.test_bucket_stats_across_sites(
                            bucket_name_to_create, config
                        )
                    if config.bucket_sync_crash:
                        is_primary = utils.is_cluster_primary()
                        if is_primary is False:
                            crash_info = reusable.check_for_crash()
                            if crash_info:
                                raise TestExecError("ceph daemon crash found!")
                            realm, source_zone = utils.get_realm_source_zone_info()
                            log.info(f"Realm name: {realm}")
                            log.info(f"Source zone name: {source_zone}")
                            for i in range(600):  # Running sync command for 600 times
                                op = utils.exec_shell_cmd(
                                    f"radosgw-admin bucket sync run --bucket bkt-crash-check --rgw-curl-low-speed-time=0 --source-zone {source_zone} --rgw-realm {realm}"
                                )
                                crash_info = reusable.check_for_crash()
                                if crash_info:
                                    raise TestExecError("ceph daemon crash found!")
                                time.sleep(1)
                    if config.dynamic_resharding is True:
                        if utils.check_dbr_support():
                            reusable.check_sync_status()
                            for i in range(10):
                                time.sleep(
                                    60
                                )  # Adding delay for processing reshard list
                                op = utils.exec_shell_cmd(
                                    f"radosgw-admin bucket stats --bucket {bkt}"
                                )
                                json_doc = json.loads(op)
                                new_num_shards = json_doc["num_shards"]
                                log.info(f"no_of_shards_created: {new_num_shards}")
                                if new_num_shards > old_num_shards:
                                    break
                            else:
                                raise TestExecError(
                                    "num shards are same after processing resharding"
                                )
                    if config.manual_resharding is True:
                        if config.sync_disable_and_enable:
                            reusable.check_sync_status()
                            op = utils.exec_shell_cmd(
                                f"radosgw-admin bucket sync disable --bucket {bkt}"
                            )
                            for i in range(10):
                                bucket_sync_status = reusable.check_bucket_sync_status(
                                    bkt
                                )
                                if "disabled" in bucket_sync_status:
                                    log.info("Sync disabled successfully")
                                    break
                                else:
                                    time.sleep(60)
                            else:
                                raise TestExecError("Bucket did not got disabled")

                        if utils.check_dbr_support():
                            op = utils.exec_shell_cmd(
                                f"radosgw-admin bucket stats --bucket {bkt}"
                            )
                            json_doc = json.loads(op)
                            old_num_shards = json_doc["num_shards"]
                            log.info(f"no_of_shards_created: {old_num_shards}")
                            if config.shards <= old_num_shards:
                                config.shards = old_num_shards + 10
                            op = utils.exec_shell_cmd(
                                f"radosgw-admin reshard add --bucket {bkt} --num-shards {config.shards}"
                            )
                            op = utils.exec_shell_cmd("radosgw-admin reshard process")
                            time.sleep(60)
                            op = utils.exec_shell_cmd(
                                f"radosgw-admin bucket stats --bucket {bkt}"
                            )
                            json_doc = json.loads(op)
                            new_num_shards = json_doc["num_shards"]
                            log.info(f"no_of_shards_created: {new_num_shards}")
                            if new_num_shards <= old_num_shards:
                                raise TestExecError(
                                    "num shards are same after processing resharding"
                                )
                        if config.sync_disable_and_enable:
                            config.objects_count = config.objects_count + 10
                            config.mapped_sizes = utils.make_mapped_sizes(config)
                            for oc, size in list(config.mapped_sizes.items()):
                                config.obj_size = size
                                s3_object_name = utils.gen_s3_object_name(
                                    bucket_name_to_create, oc
                                )
                                log.info("s3 object name: %s" % s3_object_name)
                                s3_object_path = os.path.join(
                                    TEST_DATA_PATH, s3_object_name
                                )
                                log.info("s3 object path: %s" % s3_object_path)
                                reusable.upload_object(
                                    s3_object_name,
                                    bucket,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                )
                            op = utils.exec_shell_cmd(
                                f"radosgw-admin bucket sync enable --bucket {bkt}"
                            )
                            for i in range(10):
                                bucket_sync_status = reusable.check_bucket_sync_status(
                                    bkt
                                )
                                if (
                                    "behind" in bucket_sync_status
                                    or "recovering" in bucket_sync_status
                                    or "caught up" in bucket_sync_status
                                ):
                                    log.info("Sync enabled successfully")
                                    break
                                else:
                                    time.sleep(60)
                            else:
                                raise TestExecError("Bucket did not got disabled")
                        reusable.check_sync_status()
                    # verification of shards after upload
                    if config.test_datalog_trim_command is True:
                        shard_id, end_marker = reusable.get_datalog_marker()
                        cmd = f"sudo radosgw-admin datalog trim --shard-id {shard_id} --end-marker {end_marker} --debug_ms=1 --debug_rgw=20"
                        out, err = utils.exec_shell_cmd(cmd, debug_info=True)
                        if "Segmentation fault" in err:
                            raise TestExecError("Segmentation fault occured")

                    if config.test_ops["sharding"]["enable"] is True:
                        cmd = (
                            "radosgw-admin metadata get bucket:%s | grep bucket_id"
                            % bucket.name
                        )
                        out = utils.exec_shell_cmd(cmd)
                        b_id = (
                            out.replace('"', "")
                            .strip()
                            .split(":")[1]
                            .strip()
                            .replace(",", "")
                        )
                        cmd2 = "rados -p default.rgw.buckets.index ls | grep %s" % b_id
                        out = utils.exec_shell_cmd(cmd2)
                        log.info("got output from sharing verification.--------")
                    # print out bucket stats and verify in logs for compressed data by
                    # comparing size_kb_utilized and size_kb_actual
                    if config.test_ops["compression"]["enable"] is True:
                        cmd = "radosgw-admin bucket stats --bucket=%s" % bucket.name
                        out = utils.exec_shell_cmd(cmd)
                    # print out bucket stats and verify in logs for compressed data by
                    # comparing size_kb_utilized and size_kb_actual
                    if config.test_ops["compression"]["enable"] is True:
                        cmd = "radosgw-admin bucket stats --bucket=%s" % bucket.name
                        out = utils.exec_shell_cmd(cmd)
                    if config.test_ops["delete_bucket_object"] is True:
                        reusable.delete_objects(bucket)
                        if config.bucket_sync_run_with_disable_sync_thread is False:
                            time.sleep(10)
                            reusable.check_sync_status()
                            reusable.delete_bucket(bucket)
                            ceph_version_id, _ = utils.get_ceph_version()
                            cmd = f"radosgw-admin bucket stats --bucket={bucket.name}"
                            ec, _ = sp.getstatusoutput(cmd)
                            log.info(f"Bucket stats for non-existent is {ec}")
                            if (
                                float(ceph_version_id[0]) >= 16
                                and float(ceph_version_id[1]) >= 2.8
                            ):
                                if ec != 2:
                                    raise TestExecError(
                                        "Bucket stats for non-existent bucket should return failure (2) or ENOENT."
                                    )
                    if config.test_bi_purge:
                        cmd = "radosgw-admin bucket stats --bucket=%s" % bucket.name
                        out = utils.exec_shell_cmd(cmd)
                        json_doc = json.loads(out)
                        bucket_id = json_doc["id"]
                        log.info(
                            "Remove the bucket via bucket rm and --bypass-gc option"
                        )
                        utils.exec_shell_cmd(
                            f"radosgw-admin bucket rm --bucket={bucket.name} --bypass-gc --purge-objects"
                        )
                        log.info(f"Do bi list for bucket {bucket.name}")
                        utils.exec_shell_cmd(
                            f"radosgw-admin bi list --bucket={bucket.name} --bucket-id={bucket_id}"
                        )
                        log.info(f"Do bi purge for bucket {bucket.name}")
                        utils.exec_shell_cmd(
                            f"radosgw-admin bi purge --bucket={bucket.name} --bucket-id={bucket_id}"
                        )
                        log.info(
                            f"Do bi list for bucket {bucket.name} again, it should be empty and return 2"
                        )
                        cmd = f"radosgw-admin bi list --bucket={bucket.name} --bucket-id={bucket_id}"
                        ec, _ = sp.getstatusoutput(cmd)
                        if ec != 2:
                            raise TestExecError(
                                "bi list after bi purge is not empty, it's a test failure."
                            )

                    if config.bucket_sync_run_with_disable_sync_thread:
                        out = utils.check_bucket_sync(bucket.name)
                        if out is False:
                            raise TestExecError(
                                "Command is throwing error while running bucket sync run"
                            )

                    if config.bucket_check_fix:
                        log.info(f"Verify bucket check fix removes orphaned objects")
                        index_pool_list = utils.exec_shell_cmd(
                            f"rados ls -p default.rgw.buckets.index"
                        ).split("\n")
                        index_pool_list.pop()
                        log.info(f"Index pool list: {index_pool_list}")

                        bucket_stats = utils.exec_shell_cmd(
                            f"radosgw-admin bucket stats --bucket {bucket.name}"
                        )
                        bucket_id = json.loads(bucket_stats)["id"]
                        log.info(f"bucket id is {bucket_id}")

                        bucket_list = utils.exec_shell_cmd(
                            f"radosgw-admin bucket list --bucket {bucket.name}"
                        )
                        bucket_list = json.loads(bucket_list)
                        for bkt in bucket_list:
                            if ".meta" in bkt["name"]:
                                meta_file = bkt["name"]
                        for i in index_pool_list:
                            if bucket_id in i:
                                utils.exec_shell_cmd(
                                    f"rados -p default.rgw.buckets.index rmomapkey {i} {meta_file}"
                                )
                        cmd = f"radosgw-admin bucket check --bucket={bucket.name}"
                        ceph_version_id, _ = utils.get_ceph_version()
                        ceph_version_id = ceph_version_id.split("-")
                        ceph_version_id = ceph_version_id[0].split(".")
                        bkt_check_before = utils.exec_shell_cmd(cmd)
                        bkt_check_before = json.loads(bkt_check_before)
                        if (
                            float(ceph_version_id[0]) == 17
                            and float(ceph_version_id[1]) >= 2
                            and float(ceph_version_id[2]) >= 6
                        ) or (
                            float(ceph_version_id[0]) == 18
                            and float(ceph_version_id[1]) >= 2
                            and float(ceph_version_id[2]) >= 1
                        ):
                            log.info("validating orphaned object as per new format")
                            if len(bkt_check_before["invalid_multipart_entries"]) < 1:
                                raise AssertionError(
                                    f"Orphaned object not found in bucket {bucket.name}"
                                )
                        else:
                            if len(bkt_check_before) < 1:
                                raise AssertionError(
                                    f"Orphaned object not found in bucket {bucket.name}"
                                )
                        log.info(f"o/p of bucket check before fix: {bkt_check_before}")
                        utils.exec_shell_cmd(
                            f"radosgw-admin bucket check --fix --bucket={bucket.name}"
                        )
                        bkt_check_after = utils.exec_shell_cmd(cmd)
                        bkt_check_after = json.loads(bkt_check_after)
                        log.info(f"o/p of bucket check after fix: {bkt_check_after}")
                        if (
                            float(ceph_version_id[0]) == 17
                            and float(ceph_version_id[1]) >= 2
                            and float(ceph_version_id[2]) >= 6
                        ) or (
                            float(ceph_version_id[0]) == 18
                            and float(ceph_version_id[1]) >= 2
                            and float(ceph_version_id[2]) >= 1
                        ):
                            log.info("validating bucket check as per new format")
                            if len(bkt_check_after["invalid_multipart_entries"]) != 0:
                                raise AssertionError(
                                    f"bucket check fix did not removed orphan objects on a bucket {bucket.name}"
                                )
                        else:
                            if len(bkt_check_after) != 0:
                                raise AssertionError(
                                    f"bucket check fix did not removed orphan objects on a bucket {bucket.name}"
                                )

                if config.test_ops.get("delete_bucket") is True:
                    reusable.delete_bucket(bucket)

        if config.user_reset:
            log.info(f"Verify user reset doesn't throw any error")
            bucket_list = utils.exec_shell_cmd(
                f"radosgw-admin bucket list --uid={each_user['user_id']}"
            )
            log.info(
                f"bucket list for the user {each_user['user_id']} is {bucket_list}"
            )
            utils.exec_shell_cmd(
                f"radosgw-admin user stats --uid={each_user['user_id']}"
            )
            stats_reset = utils.exec_shell_cmd(
                f"radosgw-admin user stats --uid={each_user['user_id']} --reset-stats"
            )
            if not stats_reset:
                raise AssertionError(f"user reset failed!!")

        if config.bucket_sync_run_with_disable_sync_thread:
            log.info("making changes to ceph.conf")
            ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_run_sync_thread, "True", ssh_con
            )
            srv_restarted = rgw_service.restart(ssh_con)
        if config.modify_user:
            user_id = each_user["user_id"]
            new_display_name = each_user["user_id"] + each_user["user_id"]
            cmd = f"radosgw-admin user modify --uid='{user_id}' --display-name='{new_display_name}'"
            out = utils.exec_shell_cmd(cmd)
            out = json.loads(out)
            if new_display_name == out["display_name"]:
                log.info("User modified successfully")
            else:
                raise TestExecError("Failed to modify user")
        if config.suspend_user:
            user_id = each_user["user_id"]
            cmd = f"radosgw-admin user suspend --uid='{user_id}'"
            out = utils.exec_shell_cmd(cmd)
            out = json.loads(out)
            if out["suspended"] == 1:
                log.info("User got suspended")
            else:
                raise TestExecError("Failed to suspend user")
        if config.enable_user:
            user_id = each_user["user_id"]
            cmd = f"radosgw-admin user enable --uid='{user_id}'"
            out = utils.exec_shell_cmd(cmd)
            out = json.loads(out)
            if out["suspended"] == 0:
                log.info("User enabled successfully")
            else:
                raise TestExecError("Failed to enable user")
        if config.delete_user:
            user_id = each_user["user_id"]
            out = reusable.remove_user(each_user)
            cmd = f"radosgw-admin user list"
            out = utils.exec_shell_cmd(cmd)
            if user_id not in out:
                log.info("User removed successfully")
            else:
                raise TestExecError("Failed to remove user")
        # disable compression after test
        if config.test_ops["compression"]["enable"] is True:
            log.info("disable compression")
            cmd = "radosgw-admin zone get"
            out = utils.exec_shell_cmd(cmd)
            zone = json.loads(out)
            zone = zone.get("name")
            cmd = (
                "radosgw-admin zone placement modify --rgw-zone=%s "
                "--placement-id=default-placement --compression=none" % zone
            )
            out = utils.exec_shell_cmd(cmd)
            srv_restarted = rgw_service.restart(ssh_con)
            time.sleep(10)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")
        if config.gc_verification is True:
            final_op = reusable.verify_gc()
            if final_op != -1:
                test_info.failed_status("test failed")
                sys.exit(1)

    # test async rgw_data_notify_interval_msec=0 does not disable async data notifications
    if config.test_aync_data_notifications:
        log.info("Testing async data notifications")
        out = utils.disable_async_data_notifications()
        if not out:
            raise TestExecError(
                "No 'notifying datalog change' entries should be seen in rgw logs when rgw_data_notify_interval_msec=0 "
            )
        ceph_conf.set_to_ceph_conf("global", ConfigOpts.debug_rgw, "0", ssh_con)

    if config.test_ops.get("verify_bi_put", False):
        log.info("CEPH-83574876 : Verify 'bi put' uses right bucket index shard")
        bucket_stats = json.loads(
            utils.exec_shell_cmd(f"radosgw-admin bucket stats --bucket {bucket.name}")
        )
        bucket_id = bucket_stats["id"]
        log.info(f"Bucket id is {bucket_id}")
        bi_list_cmd = f"radosgw-admin bi list --bucket {bucket.name} > bi_list.json"
        bi_list = utils.exec_shell_cmd(bi_list_cmd)
        utils.exec_shell_cmd("cat bi_list.json")

        utils.exec_shell_cmd(
            f"radosgw-admin bi put --bucket {bucket.name} --object {s3_object_name} --infile bi_list.json"
        )
        bi_list_post_bi_put = utils.exec_shell_cmd(
            f"radosgw-admin bi list --bucket {bucket.name} | grep idx"
        )

        bi_list_post_bi_put = list(bi_list_post_bi_put.split("\n"))
        bi_list_post_bi_put.pop()

        bi_list_post_bi_put_sorted = bi_list_post_bi_put[:]
        bi_list_post_bi_put_sorted.sort()

        if bi_list_post_bi_put != bi_list_post_bi_put_sorted:
            raise AssertionError(
                "bi list content of incomplete multipart is not in sorted order"
            )

        total_no_of_incomplete_multipart = len(bi_list_post_bi_put)
        log.info(
            f"total_no_of_incomplete_multipart is {total_no_of_incomplete_multipart}"
        )

        index_pool_list = utils.exec_shell_cmd(
            f"rados ls -p default.rgw.buckets.index|grep {bucket_id}"
        ).split("\n")
        index_pool_list.pop()
        log.info(f"Index pool list: {index_pool_list}")

        for pool in index_pool_list:
            cmd = f"rados -p default.rgw.buckets.index listomapkeys {pool}"
            output = utils.exec_shell_cmd(cmd)
            output_new = list(output.split("\n"))
            output_new.pop()
            op_len_new = len(output_new)
            if op_len_new > 0:
                if op_len_new != total_no_of_incomplete_multipart:
                    raise AssertionError(
                        "All the incomplete multiparts are not present in same shard"
                    )

    if config.test_ops["sharding"]["enable"] is True:
        ceph_conf.set_to_ceph_conf(
            "global", ConfigOpts.rgw_override_bucket_index_max_shards, str(0), ssh_con
        )
        srv_restarted = rgw_service.restart(ssh_con)

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

    # check for any health errors or large omaps
    out = utils.get_ceph_status()
    if not out:
        raise TestExecError(
            "ceph status is either in HEALTH_ERR or we have large omap objects."
        )


if __name__ == "__main__":
    test_info = AddTestInfo("create m buckets with n objects")
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
