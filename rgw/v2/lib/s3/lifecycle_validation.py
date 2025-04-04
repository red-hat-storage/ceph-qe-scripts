import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import json
import logging
import time
from datetime import datetime, timedelta

import v2.utils.utils as utils
from v2.tests.s3_swift import reusable

log = logging.getLogger()


def sleep_till_lc_not_processing(config, bucket):
    """
    this is achieved by sleeping till point of time which is in the middle of two lc process
    so that lc process completes and bucket list will be settled with target storage class
    """
    log.info(
        f"sleeping till time point where lc not processing on the bucket: {bucket.name}"
    )
    lc_list = json.loads(utils.exec_shell_cmd("radosgw-admin lc list"))
    log.info(f"lc list is {lc_list}")
    lc_last_processed_time = ""
    for data in lc_list:
        if bucket.name in data["bucket"]:
            lc_last_processed_time = data["started"]
            log.info(
                f"last lc processed time for bucket {bucket.name} is {lc_last_processed_time}"
            )
            break
    else:
        raise AssertionError(
            f"entry for {bucket.name} doesnot exist in lc list while trying to get last lc process time"
        )
    rgw_lc_debug_interval = config.rgw_lc_debug_interval
    log.info(f"rgw_lc_debug_interval: {rgw_lc_debug_interval}")
    datetime_lc_process = datetime.strptime(
        lc_last_processed_time, "%a, %d %b %Y %H:%M:%S %Z"
    )
    timediff_sec = rgw_lc_debug_interval + rgw_lc_debug_interval / 2
    datetime_lc_process = datetime_lc_process + timedelta(seconds=timediff_sec)
    log.info(
        f"sleeping till {datetime_lc_process} so that lc process completes and bucket list is settled"
    )
    while datetime.utcnow() < datetime_lc_process:
        log.info(f"current time: {datetime.utcnow().isoformat()}")
        time.sleep(5)
    log.info(f"lc not processing now on the bucket: {bucket.name}")


def validate_prefix_rule(bucket, config):
    """
    This function is to validate the prefix rule for versioned objects

    Parameters:
        bucket(char): Name of the bucket
        config(list): config
    """
    log.info("verification starts")
    objects_count = config.objects_count
    objs_total = (config.test_ops["version_count"]) * (config.objects_count)
    objs_ncurr = (config.test_ops["version_count"]) * (config.objects_count) - (
        config.objects_count
    )
    objs_diff = objs_total - objs_ncurr
    if config.test_ops.get("tenant_name"):
        tenant_name = config.test_ops.get("tenant_name")
        op = utils.exec_shell_cmd(
            f"radosgw-admin bucket stats --bucket {tenant_name}/{bucket.name}"
        )
    else:
        op = utils.exec_shell_cmd(
            "radosgw-admin bucket stats --bucket=%s" % bucket.name
        )
    if config.conflict_transition_actions:
        log.info(
            "Transition to latest storage class in lc config taken place"
            + " when there is a conflict between transition rules having same days and same prefix"
            + " but different storage class"
        )

    if config.conflict_transition_actions or config.test_ops.get("reverse_transition"):
        sleep_till_lc_not_processing(config, bucket)
    if config.test_ops.get("tenant_name"):
        tenant_name = config.test_ops.get("tenant_name")
        op2 = utils.exec_shell_cmd(
            f"radosgw-admin bucket list --bucket {tenant_name}/{bucket.name}"
        )
    else:
        op2 = utils.exec_shell_cmd(
            "radosgw-admin bucket list --bucket=%s" % bucket.name
        )
    json_doc = json.loads(op)
    json_doc2 = json.loads(op2)
    objects = json_doc["usage"]["rgw.main"]["num_objects"]
    if config.test_ops.get("expected_storage_class"):
        expected_storage_class = config.test_ops.get("expected_storage_class")
    else:
        expected_storage_class = config.second_storage_class
    if config.test_lc_transition:
        if config.test_ops.get("test_cloud_transition", False):
            log.info("Start the LC cloud transition verification")
            objs_total = (config.test_ops["version_count"]) * (config.objects_count)
            log.info(f"total objects are {objs_total} objects.")
            bucket_stats_op = utils.exec_shell_cmd(
                f"radosgw-admin bucket stats --bucket={bucket.name}"
            )
            json_doc = json.loads(bucket_stats_op)
            bucket_list_op = utils.exec_shell_cmd(
                f"radosgw-admin bucket list --bucket={bucket.name}"
            )
            json_doc_list = json.loads(bucket_list_op)
            objects_remaining = json_doc["usage"]["rgw.main"]["num_objects"]
            count = 0
            if config.test_ops.get("test_retain_head", False):
                log.info("Verifying the cloud transition with retain_head_true")
                if config.test_ops.get("test_cloud_transition_at_remote", False):
                    zone_name = config.remote_zone
                    log.info(
                        "Verifying the cloud transition at remote site with retain_head_true"
                    )
                    remote_site_ssh_con = reusable.get_remote_conn_in_multisite()
                    log.info(
                        f"collect bucket stats for {bucket.name} at remote site {zone_name}"
                    )
                    cmd_bucket_stats = (
                        f"radosgw-admin bucket stats --bucket {bucket.name}"
                    )
                    stdin, stdout, stderr = remote_site_ssh_con.exec_command(
                        cmd_bucket_stats
                    )
                    cmd_output = stdout.read().decode()
                    stats_remote = json.loads(cmd_output)
                    log.info(f"The bucket stats at the remote site is {stats_remote}")
                    remote_cloud_tiered_objects = stats_remote["usage"][
                        "rgw.cloudtiered"
                    ]["num_objects"]
                    if remote_cloud_tiered_objects == objs_total:
                        log.info(
                            f"LC cloud transition passed at remote site,{zone_name}"
                        )
                    else:
                        raise AssertionError(
                            f"LC transition failed for {bucket.name} at remote site,{zone_name}"
                        )
                else:
                    objects_cloud_tiered = json_doc["usage"]["rgw.cloudtiered"][
                        "num_objects"
                    ]

                    log.info(
                        f" objects cloud tiered are {objects_cloud_tiered} and delete-marker count {count}"
                    )
                    if objects_cloud_tiered == objs_total:
                        log.info(
                            f"lifecycle transition to cloud validated for current and noncurrent objects with retain_head_object_true for bucket {bucket.name}"
                        )
                    else:
                        raise AssertionError(
                            "Lifecycle cloud transition validation failed retain_head_object_true for bucket {bucket.name}"
                        )
            else:
                log.info("Verifying the cloud transition with retain_head_object_false")
                for i in range(0, config.objects_count):
                    if json_doc_list[i]["tag"] == "delete-marker":
                        count += 1
                if objects_remaining == 0 and count == config.objects_count:
                    log.info(
                        f"lifecycle transition to cloud validated for current and noncurrent objects with retain_head_object_false for bucket {bucket.name}"
                    )
                else:
                    raise AssertionError(
                        f"Lifecycle cloud transition validation failed with retain_head_object_false for bucket {bucket.name}"
                    )
        else:
            log.info("Start the validation of LC pool transition")
            curr = 0
            ncurr = 0
            two_pool_curr_ncurr = 0
            ec_pool_curr_ncurr = 0
            for i in range(0, objs_total):
                storage_class = json_doc2[i]["meta"]["storage_class"]
                if (
                    config.two_pool_transition
                    and storage_class == expected_storage_class
                ):
                    two_pool_curr_ncurr += 1
                elif (
                    config.ec_pool_transition
                    and storage_class == config.ec_storage_class
                ):
                    ec_pool_curr_ncurr += 1
                else:
                    if storage_class == config.storage_class:
                        curr += 1
                    else:
                        ncurr += 1
            if curr == config.objects_count and ncurr == objs_ncurr:
                log.info(
                    "Lifecycle transition of current and noncurrent object version validated"
                )
            elif two_pool_curr_ncurr == objs_total:
                log.info(
                    "Two pool Lifecycle transition of current and noncurrent object version validated."
                )
            elif ec_pool_curr_ncurr == objs_total:
                log.info(
                    "Bucket LC Transition to EC pool of current and noncurrent object version validated."
                )
            else:
                log.error(f"current: {curr} and noncurrent: {ncurr}")
                log.error(f"two_pool_curr_ncurr: {two_pool_curr_ncurr}")
                log.error(f"ec_pool_curr_ncurr: {ec_pool_curr_ncurr}")
                raise AssertionError("lc validation for object transition failed")
    else:
        log.info("Start the validation of LC expiration.")

        c1 = 0
        if objects == objs_total:
            for i, entry in enumerate(json_doc2):
                print(entry["tag"])
                if entry["tag"] == "delete-marker":
                    c1 = c1 + 1
            if c1 != (config.objects_count):
                raise AssertionError(
                    "Lifecycle expiration of current object version for prefix filter failed"
                )
            log.info(
                "Lifecycle expiration of current object version validated for prefix filter"
            )
        for lc_conf in config.lifecycle_conf:
            log.info(f"lc config is {lc_conf}")
            if "NoncurrentVersionExpiration" in lc_conf.keys():
                if objects != objs_diff:
                    raise AssertionError(
                        "Lifecycle expiration of non_current object version for prefix filter failed"
                    )
                log.info(
                    "Lifecycle expiration of non_current object version validated for prefix filter"
                )


def validate_prefix_rule_non_versioned(bucket, config, ssh_con=None):
    log.info("verification starts")
    objects_count = config.objects_count
    if config.test_lc_transition:
        cmd = utils.exec_shell_cmd(
            f"radosgw-admin bucket list --bucket {bucket.name}{f' --max-entries {config.objects_count}' if  config.objects_count > 1000 else ''}"
        )
        json_doc = json.loads(cmd)
        obj_count = (
            config.objects_count if config.objects_count < 1000 else len(json_doc)
        )
        for i in range(0, obj_count):
            storage_class = json_doc[i]["meta"]["storage_class"]
            log.info(f"object has transitioned to {storage_class}")
            if storage_class != config.storage_class:
                raise AssertionError("lc validation for object transition failed")
    else:
        bkt_stats_cmd = f"radosgw-admin bucket stats --bucket {bucket.name}"
        if ssh_con:
            op = utils.remote_exec_shell_cmd(ssh_con, bkt_stats_cmd, return_output=True)
        else:
            op = utils.exec_shell_cmd(bkt_stats_cmd)
        json_doc = json.loads(op)
        objects = json_doc["usage"]["rgw.main"]["num_objects"]
        if objects != 0:
            raise AssertionError("lc validation failed")


def validate_and_rule(bucket, config):
    """
    This function is to validate AND rule

    Parameters:
        bucket(char): Name of the bucket
        config(list): config
    """
    log.info("verification starts")
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket=%s" % bucket.name)
    json_doc = json.loads(op)
    op2 = utils.exec_shell_cmd(
        f"radosgw-admin bucket list --bucket {bucket.name}{f' --max-entries {config.objects_count}' if  config.objects_count > 1000 else ''}"
    )
    json_doc2 = json.loads(op2)
    objects = json_doc["usage"]["rgw.main"]["num_objects"]
    if config.test_lc_transition and not config.test_ops.get(
        "conflict_btw_exp_transition"
    ):
        obj_count = (
            config.objects_count if config.objects_count < 1000 else len(json_doc2)
        )
        for i in range(0, obj_count):
            storage_class = json_doc2[i]["meta"]["storage_class"]
            if storage_class != config.storage_class:
                raise AssertionError("LC transition for AND filters failed")
        log.info("Lifecycle transition with And rule validated successfully")
    else:
        if objects != 0:
            if config.test_ops.get("conflict_btw_expiration_transition"):
                raise AssertionError(
                    "Idealy expiration action should take effect"
                    + " when there is conflict between expiration and transition."
                    + "But all objects are not expired"
                )
            raise AssertionError("Lifecycle expiration with And rule Failed!!")
        log.info("Lifecycle expiration with And rule validated successfully")
