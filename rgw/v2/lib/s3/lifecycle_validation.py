import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import json
import logging

import v2.utils.utils as utils

log = logging.getLogger()


def validate_prefix_rule(bucket, config):
    """
    This function is to validate the prefix rule for versioned objects

    Parameters:
        bucket(char): Name of the bucket
        config(list): config
    """
    log.info("verification starts")
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket=%s" % bucket.name)
    op2 = utils.exec_shell_cmd("radosgw-admin bucket list --bucket=%s" % bucket.name)
    json_doc = json.loads(op)
    json_doc2 = json.loads(op2)
    objects = json_doc["usage"]["rgw.main"]["num_objects"]
    objs_total = (config.test_ops["version_count"]) * (config.objects_count)
    objs_ncurr = (config.test_ops["version_count"]) * (config.objects_count) - (
        config.objects_count
    )
    objs_diff = objs_total - objs_ncurr
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
    if objects != objs_diff:
        raise AssertionError(
            "Lifecycle expiration of non_current object version for prefix filter failed"
        )
    log.info(
        "Lifecycle expiration of non_current object version validated for prefix filter"
    )


def validate_prefix_rule_non_versioned(bucket):
    log.info("verification starts")
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket=%s" % bucket.name)
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
    objects = json_doc["usage"]["rgw.main"]["num_objects"]
    if objects != 0:
        raise AssertionError("Lifecycle expiration with And rule Failed!!")
    log.info("Lifecycle expiration with And rule validated successfully")
