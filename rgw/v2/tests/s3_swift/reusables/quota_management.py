import logging
import os

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.tests.s3_swift import reusable

log = logging.getLogger()


def set_quota(quota_scope, user_info, max_objects=None, max_size=None):
    log.info(f"setting {quota_scope} quota")
    cmd = f"radosgw-admin quota set --quota-scope={quota_scope} --uid={user_info['user_id']}"
    if max_objects:
        cmd = cmd + f" --max-objects={max_objects}"
    if max_size:
        cmd = cmd + f" --max-size={max_size}"
    utils.exec_shell_cmd(cmd)
    cmd = f"radosgw-admin user info --uid={user_info['user_id']}"
    utils.exec_shell_cmd(cmd)


def toggle_quota(toggle, quota_scope, user_info):
    log.info(f"{toggle} {quota_scope} quota")
    cmd = f"radosgw-admin quota {toggle} --quota-scope={quota_scope} --uid={user_info['user_id']}"
    utils.exec_shell_cmd(cmd)
    cmd = f"radosgw-admin user info --uid={user_info['user_id']}"
    utils.exec_shell_cmd(cmd)


def upload_object_initiate(
    test_data_path, config, each_user, bucket, bucket_name, obj_name_suffix, obj_size
):
    config.obj_size = obj_size
    s3_object_name = utils.gen_s3_object_name(bucket_name, obj_name_suffix)
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(test_data_path, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
    log.info("upload type: normal")
    try:
        reusable.upload_object(
            s3_object_name,
            bucket,
            test_data_path,
            config,
            each_user,
        )
        return True
    except TestExecError as e:
        log.info(e)
        return False


def test_max_objects(
    test_data_path, quota_scope, config, each_user, bucket, max_objects
):
    log.info(f"testing {quota_scope} quota max objects")
    set_quota(quota_scope=quota_scope, user_info=each_user, max_objects=max_objects)
    toggle_quota("enable", quota_scope, each_user)

    log.info(f"uploading {max_objects} objects equal to quota limit")
    for i in range(1, max_objects + 1):
        uploaded = upload_object_initiate(
            test_data_path, config, each_user, bucket, bucket.name, i, 0
        )
        if not uploaded:
            AssertionError(
                f"{quota_scope} quota with max objects failed as upload object refused before reaching limit"
            )
    log.info(
        f"uploading one more objects to test {quota_scope} quota max objects limit"
    )
    uploaded = upload_object_initiate(
        test_data_path, config, each_user, bucket, bucket.name, i + 1, 0
    )
    if uploaded:
        raise AssertionError(f"{quota_scope} quota with max objects failed")
    log.info(f"object upload failed as {quota_scope} quota max objects limit exceeded")

    toggle_quota("disable", quota_scope, each_user)
    log.info(f"uploading one more object after disabling {quota_scope} quota")
    uploaded = upload_object_initiate(
        test_data_path, config, each_user, bucket, bucket.name, i + 1, 0
    )
    if not uploaded:
        raise AssertionError(
            f"object upload refused even after disabling {quota_scope} quota"
        )
    log.info("object upload successful after disabling quota")
    reusable.delete_objects(bucket)
    log.info(f"{quota_scope} quota with max objects passed")


def test_max_size(test_data_path, quota_scope, config, each_user, bucket, max_size):
    log.info(f"testing {quota_scope} quota max size")
    set_quota(quota_scope=quota_scope, user_info=each_user, max_size=max_size)
    toggle_quota("enable", quota_scope, each_user)

    log.info(
        f"uploading object in bucket size greater than the {quota_scope} quota limit"
    )
    uploaded = upload_object_initiate(
        test_data_path, config, each_user, bucket, bucket.name, 1, max_size + 1
    )
    if uploaded:
        raise AssertionError(f"{quota_scope} quota with max size failed")
    log.info(f"object upload failed as {quota_scope} quota max size limit exceeded")

    toggle_quota("disable", quota_scope, each_user)
    log.info(
        f"uploading object that exceeds max size after disabling {quota_scope} quota"
    )
    uploaded = upload_object_initiate(
        test_data_path, config, each_user, bucket, bucket.name, 1, max_size + 1
    )
    if not uploaded:
        raise AssertionError(
            f"object upload refused even after disabling {quota_scope} quota"
        )
    log.info("object upload successful after disabling quota")
    reusable.delete_objects(bucket)
    log.info(f"{quota_scope} quota with max size passed")
