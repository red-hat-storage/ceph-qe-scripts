"""
# test s3 bucket_lifecycle operations (like read, modify and delete)

Usage: test_bucket_lifecycle_config_ops.py -c configs/<input-yaml>
where <input-yaml> are test_bucket_lifecycle_config_disable.yaml, test_bucket_lifecycle_config_modify.yaml, test_bucket_lifecycle_config_read.yaml and test_bucket_lifecycle_config_versioning.yaml

Operation:
- Create a user and a bucket (enable versioning as per the input from the yaml file)
- Create objects in the bukcet(object count and object size taken from the yaml file)
- Perform lifecycle operation like read/modify/disable on the bucket and verify they're successful
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import traceback

import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3 import lifecycle as lc
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser

log = logging.getLogger()


TEST_DATA_PATH = None


def basic_lifecycle_config(prefix, days, id, status="Enabled"):
    rule = {}
    expiration = lc.gen_expiration()
    expiration["Expiration"].update(lc.gen_expiration_days(days))
    filter = lc.gen_filter()
    filter["Filter"].update(lc.gen_prefix(prefix))
    rule.update(lc.gen_id(id))
    rule.update(filter)
    rule.update(expiration)
    rule.update(lc.gen_status(status))
    lifecycle_config = lc.gen_lifecycle_configuration([rule])
    log.info("life_cycle config:\n%s" % lifecycle_config)
    return lifecycle_config


def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()
        # create buckets
        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=1
                )
                bucket = reusable.create_bucket(bucket_name, rgw_conn, each_user)
                if config.test_ops["enable_versioning"] is True:
                    log.info("bucket versionig test on bucket: %s" % bucket.name)
                    # bucket_versioning = s3_ops.resource_op(rgw_conn, 'BucketVersioning', bucket.name)
                    bucket_versioning = s3lib.resource_op(
                        {
                            "obj": rgw_conn,
                            "resource": "BucketVersioning",
                            "args": [bucket.name],
                        }
                    )
                    version_status = s3lib.resource_op(
                        {"obj": bucket_versioning, "resource": "status", "args": None}
                    )
                    if version_status is None:
                        log.info("bucket versioning still not enabled")
                    # enabling bucket versioning
                    version_enable_status = s3lib.resource_op(
                        {"obj": bucket_versioning, "resource": "enable", "args": None}
                    )
                    response = HttpResponseParser(version_enable_status)
                    if response.status_code == 200:
                        log.info("version enabled")
                    else:
                        raise TestExecError("version enable failed")
                if config.test_ops["create_object"] is True:
                    # upload data
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                        if config.test_ops["version_count"] > 0:
                            for vc in range(config.test_ops["version_count"]):
                                log.info(
                                    "version count for %s is %s"
                                    % (s3_object_name, str(vc))
                                )
                                log.info("modifying data: %s" % s3_object_name)
                                reusable.upload_object(
                                    s3_object_name,
                                    bucket,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                    append_data=True,
                                    append_msg="hello object for version: %s\n"
                                    % str(vc),
                                )
                        else:
                            log.info("s3 objects to create: %s" % config.objects_count)
                            reusable.upload_object(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                each_user,
                            )
                bucket_life_cycle = s3lib.resource_op(
                    {
                        "obj": rgw_conn,
                        "resource": "BucketLifecycleConfiguration",
                        "args": [bucket.name],
                    }
                )
                life_cycle = basic_lifecycle_config(prefix="key", days=20, id="rul1")
                put_bucket_life_cycle = s3lib.resource_op(
                    {
                        "obj": bucket_life_cycle,
                        "resource": "put",
                        "kwargs": dict(LifecycleConfiguration=life_cycle),
                    }
                )
                log.info("put bucket life cycle:\n%s" % put_bucket_life_cycle)
                if put_bucket_life_cycle is False:
                    raise TestExecError(
                        "Resource execution failed: bucket creation faield"
                    )
                if put_bucket_life_cycle is not None:
                    response = HttpResponseParser(put_bucket_life_cycle)
                    if response.status_code == 200:
                        log.info("bucket life cycle added")
                    else:
                        raise TestExecError("bucket lifecycle addition failed")
                else:
                    raise TestExecError("bucket lifecycle addition failed")
                log.info("trying to retrieve bucket lifecycle config")
                get_bucket_life_cycle_config = s3lib.resource_op(
                    {
                        "obj": rgw_conn2,
                        "resource": "get_bucket_lifecycle_configuration",
                        "kwargs": dict(Bucket=bucket.name),
                    }
                )
                if get_bucket_life_cycle_config is False:
                    raise TestExecError("bucket lifecycle config retrieval failed")
                if get_bucket_life_cycle_config is not None:
                    response = HttpResponseParser(get_bucket_life_cycle_config)
                    if response.status_code == 200:
                        log.info("bucket life cycle retrieved")
                    else:
                        raise TestExecError("bucket lifecycle config retrieval failed")
                else:
                    raise TestExecError("bucket life cycle retrieved")
                if config.test_ops["create_object"] is True:
                    for oc in range(config.objects_count):
                        s3_object_name = utils.gen_s3_object_name(bucket.name, oc)
                        if config.test_ops["version_count"] > 0:
                            if (
                                config.test_ops.get("delete_versioned_object", None)
                                is True
                            ):
                                log.info(
                                    "list all the versions of the object and delete the "
                                    "current version of the object"
                                )
                                log.info(
                                    "all versions for the object: %s\n" % s3_object_name
                                )
                                versions = bucket.object_versions.filter(
                                    Prefix=s3_object_name
                                )
                                t1 = []
                                for version in versions:
                                    log.info(
                                        "key_name: %s --> version_id: %s"
                                        % (version.object_key, version.version_id)
                                    )
                                    t1.append(version.version_id)
                                s3_object = s3lib.resource_op(
                                    {
                                        "obj": rgw_conn,
                                        "resource": "Object",
                                        "args": [bucket.name, s3_object_name],
                                    }
                                )
                                # log.info('object version to delete: %s -> %s' % (versions[0].object_key,
                                #                                                 versions[0].version_id))
                                delete_response = s3_object.delete()
                                log.info("delete response: %s" % delete_response)
                                if delete_response["DeleteMarker"] is True:
                                    log.info("object delete marker is set to true")
                                else:
                                    raise TestExecError(
                                        "'object delete marker is set to false"
                                    )
                                log.info(
                                    "available versions for the object after delete marker is set"
                                )
                                t2 = []
                                versions_after_delete_marker_is_set = (
                                    bucket.object_versions.filter(Prefix=s3_object_name)
                                )
                                for version in versions_after_delete_marker_is_set:
                                    log.info(
                                        "key_name: %s --> version_id: %s"
                                        % (version.object_key, version.version_id)
                                    )
                                    t2.append(version.version_id)
                                t2.pop()
                                if t1 == t2:
                                    log.info("versions remained intact")
                                else:
                                    raise TestExecError(
                                        "versions are not intact after delete marker is set"
                                    )
                # modify bucket lifecycle configuration, modify expiration days here for the test case.
                if config.test_ops.get("modify_lifecycle", False) is True:
                    log.info("modifying lifecycle configuration")
                    life_cycle_modifed = basic_lifecycle_config(
                        prefix="key", days=15, id="rul1", status="Disabled"
                    )
                    put_bucket_life_cycle = s3lib.resource_op(
                        {
                            "obj": bucket_life_cycle,
                            "resource": "put",
                            "kwargs": dict(LifecycleConfiguration=life_cycle_modifed),
                        }
                    )
                    log.info("put bucket life cycle:\n%s" % put_bucket_life_cycle)
                    if put_bucket_life_cycle is False:
                        raise TestExecError(
                            "Resource execution failed: bucket creation faield"
                        )
                    if put_bucket_life_cycle is not None:
                        response = HttpResponseParser(put_bucket_life_cycle)

                        if response.status_code == 200:
                            log.info("bucket life cycle added")

                        else:
                            raise TestExecError("bucket lifecycle addition failed")
                    else:
                        raise TestExecError("bucket lifecycle addition failed")
                    log.info("trying to retrieve bucket lifecycle config")
                    get_bucket_life_cycle_config = s3lib.resource_op(
                        {
                            "obj": rgw_conn2,
                            "resource": "get_bucket_lifecycle_configuration",
                            "kwargs": dict(Bucket=bucket.name),
                        }
                    )
                    if get_bucket_life_cycle_config is False:
                        raise TestExecError("bucket lifecycle config retrieval failed")
                    if get_bucket_life_cycle_config is not None:
                        response = HttpResponseParser(get_bucket_life_cycle_config)
                        modified_expiration_days = get_bucket_life_cycle_config[
                            "Rules"
                        ][0]["Expiration"]["Days"]
                        log.info(
                            "modified expiration days: %s" % modified_expiration_days
                        )
                        if (
                            response.status_code == 200
                            and modified_expiration_days == 15
                        ):
                            log.info("bucket life cycle retrieved after modifying")
                        else:
                            raise TestExecError(
                                "bucket lifecycle config retrieval failed after modifying"
                            )
                    else:
                        raise TestExecError(
                            "bucket lifecycle config retrieval failed after modifying"
                        )
                # disable bucket lifecycle configuration
                if config.test_ops.get("disable_lifecycle", False) is True:
                    log.info("disabling lifecycle configuration")
                    life_cycle_disabled_config = basic_lifecycle_config(
                        prefix="key", days=20, id="rul1", status="Disabled"
                    )
                    put_bucket_life_cycle = s3lib.resource_op(
                        {
                            "obj": bucket_life_cycle,
                            "resource": "put",
                            "kwargs": dict(
                                LifecycleConfiguration=life_cycle_disabled_config
                            ),
                        }
                    )
                    log.info("put bucket life cycle:\n%s" % put_bucket_life_cycle)
                    if put_bucket_life_cycle is False:
                        raise TestExecError(
                            "Resource execution failed: bucket creation faield"
                        )
                    if put_bucket_life_cycle is not None:
                        response = HttpResponseParser(put_bucket_life_cycle)
                        if response.status_code == 200:
                            log.info("bucket life cycle added")
                        else:
                            raise TestExecError("bucket lifecycle addition failed")
                    else:
                        raise TestExecError("bucket lifecycle addition failed")
                    log.info("trying to retrieve bucket lifecycle config")
                    get_bucket_life_cycle_config = s3lib.resource_op(
                        {
                            "obj": rgw_conn2,
                            "resource": "get_bucket_lifecycle_configuration",
                            "kwargs": dict(Bucket=bucket.name),
                        }
                    )
                    if get_bucket_life_cycle_config is False:
                        raise TestExecError("bucket lifecycle config retrieval failed")
                    if get_bucket_life_cycle_config is not None:
                        response = HttpResponseParser(get_bucket_life_cycle_config)
                        if (
                            response.status_code == 200
                            and get_bucket_life_cycle_config["Rules"][0]["Status"]
                            == "Disabled"
                        ):
                            log.info(
                                "disabled_status: %s"
                                % get_bucket_life_cycle_config["Rules"][0]["Status"]
                            )
                            log.info("bucket life cycle retrieved after disabled")
                        else:
                            raise TestExecError(
                                "bucket lifecycle config retrieval failed after disabled"
                            )
                    else:
                        raise TestExecError(
                            "bucket lifecycle config retrieval failed after disabled"
                        )
    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("create m buckets with n objects with bucket life cycle")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
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
        args = parser.parse_args()
        yaml_file = args.config
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read()
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
