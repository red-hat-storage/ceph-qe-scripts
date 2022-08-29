import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import random
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


def test_exec(config, ssh_con):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # create user
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

    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)  # ,config=config)
        if config.use_aws4 is True:
            rgw_conn = auth.do_auth(**{"signature_version": "s3v4"})
        else:
            rgw_conn = auth.do_auth()

        user_id = each_user["user_id"]
        # Creating a seed for multi-factor authentication
        log.info("Creating a seed for multi-factor authentication")
        cmd = "head -10 /dev/urandom | sha512sum | cut -b 1-30"
        SEED = utils.exec_shell_cmd(cmd)
        log.info(
            "Configure the one-time password generator oathtool and the back-end MFA system to use the same seed."
        )
        test_totp = reusable.generate_totp(SEED)
        serial = "MFAtest" + str(random.randrange(1, 100))
        if test_totp is False:
            raise TestExecError(
                "Failed to configure one-time password generator - oathtool"
            )

        if config.test_ops["mfa_create"] is True:
            log.info("Create a new MFA TOTP token")
            cmd = f"time radosgw-admin mfa create --uid={user_id} --totp-serial={serial} --totp-seed={SEED}"
            mfa_create = utils.exec_shell_cmd(cmd)
            if mfa_create is False:
                raise TestExecError("Failed to create new MFA TOTP token!")

        # Verify no crash is seen with in correct syntax for mfa resync command  BZ:https://bugzilla.redhat.com/show_bug.cgi?id=1947862
        if config.test_ops.get("mfa_resync_invalid_syntax") is True:
            log.info(
                "Validate the mfa resync command errors out with approriate message on invalid syntax"
            )
            get_totp = reusable.generate_totp(SEED)
            cmd = f"radosgw-admin mfa resync --uid {user_id} --totp-serial={serial} --totp-seed={SEED} --totp-pin={get_totp}"
            mfa_resync_invalid_syntax = utils.exec_shell_cmd(cmd)
            if mfa_resync_invalid_syntax is False:
                log.info("appropriate usage message displayed")
            else:
                raise TestExecError("Usage message not displayed")

        if config.test_ops["mfa_check"] is True:
            log.info(
                "Test a multi-factor authentication (MFA) time-based one time password (TOTP) token."
            )
            get_totp = reusable.generate_totp(SEED)
            cmd = (
                "time radosgw-admin mfa check --uid=%s --totp-serial=%s --totp-pin=%s"
                % (each_user["user_id"], serial, get_totp)
            )
            cmd = f"time radosgw-admin mfa check --uid={user_id} --totp-serial={serial} --totp-pin={get_totp}"
            mfa_check = utils.exec_shell_cmd(cmd)
            if mfa_check is False:
                log.info(
                    "Resynchronize a multi-factor authentication TOTP token in case of time skew or failed checks."
                )
                previous_pin = reusable.generate_totp(SEED)
                log.info("Sleep of 30 seconds to fetch another totp")
                time.sleep(30)
                current_pin = reusable.generate_totp(SEED)
                cmd = "time radosgw-admin mfa resync --uid {user_id} --totp-serial {serial} --totp-pin {get_totp} --totp-pin {get_totp}"
                mfa_resync = utils.exec_shell_cmd(cmd)
                if mfa_resync is False:
                    raise TestExecError("Failed to resync token")
                log.info(
                    "Verify the token was successfully resynchronized by testing a new PIN"
                )
                get_totp = reusable.generate_totp(SEED)
                cmd = f"time radosgw-admin mfa check --uid {user_id} --totp-serial {serial} --totp-pin {get_totp}"
                mfa_check_resync = utils.exec_shell_cmd(cmd)
                if "ok" not in mfa_check_resync:
                    raise TestExecError("Failed to verify resync token")

        if config.test_ops["mfa_list"] is True:
            log.info("List MFA TOTP tokens")
            cmd = f"radosgw-admin mfa list --uid {user_id}"
            mfa_list = utils.exec_shell_cmd(cmd)
            if "MFAtest" in mfa_list:
                log.info("MFA token is listed for the given user")

        objects_created_list = []
        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                log.info("creating bucket with name: %s" % bucket_name_to_create)
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user
                )
                if config.test_ops.get("enable_mfa_version", False):
                    log.info("enable bucket versioning and MFA deletes")

                    token, status = reusable.enable_mfa_versioning(
                        bucket, rgw_conn, SEED, serial, each_user, write_bucket_io_info
                    )
                    if status is False:
                        log.info("trying again! AccessDenied could be a timing issue!")
                        new_token = reusable.generate_totp(SEED)
                        if token == new_token:
                            log.info("sleep of 30secs to generate another TOTP token")
                            time.sleep(30)
                        status = reusable.enable_mfa_versioning(
                            bucket,
                            rgw_conn,
                            SEED,
                            serial,
                            each_user,
                            write_bucket_io_info,
                        )
                        if status is False:
                            raise MFAVersionError(
                                "Failed to enable MFA and versioning on the bucket!"
                            )

                if config.test_ops["create_object"] is True:
                    # uploading data
                    log.info(f"top level s3 objects to create: {config.objects_count}")
                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, oc
                        )
                        log.info(f"s3 object name: {s3_object_name}")
                        s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                        log.info(f"s3 object path: {s3_object_path}")
                        if config.test_ops.get("upload_type") == "multipart":
                            log.info("upload type: multipart")
                            reusable.upload_mutipart_object(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                each_user,
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
                        objects_created_list.append((s3_object_name, s3_object_path))

                        # deleting the local file created after upload
                        if config.local_file_delete is True:
                            log.info("deleting local file created after the upload")
                            cmd = f"rm -rf {s3_object_path}"
                            utils.exec_shell_cmd(cmd)

                        # bucket list to check the objects
                        cmd = f"radosgw-admin bucket list --bucket {bucket_name_to_create}"
                        bucket_list = utils.exec_shell_cmd(cmd)

                if config.test_ops["delete_mfa_object"] is True:
                    for s3_object_name, path in objects_created_list:
                        log.info(
                            "Deleting an object configured with MFA should have TOTP token"
                        )
                        versions = bucket.object_versions.filter(Prefix=s3_object_name)
                        for version in versions:
                            log.info(
                                f"key_name: {version.object_key} --> version_id: {version.version_id}"
                            )
                            log.info("Deleting the object with TOTP token")
                            get_totp = reusable.generate_totp(SEED)
                            cmd = f"radosgw-admin object rm --object {version.object_key} --object-version {version.version_id} --totp-pin {get_totp} --bucket {bucket_name_to_create}"
                            object_delete = utils.exec_shell_cmd(cmd)
                            if object_delete is False:
                                raise TestExecError(
                                    "Object deletion with MFA token failed!"
                                )

                            log.info("Verify object is deleted permanently")
                            cmd = f"radosgw-admin bucket list --bucket {bucket_name_to_create}"
                            bucket_list = utils.exec_shell_cmd(cmd)
                            if version.version_id in bucket_list:
                                raise TestExecError(
                                    "Object version is still present, Failed to delete the object"
                                )

                if config.test_ops["delete_bucket"] is True:
                    log.info(f"Deleting the bucket {bucket_name_to_create}")
                    time.sleep(10)
                    reusable.delete_bucket(bucket)

                if config.test_ops["remove_mfa"] is True:
                    log.info(
                        "Delete a multi-factor authentication (MFA) time-based one time password (TOTP) token"
                    )
                    cmd = f"radosgw-admin mfa remove --uid {user_id} --totp-serial {serial}"
                    mfa_remove = utils.exec_shell_cmd(cmd)
                    if mfa_remove is False:
                        raise TestExecError("MFA delete failed")
                    log.info("Verify the MFA token is deleted")
                    cmd = (
                        f"radosgw-admin mfa get --uid {user_id} --totp-serial {serial}"
                    )
                    mfa_get = utils.exec_shell_cmd(cmd)
                    if mfa_get is False:
                        log.info("MFA token successfully deleted for user")
                    else:
                        raise TestExecError("MFA token delete for user failed")

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("Test rgw and Multi Factor Authentication")
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
