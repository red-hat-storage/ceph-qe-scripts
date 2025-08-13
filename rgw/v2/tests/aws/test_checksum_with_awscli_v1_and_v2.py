"""
Usage: test_checksum_with_awscli_v1_and_v2.py -c <input_yaml>
Polarion ID : CEPH-83591679
<input_yaml>
    Note: Following yaml can be used
    rgw/v2/tests/aws/configs/test_checksum_awscli_v1_v2_small_objects.yaml
    rgw/v2/tests/aws/configs/test_checksum_awscli_v1_v2_non_multipart.yaml
    rgw/v2/tests/aws/configs/test_checksum_awscli_v1_v2_multipart.yaml

Operation:
testing checksum feature with
with awscli - v1 and v2
with default checksum enabled and disabled
with small, non-multipart and multipart objects
with all supported checksums - "sha1", "sha256", "crc32", "crc32c", "crc64nvme"

operations are put, copy, get, get-object-attributes, delete
"""


import argparse
import json
import logging
import os
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


import v2.lib.manage_data as manage_data
from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user_name = (config.test_ops.get("user_name"), None)
    user_names = [user_name] if type(user_name) != list else user_name
    if config.test_ops.get("user_name", False):
        user_info = resource_op.create_users(
            no_of_users_to_create=config.user_count,
            user_names=user_names,
        )
    else:
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    log.info("installing prerequisite tools")
    log.info("Install Rhash program")
    utils.exec_shell_cmd(
        "rpm -ivh https://rpmfind.net/linux/epel/9/Everything/x86_64/Packages/r/rhash-1.4.2-1.el9.x86_64.rpm"
    )
    utils.exec_shell_cmd("sudo pip install botocore[crt]")
    utils.exec_shell_cmd(
        "ls venvawsv1 || (python3 -m venv venvawsv1 && venvawsv1/bin/pip install awscli && venvawsv1/bin/pip install botocore[crt])"
    )
    log.info("sleeping for 10 seconds")
    time.sleep(10)

    for user in user_info:
        user_name = user["user_id"]
        log.info(user_name)
        cli_aws = AWS(ssl=config.ssl, bin_path="/usr/local/bin/")
        endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)
        aws_auth.do_auth_aws(user)

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            log.info(f"Bucket {bucket_name} created")

            aws_versions = ["v1", "v2"]
            for aws_version in aws_versions:
                if aws_version == "v1":
                    cli_aws = AWS(
                        ssl=config.ssl, bin_path="/home/cephuser/venvawsv1/bin/"
                    )
                    utils.exec_shell_cmd("/home/cephuser/venvawsv1/bin/aws --version")
                elif aws_version == "v2":
                    cli_aws = AWS(ssl=config.ssl, bin_path="/usr/local/bin/")
                    utils.exec_shell_cmd("/usr/local/bin/aws --version")

                default_checksum_flags = [True, False]
                for default_checksum_flag in default_checksum_flags:
                    if default_checksum_flag:
                        aws_auth.do_auth_aws(user)
                    else:
                        aws_auth.update_aws_file(
                            user, checksum_validation_calculation="when_required"
                        )

                    for oc, size in list(config.mapped_sizes.items()):
                        algo_list = ["sha1", "sha256", "crc32", "crc32c", "crc64nvme"]
                        for algo in algo_list:
                            s3_object_name_prefix = f"{bucket_name}_{aws_version}_{'default_cksm' if default_checksum_flag else 'default_cksm_disabled'}_{algo}"
                            config.obj_size = size
                            s3_object_name = utils.gen_s3_object_name(
                                s3_object_name_prefix, oc
                            )
                            log.info(f"s3 object name: {s3_object_name}")
                            s3_object_path = os.path.join(
                                TEST_DATA_PATH, s3_object_name
                            )
                            log.info(f"s3 object path: {s3_object_path}")

                            if config.test_ops.get("upload_type") == "multipart":
                                complete_multipart_upload_resp = (
                                    aws_reusable.upload_multipart_aws(
                                        cli_aws,
                                        bucket_name,
                                        s3_object_name,
                                        TEST_DATA_PATH,
                                        endpoint,
                                        config,
                                        checksum_algo=algo,
                                    )
                                )
                                checksum = aws_reusable.calculate_checksum(
                                    algo, s3_object_path
                                )
                                aws_reusable.verify_checksum(
                                    complete_multipart_upload_resp,
                                    algo,
                                    checksum,
                                    config.test_ops.get("upload_type"),
                                )
                            else:
                                log.info("upload type: normal")
                                data_info = manage_data.io_generator(
                                    s3_object_path, size
                                )
                                checksum = aws_reusable.calculate_checksum(
                                    algo, s3_object_path
                                )
                                aws_reusable.put_object_checksum(
                                    cli_aws,
                                    bucket_name,
                                    s3_object_name,
                                    endpoint,
                                    algo,
                                    checksum,
                                    s3_object_path,
                                )

                            # copy object
                            s3_copy_object_name = f"{s3_object_name}_copy"
                            log.info(
                                f"copying object {s3_object_name} to {s3_copy_object_name}"
                            )
                            out1 = aws_reusable.copy_object(
                                cli_aws,
                                bucket_name,
                                s3_object_name,
                                endpoint,
                                dest_obj_name=s3_copy_object_name,
                            )

                            # get-object-attributes on objects
                            attrib_resp = aws_reusable.get_object_attributes(
                                cli_aws,
                                bucket_name,
                                s3_object_name,
                                endpoint,
                            )
                            log.info(
                                f"Get Object Attributes response for checksum on {s3_object_name}: {attrib_resp}"
                            )
                            aws_reusable.verify_checksum(
                                attrib_resp["Checksum"],
                                algo,
                                checksum,
                                config.test_ops.get("upload_type"),
                            )
                            attrib_resp = aws_reusable.get_object_attributes(
                                cli_aws,
                                bucket_name,
                                s3_copy_object_name,
                                endpoint,
                            )
                            log.info(
                                f"Get Object Attributes response for checksum on {s3_object_name}: {attrib_resp}"
                            )
                            aws_reusable.verify_checksum(
                                attrib_resp["Checksum"],
                                algo,
                                checksum,
                                config.test_ops.get("upload_type"),
                            )

                            if config.test_ops["download_object"] is True:
                                # downloading s3 object
                                s3_object_download_name = (
                                    s3_object_name + "." + "download"
                                )
                                s3_object_download_path = os.path.join(
                                    TEST_DATA_PATH, s3_object_download_name
                                )
                                log.info(
                                    f"downloading {s3_object_name} to filename: {s3_object_download_name}"
                                )
                                aws_reusable.get_object(
                                    cli_aws,
                                    bucket_name,
                                    s3_object_name,
                                    endpoint,
                                    download_path=s3_object_download_path,
                                )
                                s3_object_downloaded_md5 = utils.get_md5(
                                    s3_object_download_path
                                )
                                s3_object_uploaded_md5 = utils.get_md5(s3_object_path)
                                # downloading s3 copy object
                                s3_object_copy_download_name = (
                                    s3_copy_object_name + "." + "download"
                                )
                                s3_object_copy_download_path = os.path.join(
                                    TEST_DATA_PATH, s3_object_copy_download_name
                                )
                                log.info(
                                    f"downloading {s3_copy_object_name} to filename: {s3_object_copy_download_path}"
                                )
                                aws_reusable.get_object(
                                    cli_aws,
                                    bucket_name,
                                    s3_copy_object_name,
                                    endpoint,
                                    download_path=s3_object_copy_download_path,
                                )
                                s3_object_copy_downloaded_md5 = utils.get_md5(
                                    s3_object_download_path
                                )
                                # verify md5
                                log.info(
                                    f"s3_object_uploaded_md5: {s3_object_uploaded_md5}"
                                )
                                log.info(
                                    f"s3_object_downloaded_md5: {s3_object_downloaded_md5}"
                                )
                                log.info(
                                    f"s3_object_copy_downloaded_md5: {s3_object_copy_downloaded_md5}"
                                )
                                if str(s3_object_uploaded_md5) == str(
                                    s3_object_downloaded_md5
                                ) and str(s3_object_uploaded_md5) == str(
                                    s3_object_copy_downloaded_md5
                                ):
                                    log.info("md5 match")
                                    utils.exec_shell_cmd(
                                        f"rm -rf {s3_object_download_path}"
                                    )
                                    utils.exec_shell_cmd(
                                        f"rm -rf {s3_object_copy_download_path}"
                                    )
                                else:
                                    raise TestExecError("md5 mismatch")

            if config.test_ops["delete_bucket_object"] is True:
                response = aws_reusable.list_objects(cli_aws, bucket_name, endpoint)
                res_json = json.loads(response)
                log.info("The list should not have the marker object entry")
                for obj in res_json["Contents"]:
                    key = obj["Key"]
                    log.info(f"deleting object :{key}")
                    aws_reusable.delete_object(cli_aws, bucket_name, key, endpoint)
                log.info("sleeping for 10 seconds")
                time.sleep(10)
                aws_reusable.delete_bucket(cli_aws, bucket_name, endpoint)

    if config.user_remove is True:
        s3_reusable.remove_user(user)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo(
        "Upload wrong checksum with put-object through awscli v1 and v2 with default checksum enabled/disabled"
    )

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Upload wrong checksum with put-object"
        )
        parser.add_argument(
            "-c", dest="config", help="Upload wrong checksum with put-object"
        )
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
        config = resource_op.Config(yaml_file)
        config.read()
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

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
