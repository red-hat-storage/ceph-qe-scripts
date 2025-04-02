"""
Usage: test_checksum.py -c <input_yaml>
Polarion ID : CEPH-83591699, CEPH-83591679
<input_yaml>
    Note: Following yaml can be used
    configs/test_wrong_checksum.yaml
    configs/test_checksum_api.yaml

Operation:
Multiple Checksum operations for all the new supported Checksum algorithms
"""


import argparse
import json
import logging
import os
import sys
import time
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


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
    user_name = config.test_ops["user_name"]
    user_names = [user_name] if type(user_name) != list else user_name
    if config.test_ops.get("user_name", False):
        user_info = resource_op.create_users(
            no_of_users_to_create=config.user_count,
            user_names=user_names,
        )
    else:
        user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    for user in user_info:
        user_name = user["user_id"]
        log.info(user_name)
        cli_aws = AWS(ssl=config.ssl)
        endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)
        aws_auth.do_auth_aws(user)

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            log.info(f"Bucket {bucket_name} created")
            obj = "file1"
            utils.exec_shell_cmd(f"fallocate -l 1K {obj}")

            if config.test_ops.get("verify_checksum_api", False):
                checksum_algorithm = "sha1"
                log.info(
                    f"Test put object for small and multipart objects with checksum enabled for {checksum_algorithm}"
                )
                checksum = aws_reusable.calculate_checksum(checksum_algorithm, obj)
                aws_reusable.put_object_checksum(
                    cli_aws, bucket_name, obj, endpoint, checksum_algorithm, checksum
                )

                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    key_name = utils.gen_s3_object_name(bucket_name, oc)
                    complete_multipart_upload_resp = aws_reusable.upload_multipart_aws(
                        cli_aws,
                        bucket_name,
                        key_name,
                        TEST_DATA_PATH,
                        endpoint,
                        config,
                        checksum_algo=checksum_algorithm,
                    )
                    log.info(list(complete_multipart_upload_resp.keys()))
                    algo = str(checksum_algorithm).upper()
                    if f"Checksum{algo}" not in list(
                        complete_multipart_upload_resp.keys()
                    ):
                        raise AssertionError(
                            "Checksum not generated during complete multipart upload operation"
                        )
                    log.info(
                        "Get Object Attributes for checksum on the multipart object"
                    )
                    attrib_resp = aws_reusable.get_object_attributes(
                        cli_aws,
                        bucket_name,
                        key_name,
                        endpoint,
                    )

                checksum_algorithm = "sha256"
                log.info(
                    f"Test put object for small and multipart objects with checksum enabled for {checksum_algorithm}"
                )
                checksum = aws_reusable.calculate_checksum(checksum_algorithm, obj)
                aws_reusable.put_object_checksum(
                    cli_aws, bucket_name, obj, endpoint, checksum_algorithm, checksum
                )

                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    key_name = utils.gen_s3_object_name(bucket_name, oc)
                    complete_multipart_upload_resp = aws_reusable.upload_multipart_aws(
                        cli_aws,
                        bucket_name,
                        key_name,
                        TEST_DATA_PATH,
                        endpoint,
                        config,
                        checksum_algo=checksum_algorithm,
                    )
                    algo = str(checksum_algorithm).upper()
                    if f"Checksum{algo}" not in list(
                        complete_multipart_upload_resp.keys()
                    ):
                        raise AssertionError(
                            "Checksum not generated during complete multipart upload operation"
                        )
                    log.info(
                        "Get Object Attributes for checksum on the multipart object"
                    )
                    attrib_resp = aws_reusable.get_object_attributes(
                        cli_aws,
                        bucket_name,
                        key_name,
                        endpoint,
                    )

                checksum_algorithm = "crc32"
                log.info(
                    f"Test put object for small and multipart objects with checksum enabled for {checksum_algorithm}"
                )
                checksum = aws_reusable.calculate_checksum(checksum_algorithm, obj)
                aws_reusable.put_object_checksum(
                    cli_aws, bucket_name, obj, endpoint, checksum_algorithm, checksum
                )

                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    key_name = utils.gen_s3_object_name(bucket_name, oc)
                    complete_multipart_upload_resp = aws_reusable.upload_multipart_aws(
                        cli_aws,
                        bucket_name,
                        key_name,
                        TEST_DATA_PATH,
                        endpoint,
                        config,
                        checksum_algo=checksum_algorithm,
                    )
                    algo = str(checksum_algorithm).upper()
                    if f"Checksum{algo}" not in list(
                        complete_multipart_upload_resp.keys()
                    ):
                        raise AssertionError(
                            "Checksum not generated during complete multipart upload operation"
                        )
                    log.info(
                        "Get Object Attributes for checksum on the multipart object"
                    )
                    attrib_resp = aws_reusable.get_object_attributes(
                        cli_aws,
                        bucket_name,
                        key_name,
                        endpoint,
                    )

                checksum_algorithm = "crc32c"
                log.info(
                    f"Test put object for small and multipart objects with checksum enabled for {checksum_algorithm}"
                )
                checksum = aws_reusable.calculate_checksum(checksum_algorithm, obj)
                aws_reusable.put_object_checksum(
                    cli_aws, bucket_name, obj, endpoint, checksum_algorithm, checksum
                )

                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    key_name = utils.gen_s3_object_name(bucket_name, oc)
                    complete_multipart_upload_resp = aws_reusable.upload_multipart_aws(
                        cli_aws,
                        bucket_name,
                        key_name,
                        TEST_DATA_PATH,
                        endpoint,
                        config,
                        checksum_algo=checksum_algorithm,
                    )
                    algo = str(checksum_algorithm).upper()
                    if f"Checksum{algo}" not in list(
                        complete_multipart_upload_resp.keys()
                    ):
                        raise AssertionError(
                            "Checksum not generated during complete multipart upload operation"
                        )
                    log.info(
                        "Get Object Attributes for checksum on the multipart object"
                    )
                    attrib_resp = aws_reusable.get_object_attributes(
                        cli_aws,
                        bucket_name,
                        key_name,
                        endpoint,
                    )

            else:
                log.info("Install Rhash program")
                utils.exec_shell_cmd(
                    "rpm -ivh https://rpmfind.net/linux/epel/9/Everything/x86_64/Packages/r/rhash-1.4.2-1.el9.x86_64.rpm"
                )
                time.sleep(2)
                log.info(
                    "Upload object with a wrongly computed checksum for all supported algorithms"
                )
                checksum_algorithm = "sha1"
                checksum_wrong = utils.exec_shell_cmd(f"rhash --sha1 {obj}").split(
                    " ", 1
                )[0]
                aws_reusable.put_object_checksum(
                    cli_aws,
                    bucket_name,
                    obj,
                    endpoint,
                    checksum_algorithm,
                    checksum_wrong,
                )

                checksum_algorithm = "sha256"
                checksum_wrong = utils.exec_shell_cmd(f"rhash --sha256 {obj}").split(
                    " ", 1
                )[0]
                aws_reusable.put_object_checksum(
                    cli_aws,
                    bucket_name,
                    obj,
                    endpoint,
                    checksum_algorithm,
                    checksum_wrong,
                )

                checksum_algorithm = "crc32"
                checksum_wrong = utils.exec_shell_cmd(f"rhash --crc32 {obj}").split(
                    " ", 1
                )[1]
                aws_reusable.put_object_checksum(
                    cli_aws,
                    bucket_name,
                    obj,
                    endpoint,
                    checksum_algorithm,
                    "randeasdc",
                )

                utils.exec_shell_cmd("sudo pip install botocore[crt]")
                checksum_algorithm = "crc32c"
                checksum_wrong = utils.exec_shell_cmd(f"rhash --crc32c {obj}").split(
                    " ", 1
                )[0]
                aws_reusable.put_object_checksum(
                    cli_aws,
                    bucket_name,
                    obj,
                    endpoint,
                    checksum_algorithm,
                    checksum_wrong,
                )

    if config.user_remove is True:
        s3_reusable.remove_user(user)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("Upload wrong checksum with put-object through awscli")

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
