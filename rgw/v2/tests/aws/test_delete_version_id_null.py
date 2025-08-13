"""
Usage: test_delete_version_id_null.py -c configs/test_delete_version_id_null.yaml

<input_yaml>
    Note: Following yaml can be used
    configs/test_delete_version_id_null.yaml

Operation:
    Validates Null version id deletion using AWS

"""


import argparse
import json
import logging
import os
import random
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


import time
from pathlib import Path

from v2.lib import resource_op
from v2.lib.aws import auth as aws_auth
from v2.lib.aws.resource_op import AWS
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.sync_status import sync_status
from v2.tests.aws import reusable as aws_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger(__name__)
TEST_DATA_PATH = None

root_path = str(Path.home())
root_path = root_path + "/.aws/"


def test_exec(config, ssh_con):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    primary = utils.is_cluster_primary()
    if primary:
        current_zone_name = "primary"
        remote_zone_name = "secondary"
    else:
        current_zone_name = "secondary"
        remote_zone_name = "primary"

    current_rgw_ip = utils.get_rgw_ip_zone(current_zone_name)
    remote_rgw_ip = utils.get_rgw_ip_zone(remote_zone_name)
    log.info(f"current_ip : {current_rgw_ip}")
    log.info(f"remote_ip : {remote_rgw_ip}")
    remote_site_ssh_con = utils.connect_remote(remote_rgw_ip)
    log.info(f"remote_site_ssh_con : {remote_site_ssh_con}")

    for user in user_info:
        user_name = user["user_id"]
        log.info(user_name)
        cli_aws = AWS(ssl=config.ssl)
        aws_auth.do_auth_aws(user)
        aws_auth.do_auth_aws(user, remote_site_ssh_con)
        local_port = utils.get_radosgw_port_no(ssh_con)
        log.info(f"local_port is {local_port}")
        remote_port = utils.get_radosgw_port_no(remote_site_ssh_con)
        log.info(f"remote_port is {remote_port}")
        internet_protocol = "https" if config.ssl else "http"
        local_endpoint = f"{internet_protocol}://{current_rgw_ip}:{local_port}"
        remote_endpoint = f"{internet_protocol}://{remote_rgw_ip}:{remote_port}"

        bucket_name = "testbkt"
        aws_reusable.create_bucket(cli_aws, bucket_name, local_endpoint)
        log.info(f"Bucket {bucket_name} created")
        object_name = "hello.txt"
        utils.exec_shell_cmd(f"fallocate -l 1K {object_name}")
        aws_reusable.put_object(cli_aws, bucket_name, object_name, local_endpoint)

        # waiting for sync to be caught up with other site
        sync_status(ssh_con=remote_site_ssh_con)

        # Verifying object with version id null is created on both local and remote sites
        aws_reusable.verify_object_with_version_id_null(
            cli_aws, bucket_name, object_name, local_endpoint
        )
        aws_reusable.verify_object_with_version_id_null(
            cli_aws, bucket_name, object_name, remote_endpoint
        )

        log.info(
            f"Enabling versioning for the bucket {bucket_name} from local site:{current_zone_name}"
        )
        aws_reusable.put_get_bucket_versioning(cli_aws, bucket_name, local_endpoint)

        # Upload another version of the object to the bucket from local site
        aws_reusable.put_object(cli_aws, bucket_name, object_name, local_endpoint)

        sync_status(ssh_con=remote_site_ssh_con)

        version_list = aws_reusable.list_object_versions(
            cli_aws, bucket_name, local_endpoint
        )
        log.info(
            f"versions of objects for the bucket {bucket_name} from local site: {current_zone_name} is {version_list}"
        )

        version_list = aws_reusable.list_object_versions(
            cli_aws, bucket_name, remote_endpoint
        )
        log.info(
            f"versions of objects for the bucket {bucket_name} from remote site:{remote_zone_name} is {version_list}"
        )

        # Deleting object with version id null from local site
        aws_reusable.delete_object(
            cli_aws, bucket_name, object_name, local_endpoint, versionid="null"
        )
        sync_status(ssh_con=remote_site_ssh_con)

        # Verifying object with version id null is deleted from both sites:local and remote
        aws_reusable.verify_object_with_version_id_null(
            cli_aws, bucket_name, object_name, local_endpoint, created=False
        )
        aws_reusable.verify_object_with_version_id_null(
            cli_aws, bucket_name, object_name, remote_endpoint, created=False
        )

        s3_reusable.remove_user(user)

    # check for any crashes during the execution
    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test bucket creation through awscli")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(
            description="Validate null version id deletion using AWS"
        )
        parser.add_argument(
            "-c", dest="config", help="RGW Validate null version id deletion using AWS"
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
