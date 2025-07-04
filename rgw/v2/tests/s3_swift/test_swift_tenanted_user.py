"""
test_swift_tenanted_user.py - Test Swift all type of  objects expiration

Usage: test_swift_tenanted_user.py -c <input_yaml>
<input_yaml>
    multisite_configs/test_swift_tenanted_user.yaml

"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import random
import string
import time
import traceback

import names
import swiftclient
import v2.lib.resource_op as swiftlib
import v2.utils.utils as utils
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.swift.auth import Auth
from v2.lib.sync_status import sync_status
from v2.tests.s3_swift import reusable
from v2.tests.s3_swift.reusables import swift_reusable as sr
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import HttpResponseParser, RGWService

log = logging.getLogger()

TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()
    ceph_conf = CephConfOp(ssh_con)
    log.info(type(ceph_conf))
    rgw_service = RGWService()
    # preparing data
    tenants_user_info = []
    tenant = "tenant"
    user_name = names.get_first_name() + random.choice(string.ascii_letters)

    tenant_user_info = umgmt.create_tenant_user(
        tenant_name=tenant, user_id=user_name, displayname=user_name
    )
    tenants_user_info.append(tenant_user_info)
    user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_name)
    auth = Auth(user_info, ssh_con, config.ssl)
    rgw = auth.do_auth()
    log.info(f"========{user_info}========")
    container_name = utils.gen_bucket_name_from_userid(
        user_info["user_id"], rand_no=str(3) + "new"
    )
    object_name = utils.gen_s3_object_name(f"{user_info['user_id']}.container.{1}", 1)
    rgw.put_container(container_name)
    rgw_secondary = reusable.get_remote_conn_in_multisite()
    log.info("Check sync status in local site")
    sync_status()

    log.info("Check sync status in remote site")
    sync_status(ssh_con=rgw_secondary)
    primary = utils.is_cluster_primary()
    if primary:
        remote_zone_name = "secondary"
    else:
        remote_zone_name = "primary"

    remote_rgw_ip = utils.get_rgw_ip_zone(remote_zone_name)
    log.info(f"remote_ip : {remote_rgw_ip}")
    local_script_path = "swift_upload.sh"
    remote_script_path = "/tmp/swift_upload.sh"

    user_id = user_info["user_id"]
    user_key = user_info["key"]

    shell_script = f"""#!/bin/bash

    # User variables
    RGW_HOST="{remote_rgw_ip}"
    RGW_PORT="80"
    USER_ID='{user_id}'
    SECRET_KEY="{user_key}"
    LOCAL_FILE="obj1.bin"
    CONTAINER="{container_name}"
    OBJECT="object1"
    
    dd if=/dev/zero of=$LOCAL_FILE bs=1M count=100
    sleep 10
    #set -x

    # Authenticate and get token and storage URL
    AUTH_RESPONSE=$(curl -s -i \\
      -H "X-Auth-User: $USER_ID" \\
      -H "X-Auth-Key: $SECRET_KEY" \\
      "http://$RGW_HOST:$RGW_PORT/auth/v1.0")
    
    #set +x

    STORAGE_URL=$(echo "$AUTH_RESPONSE" | grep -i "X-Storage-Url:" | awk '{{print $2}}' | tr -d '\\r')
    AUTH_TOKEN=$(echo "$AUTH_RESPONSE" | grep -i "X-Auth-Token:" | awk '{{print $2}}' | tr -d '\\r')

    if [[ -z "$STORAGE_URL" || -z "$AUTH_TOKEN" ]]; then
      echo "Failed to authenticate. Check your credentials and RGW endpoint."
      exit 1
    fi

    # Create a container
    echo "Creating container '$CONTAINER'..."
    curl -i -X PUT \\
      -H "X-Auth-Token: $AUTH_TOKEN" \\
      "$STORAGE_URL/$CONTAINER"
    echo

    # Upload an object to the container
    echo "Uploading file '$LOCAL_FILE' as object '$OBJECT' to container '$CONTAINER'..."
    curl -i -X PUT \\
      -H "X-Auth-Token: $AUTH_TOKEN" \\
      -T "$LOCAL_FILE" \\
      "$STORAGE_URL/$CONTAINER/$OBJECT"
    echo

    echo "Script completed."
    """

    local_script_path = "/tmp/swift_upload.sh"
    with open(local_script_path, "w") as f:
        f.write(shell_script)
    os.chmod(local_script_path, 0o755)  # Make script executable

    log.info(f"Shell script created at {local_script_path}")

    # Copy script to remote server
    sftp = rgw_secondary.open_sftp()
    sftp.put(local_script_path, remote_script_path)
    sftp.close()

    # Execute script on remote server
    stdin, stdout, stderr = rgw_secondary.exec_command(f"bash {remote_script_path}")
    log.info("--- Output ---")
    log.info(stdout.read().decode())
    log.info("--- Errors ---")
    log.info(stderr.read().decode())

    rgw_secondary.close()
    log.info("Done.")
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":

    test_info = AddTestInfo("test_swift_delete_during_sync")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW SWIFT Automation")
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
        config.read(ssh_con)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
