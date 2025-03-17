"""
test_swift_static_large_object_expiration.py - Test expiration a Static large object. Check the time for delete

Usage: test_swift_static_large_object_expiration.py -c <input_yaml>

<input_yaml>
        swift_slo_expiry.yaml

Operation:
    Test expiration of a static large object. check after it got deleted.
    create_a_large_file
    upload segments
    create manifest file and upload
    set expiration
    verify expiration
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import logging
import traceback

import v2.lib.resource_op as swiftlib
import v2.utils.utils as utils
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
import v2.lib.manage_data as manage_data
from v2.lib.swift.auth import Auth
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
import time
from datetime import datetime,timezone, timedelta
import random, string
import json
from swiftclient import ClientException
import concurrent.futures
log = logging.getLogger()


TEST_DATA_PATH = None



def get_unique_name(length=7):
    characters = string.ascii_letters + string.digits
    return "".join(random.choices(characters,k=length))

container_name = "swiftuser_"+get_unique_name()
object_name = 'object_'+get_unique_name()
segment_prefix = f"{object_name}/segment"
segment_size_test =100000000
filename_test= "a_large_file"+get_unique_name(3)

def create_a_large_file(filename):
    file_path = os.path.join(TEST_DATA_PATH, filename)
    data_info = manage_data.io_generator(file_path, 1073741824) #1GB File Creation
    # Container and object detail
    print(f"DATA INFO :: {data_info}")

def upload_segments(rgw,filename,segment_size):
    """Upload segments of the binary file."""
    segment_list = []
    file_path = os.path.join(TEST_DATA_PATH, filename)

    with open(file_path, 'rb') as f:
        segment_number = 0
        while True:
            segment_data = f.read(segment_size)
            if not segment_data:
                break

            # Segment name
            segment_name = f"{object_name}/segment_{segment_number:08d}"

            # Upload the segment
            rgw.put_object(container_name, segment_name, contents=segment_data)

            # Add segment metadata to the manifest list
            segment_list.append({
                'path': f"/{container_name}/{segment_name}",
                'etag': rgw.head_object(container_name, segment_name)['etag'],
                'size_bytes': len(segment_data)
            })

            print(f"Uploaded segment: {segment_name}")
            segment_number += 1

    return segment_list

def create_slo_manifest(rgw, segment_list):
    """Create the manifest file for the SLO."""
    headers = {'X-Static-Large-Object': 'True'}
    rgw.put_object(container_name, object_name, contents=json.dumps(segment_list), headers=headers)
    print(f"SLO manifest created for '{object_name}'.")


def set_expiration(rgw):
    """Sets expiration for the SLO."""
    expiration_time = (datetime.now(timezone.utc) + timedelta(seconds=60)).strftime('%s')  # Expire in 60 seconds
    rgw.post_object(container_name, object_name, headers={'X-Delete-At': expiration_time})
    print(f"SLO '{object_name}' will expire at {datetime.fromtimestamp(int(expiration_time), tz=timezone.utc)} UTC.")

def verify_expiration(rgw):
    """Verifies that the SLO expires as expected."""
    print("Waiting for expiration...")
    time.sleep(70)  # Wait for 60 seconds + buffer
    try:
        rgw.head_object(container_name, object_name)
        print("Error: Object still exists after expiration.")
    except ClientException as e:
        if e.http_status == 404:
            print("Success: Object has expired and is no longer accessible.")
        else:
            print(f"Unexpected error: {e}")

def test_exec(config, ssh_con):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()

    # preparing data

    user_names = get_unique_name()
    print(f"Username : {user_names}")
    tenant = "tenant"
    tenant_user_info = umgmt.create_tenant_user(
        tenant_name=tenant, user_id=user_names, displayname=user_names
    )
    user_info = umgmt.create_subuser(tenant_name=tenant, user_id=user_names)

    auth = Auth(user_info, ssh_con)
    rgw = auth.do_auth()

    rgw.put_container(container_name)
    create_a_large_file(filename_test)
    # Upload segments and create manifest

    segments = upload_segments(rgw,
    filename_test,segment_size=segment_size_test)
    print(f"Static Large Object '{object_name}' uploaded successfully.")
    create_slo_manifest(rgw,segments)
    set_expiration(rgw)
    verify_expiration(rgw)




if __name__ == "__main__":

    test_info = AddTestInfo("swift slo expiration")

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
