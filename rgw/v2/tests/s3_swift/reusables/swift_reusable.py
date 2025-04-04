import json
import logging
import os
import random
import string
import time
from datetime import datetime, timedelta, timezone

import v2.lib.manage_data as manage_data
import v2.utils.utils as utils
from swiftclient import ClientException
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()


def get_unique_name(length=7):
    characters = string.ascii_letters + string.digits
    return "".join(random.choices(characters, k=length))


def create_a_large_file(TEST_DATA_PATH, filename):
    file_path = os.path.join(TEST_DATA_PATH, filename)
    # data_info = manage_data.io_generator(file_path, 1073741824) #1GB File Creation
    data_info = manage_data.io_generator(file_path, 10000)  # small File Creation
    # Container and object detail
    log.info(f"md5 of uploading large file :{utils.get_md5(file_path)}")
    log.info(f"DATA INFO :: {data_info}")


def upload_segments(
    rgw, TEST_DATA_PATH, container_name, object_name, filename, segment_size
):
    """Upload segments of the binary file."""
    segment_list = []
    file_path = os.path.join(TEST_DATA_PATH, filename)

    with open(file_path, "rb") as f:
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
            segment_list.append(
                {
                    "path": f"/{container_name}/{segment_name}",
                    "etag": rgw.head_object(container_name, segment_name)["etag"],
                    "size_bytes": len(segment_data),
                }
            )

            log.info(f"Uploaded segment: {segment_name}")
            segment_number += 1

    return segment_list


def upload_manifest(rgw, container_name, object_name, segment_list):
    """upload the manifest file for the SLO."""

    rgw.put_object(
        container_name,
        object_name,
        contents=json.dumps(segment_list),
        query_string="multipart-manifest=put",
    )
    log.info(f"Manifest File : {json.dumps(segment_list)}")
    log.info(f"SLO manifest uploaded for '{object_name}'.")
    log.info(f"Static Large Object '{object_name}' uploaded successfully.")


def set_expiration(rgw, container_name, object_name, expiration_after=30):
    """Sets expiration for the SLO."""
    expiration_time = (
        datetime.now(timezone.utc) + timedelta(seconds=expiration_after)
    ).strftime(
        "%s"
    )  # Expire in 60 seconds
    rgw.post_object(
        container_name, object_name, headers={"X-Delete-At": expiration_time}
    )
    log.info(
        f"SLO '{object_name}' will expire at {datetime.fromtimestamp(int(expiration_time), tz=timezone.utc)} UTC."
    )


def verify_expiration(rgw, container_name, object_name, expiration_time=300):
    """Verifies that the SLO expires as expected."""
    log.info("Waiting for expiration...")
    time.sleep(expiration_time)  # Wait for expiration time

    try:
        metadata_verification = rgw.head_object(container_name, object_name)
        log.error("Error: Object still exists after expiration.")
        log.info(f"METADATA VERIFICATION : {metadata_verification}")
    except ClientException as e:
        if e.http_status == 404:
            log.info("Success: Object has expired and is no longer accessible.")
        else:
            log.info(f"Unexpected error: {e}")
