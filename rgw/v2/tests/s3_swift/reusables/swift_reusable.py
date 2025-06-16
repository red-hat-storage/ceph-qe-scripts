import hashlib
import json
import logging
import os
import random
import string
import time
from datetime import datetime, timedelta, timezone

import v2.lib.manage_data as manage_data
import v2.utils.utils as utils
from cryptography.fernet import Fernet
from swiftclient import ClientException

log = logging.getLogger()


def get_unique_name(length=7):
    characters = string.ascii_letters + string.digits
    return "".join(random.choices(characters, k=length))


def create_a_large_file(TEST_DATA_PATH, filename, filesize=10000):
    file_path = os.path.join(TEST_DATA_PATH, filename)
    data_info = manage_data.io_generator(file_path, filesize)  # File Creation
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
    """Sets expiration for the objects"""
    expiration_time = (
        datetime.now(timezone.utc) + timedelta(seconds=expiration_after)
    ).strftime(
        "%s"
    )  # Expire in 60 seconds
    rgw.post_object(
        container_name, object_name, headers={"X-Delete-At": expiration_time}
    )
    log.info(
        f" '{object_name}' will expire at {datetime.fromtimestamp(int(expiration_time), tz=timezone.utc)} UTC."
    )


def verify_expiration(rgw, container_name, object_name, expiration_time=300):
    """Verifies that the Object expires as expected."""
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


def create_test_files(TEST_DATA_PATH, base_name, filetype, size_bytes=1024 * 10):
    # Create .txt file
    if filetype == "txt":
        txt_filename = f"{base_name}.txt"
        line = "This is a test line.\n"
        with open(os.path.join(TEST_DATA_PATH, txt_filename), "w") as f:
            lines_needed = size_bytes // len(line)
            for _ in range(lines_needed):
                f.write(line)
            # Fill up remaining bytes if needed
            remaining = size_bytes % len(line)
            if remaining:
                f.write("A" * remaining)
        print(f"Created {txt_filename} of size {size_bytes} bytes")
        return txt_filename

    # Create .bin file
    elif filetype == "bin":
        bin_filename = f"{base_name}.bin"
        with open(os.path.join(TEST_DATA_PATH, bin_filename), "wb") as f:
            f.write(os.urandom(size_bytes))
        print(f"Created {bin_filename} of size {size_bytes} bytes")
        return bin_filename

    # Create .tar file
    elif filetype == "tar":
        tar_filename = f"{base_name}.tar"
        with open(os.path.join(TEST_DATA_PATH, tar_filename), "wb") as f:
            f.write(b"A" * size_bytes)
        print(f"Created {tar_filename} of size {size_bytes} bytes")
        return tar_filename


def upload_regular_object(rgw, container_name, TEST_DATA_PATH):
    # Upload regular object
    filename_test = "regular-ob-" + get_unique_name(3)
    filename_test = create_test_files(TEST_DATA_PATH, filename_test, "txt")
    with open(os.path.join(TEST_DATA_PATH, filename_test), "rb") as f:
        rgw.put_object(container_name, filename_test, contents=f)
    print("Regular object uploaded.")


def upload_dlo(rgw, container_name, TEST_DATA_PATH, filesize=10000):
    # Upload DLO (Dynamic Large Object)
    segment_prefix = "dlo_segments/segment"
    segment_size = 1024 * 1024  # 1MB per segment
    object_name = "dlo_object"
    filename_test = "a_large_file" + get_unique_name(3)
    create_a_large_file(TEST_DATA_PATH, filename_test, filesize)
    with open(os.path.join(TEST_DATA_PATH, filename_test), "rb") as f:
        i = 0
        while True:
            chunk = f.read(segment_size)
            if not chunk:
                break
            rgw.put_object(container_name, f"{segment_prefix}{i}", contents=chunk)
            i += 1
    # Upload manifest
    rgw.put_object(
        container_name,
        object_name,
        contents="",
        headers={"X-Object-Manifest": f"{container_name}/{segment_prefix}"},
    )
    print("DLO uploaded.")


def upload_slo(rgw, container_name, TEST_DATA_PATH, filesize=10000):
    # Upload SLO (Static Large Object)
    segment_prefix = "slo_segments/segment"
    segment_size = 1024 * 1024
    manifest = []

    filename_test = "a_large_file" + get_unique_name(3)
    create_a_large_file(TEST_DATA_PATH, filename_test, filesize)
    with open(os.path.join(TEST_DATA_PATH, filename_test), "rb") as f:
        i = 0
        while True:
            chunk = f.read(segment_size)
            if not chunk:
                break
            segment_name = f"{segment_prefix}{i}"
            etag = hashlib.md5(chunk).hexdigest()
            rgw.put_object(container_name, segment_name, contents=chunk)
            manifest.append(
                {
                    "path": f"/{container_name}/{segment_name}",
                    "etag": etag,
                    "size_bytes": len(chunk),
                }
            )
            i += 1
    # Upload SLO manifest
    rgw.put_object(
        container_name,
        "slo_object",
        contents=json.dumps(manifest),
        headers={"X-Static-Large-Object": "True", "Content-Type": "application/json"},
    )
    print("SLO uploaded.")


def upload_multipart(rgw, container_name, TEST_DATA_PATH):
    # Multipart upload - SLO
    upload_slo(rgw, container_name, TEST_DATA_PATH, filesize=10000)
    print("Multipart (SLO) uploaded.")


def upload_encrypted_object(rgw, container_name, TEST_DATA_PATH):
    # Upload Encrypted object
    key = Fernet.generate_key()
    cipher = Fernet(key)
    filename_test = "encrypted-ob-" + get_unique_name(3)
    filename_test = create_test_files(TEST_DATA_PATH, filename_test, "txt")
    with open(os.path.join(TEST_DATA_PATH, filename_test), "rb") as f:
        encrypted = cipher.encrypt(f.read())
    rgw.put_object(container_name, filename_test, contents=encrypted)
    print("Encrypted object uploaded. Key:", key.decode())


def upload_compressed_object(rgw, container_name, TEST_DATA_PATH):
    # Upload Compressed object
    filename_test = "regular-ob-" + get_unique_name(3)
    filename_test = create_test_files(TEST_DATA_PATH, filename_test, "tar")
    with open(os.path.join(TEST_DATA_PATH, filename_test), "rb") as f:
        rgw.put_object(container_name, filename_test, contents=f)
    print("Compressed object uploaded.")


def list_all_objects(rgw, container_name):
    # List all containers
    containers = rgw.get_account()[1]
    for container in containers:
        container_name = container["name"]
        print(f"\nObjects in container: {container_name}")
        # List all objects in the container
        objects = rgw.get_container(container_name)[1]
        return objects


def verify_expiration_only(rgw, container_name, object_name):
    """Verifies that the Object expires as expected."""

    try:
        log.info("verifying the object expiration")
        metadata_verification = rgw.head_object(container_name, object_name)
        if metadata_verification:
            log.error("Error: Object still exists after expiration.")
            log.info(f"METADATA VERIFICATION : {metadata_verification}")
            return False

        else:
            log.info("Object Expired as expected")
            return True

    except ClientException as e:
        if e.http_status == 404:
            log.info("Success: Object has expired and is no longer accessible.")
        else:
            log.info(f"Unexpected error: {e}")
        return False


def execute_on_all_objects(rgw, container_name, func):
    """
    Execute func(object_name) for every object in the container.
    """
    # Get all objects in the container
    _, objects = rgw.get_container(container_name)
    print(objects)
    if objects is None:
        log.info("No Objects Found")

    for obj in objects:
        func(rgw, container_name, obj["name"])
        log.info(f"Executed{func} on {obj['name']}")
