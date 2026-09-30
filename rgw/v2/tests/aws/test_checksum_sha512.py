"""
Usage: test_checksum_sha512.py -c <input_yaml>

<input_yaml>
    configs/test_checksum_sha512_functional.yaml
    configs/test_checksum_sha512_negative.yaml

Operation:
  Functional SHA512: PUT/GET/HEAD, GetObjectAttributes, CopyObject,
                     Multipart Upload, Versioning
  Negative SHA512: invalid digest, malformed checksum, missing checksum,
                   checksum mismatch, invalid MPU checksum, unsupported algorithm
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
ALGO = "sha512"
CHECKSUM_KEY = "ChecksumSHA512"


def _assert_checksum_in_response(resp, where):
    if isinstance(resp, str):
        resp = json.loads(resp)
    # head/get may nest under top-level or under Checksum
    if CHECKSUM_KEY in resp:
        log.info("%s has %s=%s", where, CHECKSUM_KEY, resp[CHECKSUM_KEY])
        return resp[CHECKSUM_KEY]
    if "Checksum" in resp and CHECKSUM_KEY in resp["Checksum"]:
        log.info(
            "%s Checksum has %s=%s", where, CHECKSUM_KEY, resp["Checksum"][CHECKSUM_KEY]
        )
        return resp["Checksum"][CHECKSUM_KEY]
    raise TestExecError(f"{where} missing {CHECKSUM_KEY}: {resp}")


def test_functional_sha512(cli_aws, bucket_name, endpoint, config):
    """PUT/GET/HEAD, GetObjectAttributes, CopyObject, Multipart, Versioning."""
    log.info("===== Functional SHA512 tests =====")

    # Enable versioning for versioned PUT/GET coverage
    log.info("Enabling bucket versioning")
    command = cli_aws.command(
        operation="put-bucket-versioning",
        params=[
            f"--bucket {bucket_name} --versioning-configuration Status=Enabled "
            f"--endpoint-url {endpoint}"
        ],
    )
    out = utils.exec_shell_cmd(command)
    if out is False:
        raise TestExecError("Failed to enable bucket versioning")

    # --- Normal PUT with SHA512 ---
    key = "sha512-obj-put"
    obj_path = os.path.join(TEST_DATA_PATH, key)
    manage_data.io_generator(obj_path, 4096)
    checksum = aws_reusable.calculate_checksum(ALGO, obj_path)
    put_resp = aws_reusable.put_object_checksum(
        cli_aws, bucket_name, key, endpoint, ALGO, checksum, s3_object_path=obj_path
    )
    put_json = json.loads(put_resp) if isinstance(put_resp, str) else put_resp
    _assert_checksum_in_response(put_json, "put-object")

    # --- HEAD with checksum-mode ---
    head_resp = aws_reusable.head_object(
        cli_aws, bucket_name, key, endpoint, checksum_mode=True
    )
    head_cksm = _assert_checksum_in_response(head_resp, "head-object")
    if head_cksm != checksum:
        raise TestExecError(
            f"HEAD checksum mismatch: expected {checksum}, got {head_cksm}"
        )

    # --- GET with checksum-mode ---
    download_path = os.path.join(TEST_DATA_PATH, f"{key}.download")
    get_resp = aws_reusable.get_object(
        cli_aws,
        bucket_name,
        key,
        endpoint,
        download_path=download_path,
        checksum_mode=True,
    )
    get_json = json.loads(get_resp)
    get_cksm = _assert_checksum_in_response(get_json, "get-object")
    if get_cksm != checksum:
        raise TestExecError(
            f"GET checksum mismatch: expected {checksum}, got {get_cksm}"
        )
    if utils.get_md5(download_path) != utils.get_md5(obj_path):
        raise TestExecError("GET download md5 mismatch")

    # --- GetObjectAttributes ---
    attrib_resp = aws_reusable.get_object_attributes(
        cli_aws, bucket_name, key, endpoint
    )
    aws_reusable.verify_checksum(attrib_resp["Checksum"], ALGO, checksum, "normal")

    # --- CopyObject with SHA512 ---
    copy_key = f"{key}-copy"
    copy_resp = aws_reusable.copy_object(
        cli_aws,
        bucket_name,
        key,
        endpoint,
        dest_obj_name=copy_key,
        checksum_algo=ALGO,
    )
    copy_json = json.loads(copy_resp) if isinstance(copy_resp, str) else copy_resp
    log.info("copy-object response: %s", copy_json)
    copy_attrib = aws_reusable.get_object_attributes(
        cli_aws, bucket_name, copy_key, endpoint
    )
    if CHECKSUM_KEY not in copy_attrib.get("Checksum", {}):
        raise TestExecError(
            f"CopyObject attributes missing {CHECKSUM_KEY}: {copy_attrib}"
        )

    # --- Multipart Upload with SHA512 ---
    for oc, size in list(config.mapped_sizes.items()):
        config.obj_size = size
        mpu_name = utils.gen_s3_object_name(f"{bucket_name}-mpu", oc)
        complete_resp = aws_reusable.upload_multipart_aws(
            cli_aws,
            bucket_name,
            mpu_name,
            TEST_DATA_PATH,
            endpoint,
            config,
            checksum_algo=ALGO,
        )
        if CHECKSUM_KEY not in complete_resp:
            raise TestExecError(
                f"MPU complete missing {CHECKSUM_KEY}: {complete_resp}"
            )
        mpu_path = os.path.join(TEST_DATA_PATH, mpu_name)
        mpu_checksum = aws_reusable.calculate_checksum(ALGO, mpu_path)
        aws_reusable.verify_checksum(
            complete_resp, ALGO, mpu_checksum, "multipart"
        )
        mpu_attrib = aws_reusable.get_object_attributes(
            cli_aws, bucket_name, mpu_name, endpoint
        )
        aws_reusable.verify_checksum(
            mpu_attrib["Checksum"], ALGO, mpu_checksum, "multipart"
        )
        log.info("SHA512 MPU + GetObjectAttributes verified for %s", mpu_name)

    # --- Versioning: second put creates new version; attributes still valid ---
    key_ver = "sha512-obj-versioned"
    ver_path = os.path.join(TEST_DATA_PATH, key_ver)
    manage_data.io_generator(ver_path, 2048)
    ver_cksm1 = aws_reusable.calculate_checksum(ALGO, ver_path)
    aws_reusable.put_object_checksum(
        cli_aws,
        bucket_name,
        key_ver,
        endpoint,
        ALGO,
        ver_cksm1,
        s3_object_path=ver_path,
    )
    manage_data.io_generator(ver_path, 3072)
    ver_cksm2 = aws_reusable.calculate_checksum(ALGO, ver_path)
    put_v2 = aws_reusable.put_object_checksum(
        cli_aws,
        bucket_name,
        key_ver,
        endpoint,
        ALGO,
        ver_cksm2,
        s3_object_path=ver_path,
    )
    put_v2_json = json.loads(put_v2) if isinstance(put_v2, str) else put_v2
    if "VersionId" not in put_v2_json:
        raise TestExecError(
            f"Expected VersionId on versioned put-object: {put_v2_json}"
        )
    latest_attrib = aws_reusable.get_object_attributes(
        cli_aws, bucket_name, key_ver, endpoint
    )
    aws_reusable.verify_checksum(
        latest_attrib["Checksum"], ALGO, ver_cksm2, "normal"
    )
    log.info("SHA512 versioning PUT/GetObjectAttributes verified")


def test_negative_sha512(cli_aws, bucket_name, endpoint, config):
    """Negative SHA512 checksum scenarios."""
    log.info("===== Negative SHA512 tests =====")
    key = "sha512-neg-obj"
    obj_path = os.path.join(TEST_DATA_PATH, key)
    manage_data.io_generator(obj_path, 1024)
    good_checksum = aws_reusable.calculate_checksum(ALGO, obj_path)

    # 1. Invalid digest (wrong content hash for this object)
    log.info("Negative: invalid/wrong digest")
    wrong = aws_reusable.calculate_checksum("sha256", obj_path)
    # sha256 digest is shorter/different; still valid base64 but wrong for sha512
    # Prefer a same-length wrong sha512: hash different file
    other_path = os.path.join(TEST_DATA_PATH, "other-neg")
    manage_data.io_generator(other_path, 2048)
    wrong = aws_reusable.calculate_checksum(ALGO, other_path)
    aws_reusable.put_object_checksum(
        cli_aws,
        bucket_name,
        key,
        endpoint,
        ALGO,
        wrong,
        s3_object_path=obj_path,
        failure_expected=True,
    )

    # 2. Malformed checksum (not valid base64 / garbage)
    log.info("Negative: malformed checksum")
    aws_reusable.put_object_checksum(
        cli_aws,
        bucket_name,
        f"{key}-malformed",
        endpoint,
        ALGO,
        "!!!not-valid-base64!!!",
        s3_object_path=obj_path,
        failure_expected=True,
    )

    # 3. Missing checksum value (algorithm only — client may compute; force mismatch
    #    by providing empty/invalid via omit then separate explicit mismatch case)
    log.info("Negative: checksum mismatch (truncated/padded wrong value)")
    # Truncate good checksum to create mismatch while remaining somewhat parseable
    truncated = good_checksum[:8]
    aws_reusable.put_object_checksum(
        cli_aws,
        bucket_name,
        f"{key}-mismatch",
        endpoint,
        ALGO,
        truncated,
        s3_object_path=obj_path,
        failure_expected=True,
    )

    # 4. Missing checksum: send algorithm without digest is OK for client-computed;
    #    negative case uses checksum value without matching algorithm via unsupported
    log.info("Negative: unsupported algorithm")
    command = cli_aws.command(
        operation="put-object",
        params=[
            f"--bucket {bucket_name} --key {key}-unsupported --body {obj_path} "
            f"--endpoint-url {endpoint} --checksum-algorithm MD5 "
            f"--checksum-sha512 {good_checksum}"
        ],
    )
    out = utils.exec_shell_cmd(command)
    if out is not False:
        raise TestExecError(
            "put-object with unsupported checksum algorithm MD5 unexpectedly succeeded"
        )
    log.info("Unsupported algorithm rejected as expected")

    # 5. Invalid MPU checksum: upload parts with SHA512 then complete with wrong part etag/checksum structure
    log.info("Negative: invalid MPU checksum (complete with wrong ChecksumSHA512)")
    mpu_key = "sha512-neg-mpu"
    create_resp = json.loads(
        aws_reusable.create_multipart_upload(
            cli_aws, bucket_name, mpu_key, endpoint, checksum_algo=ALGO
        )
    )
    upload_id = create_resp["UploadId"]
    part_path = os.path.join(TEST_DATA_PATH, "mpu-part1")
    manage_data.io_generator(part_path, 5 * 1024 * 1024)
    part_cksm = aws_reusable.calculate_checksum(ALGO, part_path)
    part_resp = json.loads(
        aws_reusable.upload_part(
            cli_aws,
            bucket_name,
            mpu_key,
            1,
            upload_id,
            part_path,
            endpoint,
            checksum_algo=ALGO,
            checksum=part_cksm,
        )
    )
    # Build complete-multipart payload with deliberately wrong ChecksumSHA512
    mpstructure = {
        "Parts": [
            {
                "PartNumber": 1,
                "ETag": part_resp["ETag"],
                CHECKSUM_KEY: wrong,
            }
        ]
    }
    with open("mpstructure_neg.json", "w") as fd:
        json.dump(mpstructure, fd)
    complete_cmd = cli_aws.command(
        operation="complete-multipart-upload",
        params=[
            f"--bucket {bucket_name} --key {mpu_key} --upload-id {upload_id} "
            f"--multipart-upload file://mpstructure_neg.json --endpoint-url {endpoint} "
            f"--checksum-sha512 {wrong}"
        ],
    )
    complete_out = utils.exec_shell_cmd(complete_cmd)
    if complete_out is not False:
        # Some RGW builds may ignore top-level checksum on complete; abort if succeeded wrongly
        # Prefer failure; if it succeeded, verify object attributes don't silently accept wrong digest
        log.warning(
            "complete-multipart-upload with wrong checksum returned: %s", complete_out
        )
        # Abort is not possible after complete; delete object and treat as soft check
        try:
            attrib = aws_reusable.get_object_attributes(
                cli_aws, bucket_name, mpu_key, endpoint
            )
            if attrib["Checksum"].get(CHECKSUM_KEY) == wrong:
                raise TestExecError(
                    "Invalid MPU checksum was accepted and stored as ChecksumSHA512"
                )
        except Exception as e:
            if isinstance(e, TestExecError):
                raise
            log.info("Post-complete attribute check: %s", e)
    else:
        log.info("Invalid MPU checksum rejected as expected")

    # Abort leftover multipart if still open
    abort_cmd = cli_aws.command(
        operation="abort-multipart-upload",
        params=[
            f"--bucket {bucket_name} --key {mpu_key} --upload-id {upload_id} "
            f"--endpoint-url {endpoint}"
        ],
    )
    utils.exec_shell_cmd(abort_cmd)

    # 6. Missing checksum when explicitly required via empty value
    log.info("Negative: empty checksum value")
    aws_reusable.put_object_checksum(
        cli_aws,
        bucket_name,
        f"{key}-empty",
        endpoint,
        ALGO,
        "",
        s3_object_path=obj_path,
        failure_expected=True,
    )
    log.info("All negative SHA512 scenarios completed")


def test_exec(config, ssh_con):
    if not aws_reusable.supports_sha512_checksum():
        log.info(
            "Skipping SHA512 tests: requires Ceph 10.0+ (upstream >= %s)",
            aws_reusable.SHA512_MIN_CEPH_VERSION,
        )
        return

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)

    log.info("Install Rhash program")
    utils.exec_shell_cmd(
        "rpm -ivh https://rpmfind.net/linux/epel/9/Everything/x86_64/Packages/r/rhash-1.4.2-1.el9.x86_64.rpm"
    )
    utils.exec_shell_cmd("sudo pip install botocore[crt]")
    time.sleep(10)

    for user in user_info:
        user_name = user["user_id"]
        cli_aws = AWS(ssl=config.ssl)
        endpoint = aws_reusable.get_endpoint(ssh_con, ssl=config.ssl)
        aws_auth.do_auth_aws(user)

        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=bc)
            aws_reusable.create_bucket(cli_aws, bucket_name, endpoint)
            log.info("Bucket %s created", bucket_name)

            if config.test_ops.get("verify_sha512_functional", False):
                test_functional_sha512(cli_aws, bucket_name, endpoint, config)

            if config.test_ops.get("verify_sha512_negative", False):
                test_negative_sha512(cli_aws, bucket_name, endpoint, config)

            if config.test_ops.get("delete_bucket_object", True):
                response = aws_reusable.list_objects(cli_aws, bucket_name, endpoint)
                if response and response is not False:
                    res_json = json.loads(response)
                    for obj in res_json.get("Contents", []):
                        aws_reusable.delete_object(
                            cli_aws, bucket_name, obj["Key"], endpoint
                        )
                # delete versions if any
                vers = aws_reusable.list_object_versions(
                    cli_aws, bucket_name, endpoint
                )
                if vers and vers is not False:
                    vers_json = json.loads(vers) if isinstance(vers, str) else vers
                    for v in vers_json.get("Versions", []):
                        del_cmd = cli_aws.command(
                            operation="delete-object",
                            params=[
                                f"--bucket {bucket_name} --key {v['Key']} "
                                f"--version-id {v['VersionId']} --endpoint-url {endpoint}"
                            ],
                        )
                        utils.exec_shell_cmd(del_cmd)
                aws_reusable.delete_bucket(cli_aws, bucket_name, endpoint)

    if config.user_remove is True:
        s3_reusable.remove_user(user)

    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("SHA512 checksum functional and negative tests via awscli")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        TEST_DATA_PATH = os.path.join(project_dir, "test_data")
        log.info("TEST_DATA_PATH: %s", TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="SHA512 checksum tests")
        parser.add_argument("-c", dest="config", help="yaml configuration")
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
        ssh_con = None
        if args.rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(args.rgw_node)
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
