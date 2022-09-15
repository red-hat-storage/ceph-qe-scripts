"""
test_rate_limit - Test rate limit on a User and Bucket level using s3cmd

Usage: test_rate_limit.py -c <input_yaml>

<input_yaml>
    Note: Following yaml can be used
    test_rate_limit.yaml

Polarion Tests:
CEPH-83574910
CEPH-83574913

Operation:
    Create an user
    Create a bucket with user credentials
    Enable the limits max-read-ops, max-read-bytes, max-write-ops, max-write-bytes on a Bucket scope
    Verify the rate limits using s3cmd
    Repeat the same limits on a User scope
"""

import argparse
import json
import logging
import os
import sys
import traceback
import subprocess
from time import sleep
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))


from v2.lib import resource_op
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.s3cmd import auth as s3_auth
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.lib.exceptions import S3CommandExecError
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None

def test_exec(config):
    """
    Executes test based on configuration passed
    Args:
        config(object): Test configuration
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    user_info = resource_op.create_users(no_of_users_to_create=config.user_count)[0]
    user_name = user_info["user_id"]

    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port()
    s3_auth.do_auth(user_info, ip_and_port)
    # add rate limit capability to rgw user
    caps_add = utils.exec_shell_cmd(
        f"radosgw-admin caps add --uid {user_name} --caps='users=*;buckets=*;ratelimit=*'"
    )
    data = json.loads(caps_add)
    caps = data["caps"]
    log.info(f" User Caps are :{caps}")

    #create bucket and set limits
    bucket_name = utils.gen_bucket_name_from_userid(user_name, rand_no=0)
    s3cmd_reusable.create_bucket(bucket_name)
    log.info(f"Bucket {bucket_name} created")
    limset = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit set --ratelimit-scope=bucket --bucket={bucket_name}"
        + " --max-read-ops=2 --max-read-bytes=4096 --max-write-bytes=4096 --max-write-ops=2"
    )
    log.info(f"Rate limits set on bucket {bucket_name}")
    limenable = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit enable --ratelimit-scope=bucket --bucket={bucket_name}"
    )
    limget = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit get --ratelimit-scope=bucket --bucket={bucket_name}"
    )
    log.info(f"Rate limits enabled on bucket : {limget} ")

    #test the read and write ops limit
    try:
        range_val = "{1..3}"
        cmd = (f"for i in {range_val}; do /home/cephuser/venv/bin/s3cmd ls s3://{bucket_name}/ ;done;")
        #rc = utils.exec_shell_cmd(cmd)
        rc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"

    log.info(f"Sleeping for a minute to reset limits")
    sleep(61)

    s3cmd_reusable.create_local_file("2k", "file1")
    try:
        range_val = "{1..3}"
        cmd = (
        f"for i in {range_val}; do /home/cephuser/venv/bin/s3cmd put file1 s3://{bucket_name}/files/file$i ;done;")
        #rc = utils.exec_shell_cmd(cmd)
        rc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"

    #sleep a minute to reset the ops limit
    log.info(f"Sleeping for a minute to reset limits")
    sleep(61)

    #test the read and write data limit
    try:
        range_val = "{1..3}"
        cmd = (f"for i in {range_val}; do /home/cephuser/venv/bin/s3cmd ls s3://{bucket_name}/files/file1 ;done;")
        #rc = utils.exec_shell_cmd(cmd)
        rc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"

    log.info(f"Sleeping for a minute to reset limits")
    sleep(61)
    try:
        range_val = "{1..3}"
        cmd = (f"for i in {range_val}; do /home/cephuser/venv/bin/s3cmd put file1 s3://{bucket_name}/files/file$i ;done;")
        #rc = utils.exec_shell_cmd(cmd)
        rc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"

    log.info(f"Sleeping for a minute to reset limits")
    sleep(61)

    #Set the rate limits for the user and enable them
    utils.exec_shell_cmd(f"radosgw-admin ratelimit disable --ratelimit-scope=bucket --bucket={bucket_name}")
    limset = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit set --ratelimit-scope=user --uid={user_name}"
        + " --max-read-ops=2 --max-read-bytes=4096 --max-write-bytes=4096 --max-write-ops=2"
    )
    log.info(f"Rate limits set on user {user_name}")
    limenable = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit enable --ratelimit-scope=user --uid={user_name}"
    )
    limget = utils.exec_shell_cmd(
        f"radosgw-admin ratelimit get --ratelimit-scope=user --uid={user_name}"
    )
    log.info(f"Rate limits enabled on bucket : {limget} ")

    #test the read and write ops limit
    bucket_name2 = utils.gen_bucket_name_from_userid(user_name, rand_no=1)
    s3cmd_reusable.create_bucket(bucket_name2)
    try:
        range_val = "{1..3}"
        cmd = (f"for i in {range_val}; do /home/cephuser/venv/bin/s3cmd ls s3://{bucket_name2}/ ;done;")
        #rc = utils.exec_shell_cmd(cmd)
        rc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"

    log.info(f"Sleeping for a minute to reset limits")
    sleep(61)
    try:
        range_val = "{1..3}"
        cmd = (f"for i in {range_val}; do /home/cephuser/venv/bin/s3cmd put file1 s3://{bucket_name2}/files/file$i ;done;")
        #rc = utils.exec_shell_cmd(cmd)
        rc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"

    # sleep a minute to reset the ops limit
    log.info(f"Sleeping for a minute to reset limits")
    sleep(61)

    # test the read and write data limit
    try:
        range_val = "{1..3}"
        cmd = (f"for i in {range_val}; do /home/cephuser/venv/bin/s3cmd ls s3://{bucket_name2}/files/file1 ;done;")
        #rc = utils.exec_shell_cmd(cmd)
        rc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"

    log.info(f"Sleeping for a minute to reset limits")
    sleep(61)
    try:
        range_val = "{1..3}"
        cmd = (f"for i in {range_val}; do /home/cephuser/venv/bin/s3cmd put file1 s3://{bucket_name2}/files/file$i ;done;")
        #rc = utils.exec_shell_cmd(cmd)
        rc = subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = rc.communicate()
        log.info(stdout)
        log.info(stderr)
    except Exception as e:
        raise S3CommandExecError(message=str(e))
    assert "503" in str(stderr), "Rate limit slowdown not observed, failing!"




if __name__ == "__main__":

    test_info = AddTestInfo("test bucket and user rate limits")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 bucket and user rate limits")
        parser.add_argument("-c", dest="config", help="RGW S3 bucket and user rate limits")
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
        config = resource_op.Config(yaml_file)
        config.read()
        test_exec(config)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)