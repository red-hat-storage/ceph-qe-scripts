"""
Test bucket lifecycle for noncurrent version expiration after rgw_lc_debug_interval change.

Usage: test_lc_noncurrent_exp_restart.py -c configs/<input-yaml>
where : <input-yaml> is test_lc_noncurrent_exp_restart.yaml

Operation:
-Remove rgw_lc_debug_interval so cluster uses default
-Enable log_to_file, set rgw_lifecycle_work_time = 00:00-23:59 and restart RGW
-Create a user and a versioned bucket
-Apply lifecycle rule with Expiration and NoncurrentVersionExpiration
-Upload objects and overwrite them multiple times to create versions
-Stop RGW, set rgw_lc_debug_interval to 10, start RGW
-Wait for LC processing cycle
-Check RGW file logs for segmentation fault and check_for_crash
-Remove the user at successful completion
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
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
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService, rgw_daemons_status

log = logging.getLogger(__name__)
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    rgw_orch = json.loads(
        utils.exec_shell_cmd("ceph orch ls --service-type rgw -f json")
    )
    rgw_service_name = rgw_orch[0]["service_name"]
    log.info("rgw service name: %s" % rgw_service_name)

    log.info("removing rgw_lc_debug_interval to use cluster default")
    utils.exec_shell_cmd(
        "sudo ceph config rm client.%s rgw_lc_debug_interval" % rgw_service_name
    )
    utils.exec_shell_cmd("sudo ceph config rm client.rgw rgw_lc_debug_interval")

    log.info("enabling log_to_file so RGW segfaults are written under /var/log/ceph")
    ceph_conf.set_to_ceph_conf("global", ConfigOpts.log_to_file, "true", ssh_con)

    log.info("setting lifecycle work time with default rgw_lc_debug_interval")
    ceph_conf.set_to_ceph_conf(
        "global",
        ConfigOpts.rgw_lifecycle_work_time,
        str(config.rgw_lifecycle_work_time),
        ssh_con,
    )
    log.info("trying to restart services")
    srv_restarted = rgw_service.restart(ssh_con)
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info("RGW service restarted")

    user_info = s3lib.create_users(config.user_count)
    for each_user in user_info:
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        rgw_conn = auth.do_auth()
        rgw_conn2 = auth.do_auth_using_client()

        log.info("no of buckets to create: %s" % config.bucket_count)
        for bc in range(config.bucket_count):
            bucket_name = utils.gen_bucket_name_from_userid(
                each_user["user_id"], rand_no=bc
            )
            bucket = reusable.create_bucket(
                bucket_name, rgw_conn, each_user, ip_and_port
            )
            reusable.enable_versioning(
                bucket, rgw_conn, each_user, write_bucket_io_info
            )

            life_cycle_rule = {"Rules": config.lifecycle_conf}
            reusable.put_bucket_lifecycle(bucket, rgw_conn, rgw_conn2, life_cycle_rule)

            prefix = config.lifecycle_conf[0]["Filter"]["Prefix"]
            if config.test_ops["create_object"]:
                log.info("s3 objects to create: %s" % config.objects_count)
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = prefix + bucket.name + "." + str(oc)
                    if config.test_ops["version_count"] > 0:
                        for vc in range(config.test_ops["version_count"]):
                            log.info(
                                "version count for %s is %s" % (s3_object_name, str(vc))
                            )
                            log.info("modifying data: %s" % s3_object_name)
                            reusable.upload_object(
                                s3_object_name,
                                bucket,
                                TEST_DATA_PATH,
                                config,
                                each_user,
                                append_data=True,
                                append_msg="hello object for version: %s\n" % str(vc),
                            )
                    else:
                        reusable.upload_object(
                            s3_object_name,
                            bucket,
                            TEST_DATA_PATH,
                            config,
                            each_user,
                        )

            bucket_stats = json.loads(
                utils.exec_shell_cmd(
                    "radosgw-admin bucket stats --bucket=%s" % bucket.name
                )
            )
            initial_num_objects = bucket_stats["usage"]["rgw.main"]["num_objects"]
            log.info("bucket stats after upload, num_objects=%s" % initial_num_objects)

            restart_lc_debug_interval = config.test_ops.get(
                "restart_lc_debug_interval", 10
            )

            # Capture baseline on all RGW nodes before stop/set/start.
            # Use sudo bash -c so /var/log/ceph/* glob expands as root
            # (cephuser cannot expand that path before sudo).
            rgw_log_grep_cmd = (
                "sudo bash -c \"grep -F 'Caught signal (Segmentation fault)' "
                '/var/log/ceph/*/ceph-client.rgw*.log 2>/dev/null || true"'
            )
            rgw_ps = json.loads(
                utils.exec_shell_cmd("ceph orch ps --daemon_type rgw -f json")
            )
            rgw_hosts = sorted({daemon["hostname"] for daemon in rgw_ps})
            log.info("checking rgw logs on hosts: %s" % rgw_hosts)
            rgw_segfault_baseline = ""
            for host in rgw_hosts:
                host_ls = utils.exec_shell_cmd("ceph orch host ls | grep %s" % host)
                host_ip = host_ls.split()[1]
                log.info("grepping rgw logs on %s (%s)" % (host, host_ip))
                host_ssh = utils.connect_remote(host_ip)
                stdin, stdout, stderr = host_ssh.exec_command(rgw_log_grep_cmd)
                host_out = stdout.read().decode()
                host_err = stderr.read().decode()
                if host_err:
                    log.warning("rgw log grep stderr on %s: %s" % (host, host_err))
                log.info("rgw log grep on %s:\n%s" % (host, host_out))
                host_ssh.close()
                if host_out:
                    rgw_segfault_baseline += host_out
            baseline_segfault_count = str(rgw_segfault_baseline).count(
                "Caught signal (Segmentation fault)"
            )
            log.info(
                "rgw segfault baseline count=%s:\n%s"
                % (baseline_segfault_count, rgw_segfault_baseline)
            )

            log.info("stopping RGW service %s" % rgw_service_name)
            reusable.bring_down_all_rgws_in_the_site(rgw_service_name)

            log.info(
                "setting rgw_lc_debug_interval to %s while RGW is stopped"
                % restart_lc_debug_interval
            )
            ceph_conf.set_to_ceph_conf(
                "global",
                ConfigOpts.rgw_lc_debug_interval,
                str(restart_lc_debug_interval),
                ssh_con,
            )

            log.info("starting RGW service %s" % rgw_service_name)
            reusable.bring_up_all_rgws_in_the_site(rgw_service_name)
            time.sleep(30)

            if not rgw_daemons_status():
                raise TestExecError("RGW daemons not running after start")

            monitor_interval = config.test_ops.get("monitor_interval_sec", 10)
            lc_wait_timeout = config.test_ops.get("lc_wait_timeout_sec", 900)
            lc_min_wait_sec = config.test_ops.get(
                "lc_min_wait_sec", restart_lc_debug_interval * 6
            )
            post_lc_monitor_sec = config.test_ops.get("post_lc_monitor_sec", 30)
            log.info(
                "monitoring lc for up to %s sec (min %s sec) on bucket %s"
                % (lc_wait_timeout, lc_min_wait_sec, bucket.name)
            )
            elapsed = 0
            seen_processing = False
            processing_finished = False
            while elapsed < lc_wait_timeout:
                time.sleep(monitor_interval)
                elapsed += monitor_interval
                if not rgw_daemons_status(retry_attempts=1, retry_delay=5):
                    raise TestExecError("RGW daemon is down during LC wait period")
                lc_list = json.loads(utils.exec_shell_cmd("radosgw-admin lc list"))
                log.info("lc status after %s sec:\n%s" % (elapsed, lc_list))
                lc_status = None
                for data in lc_list:
                    if bucket.name in data["bucket"]:
                        lc_status = data["status"]
                        if lc_status == "PROCESSING":
                            seen_processing = True
                            processing_finished = False
                        elif lc_status == "COMPLETE" and seen_processing:
                            processing_finished = True
                        break
                bucket_stats = json.loads(
                    utils.exec_shell_cmd(
                        "radosgw-admin bucket stats --bucket=%s" % bucket.name
                    )
                )
                num_objects = bucket_stats["usage"]["rgw.main"]["num_objects"]
                log.info(
                    "num_objects=%s (initial=%s) lc_status=%s "
                    "seen_processing=%s processing_finished=%s"
                    % (
                        num_objects,
                        initial_num_objects,
                        lc_status,
                        seen_processing,
                        processing_finished,
                    )
                )
                if (
                    elapsed >= lc_min_wait_sec
                    and seen_processing
                    and processing_finished
                ):
                    log.info("lc processing cycle completed after %s sec" % elapsed)
                    break
            else:
                if not seen_processing:
                    raise TestExecError(
                        "LC never entered PROCESSING within %s seconds"
                        % lc_wait_timeout
                    )
                raise TestExecError(
                    "LC processing cycle did not finish within %s seconds"
                    % lc_wait_timeout
                )

            log.info(
                "continuing crash monitoring for %s sec after lc cycle"
                % post_lc_monitor_sec
            )
            post_elapsed = 0
            while post_elapsed < post_lc_monitor_sec:
                time.sleep(monitor_interval)
                post_elapsed += monitor_interval
                if not rgw_daemons_status(retry_attempts=1, retry_delay=5):
                    raise TestExecError("RGW daemon is down during post-LC monitoring")

            segfault_out = ""
            for host in rgw_hosts:
                host_ls = utils.exec_shell_cmd("ceph orch host ls | grep %s" % host)
                host_ip = host_ls.split()[1]
                log.info("grepping rgw logs on %s (%s)" % (host, host_ip))
                host_ssh = utils.connect_remote(host_ip)
                stdin, stdout, stderr = host_ssh.exec_command(rgw_log_grep_cmd)
                host_out = stdout.read().decode()
                host_err = stderr.read().decode()
                if host_err:
                    log.warning("rgw log grep stderr on %s: %s" % (host, host_err))
                log.info("rgw log grep on %s:\n%s" % (host, host_out))
                host_ssh.close()
                if host_out:
                    segfault_out += host_out
            segfault_count = str(segfault_out).count(
                "Caught signal (Segmentation fault)"
            )
            log.info(
                "rgw log segfault grep count=%s (baseline=%s):\n%s"
                % (segfault_count, baseline_segfault_count, segfault_out)
            )
            if segfault_count > baseline_segfault_count:
                raise TestExecError("Segmentation fault occured")

            cmd = f"radosgw-admin lc process --bucket {bucket_name}"
            err = utils.exec_shell_cmd(cmd, debug_info=True, return_err=True)
            log.info(f"ERROR: {err}")
            if "Segmentation fault" in str(err):
                raise TestExecError("Segmentation fault occured")

        reusable.remove_user(each_user)
        # check for any crashes during the execution
        crash_info = reusable.check_for_crash()
        if crash_info:
            raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo(
        "bucket life cycle: noncurrent expiration debug interval restart test"
    )
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
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
