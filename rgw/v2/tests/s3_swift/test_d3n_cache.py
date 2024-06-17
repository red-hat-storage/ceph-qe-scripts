import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import time
import traceback

import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()
    if config.d3n_feature is True:
        log.info("Enabling D3n feature on the cluster")
        data_path_cmd = f"sudo ls {config.datacache_path}"
        host_ips = utils.exec_shell_cmd("cut -f 1 /etc/hosts | cut -d ' ' -f 3")
        host_ips = host_ips.splitlines()
        log.info(f"hosts_ips: {host_ips}")
        for ip in host_ips:
            if ip.startswith("10."):
                log.info(f"ip is {ip}")
                ssh_con = utils.connect_remote(ip)
                stdin, stdout, stderr = ssh_con.exec_command(
                    "sudo netstat -nltp | grep radosgw"
                )
                netstst_op = stdout.readline().strip()
                log.info(f"netstat op on node {ip} is:{netstst_op}")
                if netstst_op:
                    log.info("Entering RGW node")
                    _, stdout, stderr = ssh_con.exec_command(data_path_cmd)
                    stderr = stderr.readline().strip()
                    if stderr:
                        log.info(f"creating datacache path")
                        create_cmd = f"sudo mkdir {config.datacache_path}"
                        log.info(f"executing command:{create_cmd}")
                        _, stdout, stderr = ssh_con.exec_command(create_cmd)
                        stderr = stderr.readline().strip()
                        if stderr:
                            raise AssertionError("datacache path creation failed!")
        rgw_service_name = utils.exec_shell_cmd("ceph orch ls | grep rgw").split(" ")[0]
        log.info(f"rgw service name is {rgw_service_name}")
        file_name = "/home/rgw_spec.yml"
        utils.exec_shell_cmd(
            f"ceph orch ls --service-name {rgw_service_name} --export > {file_name}"
        )
        op = utils.exec_shell_cmd(f"cat {file_name}")
        log.info(f"rgw spec is \n {op}")
        indent = " "
        new_content = f'extra_container_args:\n{indent} - "-v"\n{indent} - "{config.datacache_path}:{config.datacache_path}"'
        with open(file_name, "a") as f:
            f.write(new_content)
        op = utils.exec_shell_cmd(f"cat /home/rgw_spec.yml")
        log.info(f"Final rgw spec content is {op}")
        cmd = f"ceph orch apply -i {file_name}"
        utils.exec_shell_cmd(cmd)
        time.sleep(50)
        ceph_status = utils.exec_shell_cmd(cmd="sudo ceph status")
        if "HEALTH_ERR" in ceph_status:
            raise AssertionError("cluster is in HEALTH_ERR state")
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_d3n_l1_local_datacache_enabled,
            "true",
            ssh_con,
            set_to_all=True,
        )
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_d3n_l1_datacache_persistent_path,
            str(config.datacache_path),
            ssh_con,
            set_to_all=True,
        )
        ceph_conf.set_to_ceph_conf(
            "global",
            ConfigOpts.rgw_d3n_l1_datacache_size,
            str(config.datacache_size),
            ssh_con,
            set_to_all=True,
        )
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted")


if __name__ == "__main__":
    test_info = AddTestInfo("Testing D3N-Cache feature enablement")
    test_info.started_info()
    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        rgw_service = RGWService()
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
        ceph_conf = CephConfOp(ssh_con)
        config.read(ssh_con)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)
    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
