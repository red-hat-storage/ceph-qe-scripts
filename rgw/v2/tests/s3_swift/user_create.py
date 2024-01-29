import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import json
import logging
import traceback

import v2.lib.resource_op as s3lib
import yaml
from swiftclient import ClientException
from v2.lib.admin import UserMgmt
from v2.lib.exceptions import RGWBaseException
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.lib.sync_status import sync_status
from v2.tests.s3_swift import reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

lib_dir = os.path.abspath(os.path.join(__file__, "../"))
log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    test_info = AddTestInfo("create users")
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    umgmt = UserMgmt()
    user_detail_file = os.path.join(lib_dir, "user_details.json")
    try:
        test_info.started_info()
        # create a non-tenanted user
        if config.user_type == "non-tenanted":
            all_users_info = s3lib.create_users(config.user_count)
            with open(user_detail_file, "w") as fout:
                json.dump(all_users_info, fout)
            test_info.success_status("non-tenanted users creation completed")
        else:
            log.info("create tenanted users")
            for i in range(config.user_count):
                tenant_name = "tenant" + str(i)
                all_users_info = s3lib.create_tenant_users(
                    config.user_count, tenant_name
                )
                with open(user_detail_file, "w") as fout:
                    json.dump(all_users_info, fout)
                test_info.success_status("tenanted users creation completed")
                if config.test_ops.get("swift_user", False):
                    user_name = all_users_info[0]["user_id"]
                    user_info = umgmt.create_subuser(
                        tenant_name=tenant_name, user_id=user_name
                    )
                    log.info(f"tenant subuser info: {user_info}")
                    if config.test_ops.get("modify_swift_user", False):
                        try:
                            access = "write"
                            cmd = f"radosgw-admin subuser modify --subuser={user_name}:swift --tenant={tenant_name} --uid={tenant_name}${user_name} --cluster ceph"
                            access_modify = f"{cmd} --access={access}"
                            subuser_info = json.loads(
                                utils.exec_shell_cmd(access_modify)
                            )
                            if subuser_info["subusers"][0]["permissions"] != access:
                                raise Exception(
                                    f"Failed to modify subuser {user_name}:swift access to {access}"
                                )
                            secret_key = "swiftsecretkey"
                            key_modify = f"{cmd}  --secret-key {secret_key}"
                            subuser_info = json.loads(utils.exec_shell_cmd(key_modify))
                            if (
                                subuser_info["swift_keys"][0]["secret_key"]
                                != secret_key
                            ):
                                raise Exception(
                                    f"Failed to modify subuser {user_name}:swift secret_key to {secret_key}"
                                )
                        except ClientException as e:
                            log.error(f"Subuser modification failed: {e}")
                        test_info.success_status(
                            f"Tenanted Swift user modification completed for {user_name}:swift"
                        )
        for user in all_users_info:
            if config.test_ops.get("user_modify_with_placementid", False):
                cmd = f'radosgw-admin user modify --uid={user["user_id"]} --placement-id "test"'
                out = utils.exec_shell_cmd(cmd, return_err=True)
                log.info(f"user modify with placement id out put is {out}")
                if "*** Caught signal (Aborted) **" in out:
                    raise AssertionError("user modify with placementid caused crash!!")

        is_multisite = utils.is_cluster_multisite()
        if is_multisite:
            log.info("Cluster is multisite")
            remote_site_ssh_con = reusable.get_remote_conn_in_multisite()

            log.info("Check sync status in local site")
            sync_status()

            log.info("Check sync status in remote site")
            sync_status(ssh_con=remote_site_ssh_con)

        test_info.success_status("test passed")
        sys.exit(0)
    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("user creation failed")
        sys.exit(1)
    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("user creation failed")
        sys.exit(1)


if __name__ == "__main__":
    test_info = AddTestInfo("user create test")
    test_info.started_info()
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
    with open(yaml_file, "r") as f:
        doc = yaml.safe_load(f)
        config.user_count = doc["config"]["user_count"]
        log.info("user_count:%s\n" % (config.user_count))
    test_exec(config, ssh_con)
