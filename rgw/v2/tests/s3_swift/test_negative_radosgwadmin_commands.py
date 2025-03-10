import argparse
import os
import sys
import subprocess
import yaml

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import v1.utils.log as log
from v1.utils.test_desc import AddTestInfo

def execute_command(command):
    """Executes a command and returns stdout, stderr, and return code."""
    process = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    return_code = process.returncode
    return return_code, stdout, stderr

def test_exec_primary(config, rgw_node):
    test_info = AddTestInfo("test multisite negative primary")
    try:
        test_info.started_info()
        commands = [
            f"radosgw-admin realm create --rgw-realm '' --default",
            f"radosgw-admin realm create --rgw-realm india --default",
            f"radosgw-admin zonegroup create --rgw-realm india --rgw-zonegroup '' --endpoints http://{rgw_node}:80 --master --default",
            f"radosgw-admin zonegroup create --rgw-realm india --endpoints http://{rgw_node}:80 --master --default",
            f"radosgw-admin zonegroup create --rgw-realm india --rgw-zonegroup shared --endpoints http://{rgw_node}:80 --master --default",
            f"radosgw-admin zonegroup create --rgw-realm india --rgw-zonegroup shared --endpoints http://{rgw_node}:80 --master --default",
            f"radosgw-admin zone create --rgw-realm india --rgw-zonegroup shared --rgw-zone '' --endpoints http://{rgw_node}:80 --master --default",
            f"radosgw-admin zone create --rgw-realm india --rgw-zonegroup shared --rgw-zone primary --endpoints http://{rgw_node}:80 --master --default",
            f"radosgw-admin zone create --rgw-realm india --rgw-zonegroup shared --rgw-zone primary --endpoints http://{rgw_node}:80 --master --default",
            f"radosgw-admin user create --uid=repuser --display_name='Replication user' --access-key 21e86bce636c3aa0 --secret cf764951f1fdde5d --rgw-realm india --system",
        ]
        for command in commands:
            log.info(f"Executing command: {command}. Error expected.")
            return_code, stdout, stderr = execute_command(command)
            if return_code == 0:
                test_info.failed_status(f"Command '{command}' succeeded unexpectedly. Stdout: {stdout}, Stderr: {stderr}, Return Code: {return_code}")
                sys.exit(1)
            else:
                log.info(f"{stderr} failed as expected.")

        test_info.success_status("Negative tests on ceph-pri completed")
        sys.exit(0)
    except Exception as e:
        log.error(f"An error occurred: {e}")
        test_info.failed_status(f"An error occurred: {e}")
        sys.exit(1)

def test_exec_secondary(config, rgw_node):
    test_info = AddTestInfo("test multisite negative secondary")
    try:
        test_info.started_info()
        commands = [
            f"radosgw-admin period pull --url http://invalidurl:80 --access-key 21e86bce636c3aa0 --secret cf764951f1fdde5d",
            f"radosgw-admin period pull --url http://{rgw_node}:80 --access-key 21e80 --secret dhejsbjans",
            f"radosgw-admin period pull --url http://{rgw_node}:80 --access-key 21e86bce636c3aa0 --secret ''",
            f"radosgw-admin period pull --url http://{rgw_node}:80 --access-key '' --secret ''",
            f"radosgw-admin period pull --url http://{rgw_node}:80 --access-key '' --secret '' --rgw-realm india --rgw-zonegroup shared --rgw-zone secondary",
        ]
        for command in commands:
            log.info(f"Executing command: {command}. Error expected.")
            return_code, stdout, stderr = execute_command(command)
            if return_code == 0:
                test_info.failed_status(f"Command '{command}' succeeded unexpectedly. Stdout: {stdout}, Stderr: {stderr}, Return Code: {return_code}")
                sys.exit(1)
            else:
                log.info(f"{stderr} failed as expected.")


        test_info.success_status("Negative tests on ceph-sec completed")
        sys.exit(0)
    except Exception as e:
        log.error(f"An error occurred: {e}")
        test_info.failed_status(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RGW Multisite Negative Tests")
    parser.add_argument("-c", dest="config", help="Test yaml configuration")
    parser.add_argument("--rgw-node", dest="rgw_node", help="rgw node ip")
    args = parser.parse_args()

    yaml_file = args.config
    config = {}
    if yaml_file:
        with open(yaml_file, "r") as f:
            config = yaml.safe_load(f)

    rgw_node = args.rgw_node

    if config.get("is_primary", True):  # Default to primary if not specified
        test_exec_primary(config, rgw_node)
    else:
        test_exec_secondary(config, rgw_node)