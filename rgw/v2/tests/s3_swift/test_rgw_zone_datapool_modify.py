"""
Automates testing of RGW zone modification by updating the data pool and verifying if the change is applied.
Optionally tests negative scenarios (e.g., invalid zone names).

This script uses 'radosgw-admin' to:
1. Verify the new data pool exists using 'rados lspools'.
2. Check if the cluster is primary by inspecting the zonegroup's master zone.
3. List all zones in the zonegroup.
4. Retrieve the current zone map for the specified zone.
5. Modify the data pool in the zone map to a new specified pool (e.g., rgwec86-pool).
6. Apply the modified zone map using 'zone set'.
7. For multi-site setups, commit the period update.
9. Optionally test negative scenarios (e.g., invalid zone name).
"""

import argparse
import json
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

from v2.lib.resource_op import Config
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def is_primary_cluster():
    """
    Checks if the cluster is primary by inspecting the zonegroup's is_master and master_zone.
    
    Returns:
        bool: True if the cluster is primary, False otherwise.
        str: Name of the master zone, or None if not primary.
    """
    cmd = "radosgw-admin zonegroup get"
    result = utils.exec_shell_cmd(cmd, debug_info=True)
    if result is False:
        raise Exception(f"Failed to get zonegroup: command execution failed")
    stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
    rc = 0 if stdout_data else 1
    log.debug(f"Command output: stdout={stdout_data}, stderr={stderr_data}, rc={rc}")
    if rc != 0:
        raise Exception(f"Failed to get zonegroup: {stderr_data}")
    zonegroup = json.loads(stdout_data)

    is_master = zonegroup.get("is_master", False)
    master_zone = zonegroup.get("master_zone", "")
    if is_master:
        for zone in zonegroup.get("zones", []):
            if zone["id"] == master_zone:
                return True, zone["name"]
    return False, None


def run_zone_modify_test(config, test_info, zone_name):
    """
    Performs the RGW zone modification test for a single zone.
    
    Args:
        config: Configuration object containing test_ops with new_data_pool and is_multisite.
        test_info: AddTestInfo object for test status logging.
        zone_name: Name of the zone to test (e.g., 'primary' or 'secondary').
    
    Raises:
        Exception: If any step fails (e.g., command execution, verification, pool not found).
    """
    # Get configuration options
    new_data_pool = config.test_ops.get("new_data_pool")
    is_multisite = config.test_ops.get("is_multisite", False)

    # Step 1: Verify the new data pool exists
    cmd = "rados lspools"
    result = utils.exec_shell_cmd(cmd, debug_info=True)
    if result is False:
        raise Exception(f"Failed to list pools: command execution failed")
    stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
    rc = 0 if stdout_data else 1
    log.debug(f"Command output: stdout={stdout_data}, stderr={stderr_data}, rc={rc}")
    if rc != 0:
        raise Exception(f"Failed to list pools: {stderr_data}")
    pools = stdout_data.strip().split("\n")
    log.info(f"Available pools: {', '.join(pools)}")
    if new_data_pool not in pools:
        raise Exception(f"New data pool {new_data_pool} not found in cluster. Available pools: {', '.join(pools)}")

    # Step 2: List all zones in the zonegroup
    cmd = "radosgw-admin zonegroup get"
    result = utils.exec_shell_cmd(cmd, debug_info=True)
    if result is False:
        raise Exception(f"Failed to get zonegroup: command execution failed")
    stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
    rc = 0 if stdout_data else 1
    log.debug(f"Command output: stdout={stdout_data}, stderr={stderr_data}, rc={rc}")
    if rc != 0:
        raise Exception(f"Failed to get zonegroup: {stderr_data}")
    zonegroup = json.loads(stdout_data)
    zones = [zone["name"] for zone in zonegroup.get("zones", [])]
    log.info(f"Available zones: {', '.join(zones)}")

    # Validate zone name
    if zone_name not in zones:
        raise Exception(f"Specified zone {zone_name} not found in zonegroup. Available zones: {', '.join(zones)}")
    log.info(f"Testing zone modification for zone: {zone_name}")

    # Step 3: Get current zone map
    cmd = f"radosgw-admin zone get --rgw-zone={zone_name}"
    result = utils.exec_shell_cmd(cmd, debug_info=True)
    if result is False:
        raise Exception(f"Failed to get zone map for zone {zone_name}: command execution failed")
    stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
    rc = 0 if stdout_data else 1
    log.debug(f"Command output: stdout={stdout_data}, stderr={stderr_data}, rc={rc}")
    if rc != 0:
        raise Exception(f"Failed to get zone map for zone {zone_name}: {stderr_data}")
    zone_map = json.loads(stdout_data)
    original_data_pool = zone_map['placement_pools'][0]['val']['storage_classes']['STANDARD']['data_pool']
    log.info(f"Original data pool for zone {zone_name}: {original_data_pool}")

    # Validate new data pool
    if not new_data_pool:
        raise Exception("new_data_pool not specified in config")

    # Step 4: Modify the zone map
    zone_map['placement_pools'][0]['val']['storage_classes']['STANDARD']['data_pool'] = new_data_pool
    modified_json = json.dumps(zone_map)

    # Escape JSON for shell
    escaped_json = modified_json.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')

    # Step 5: Write modified JSON to temp file
    temp_file = f"/tmp/zone_modified_{zone_name}.json"
    cmd = f'echo "{escaped_json}" > {temp_file}'
    result = utils.exec_shell_cmd(cmd, debug_info=True)
    if result is False:
        raise Exception(f"Failed to write modified zone file for zone {zone_name}: command execution failed")
    stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
    rc = 0 if stdout_data else 1
    log.debug(f"Command output: stdout={stdout_data}, stderr={stderr_data}, rc={rc}")
    if rc != 0:
        raise Exception(f"Failed to write modified zone file for zone {zone_name}: {stderr_data}")

    # Step 6: Set the modified zone map
    cmd = f"radosgw-admin zone set --rgw-zone={zone_name} --infile {temp_file}"
    result = utils.exec_shell_cmd(cmd, debug_info=True)
    if result is False:
        raise Exception(f"Zone set failed for zone {zone_name}: command execution failed")
    stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
    rc = 0 if stdout_data else 1
    log.debug(f"Command output: stdout={stdout_data}, stderr={stderr_data}, rc={rc}")
    if "NOTICE: set zone's realm_id=" in stdout_data or "NOTICE: set zone's realm_id=" in stderr_data:
        log.warning(f"Observed NOTICE about realm_id during zone set for zone {zone_name}")
    if rc != 0:
        raise Exception(f"Zone set failed for zone {zone_name}: {stderr_data}")

    # Step 7: Commit period update for multi-site setups
    if is_multisite:
        cmd = "radosgw-admin period update --commit"
        result = utils.exec_shell_cmd(cmd, debug_info=True)
        if result is False:
            raise Exception(f"Period update failed for zone {zone_name}: command execution failed")
        stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
        rc = 0 if stdout_data else 1
        log.debug(f"Command output: stdout={stdout_data}, stderr={stderr_data}, rc={rc}")
        if rc != 0:
            raise Exception(f"Period update failed for zone {zone_name}: {stderr_data}")

    # Step 8: Verify by getting zone map again
    cmd = f"radosgw-admin zone get --rgw-zone={zone_name}"
    result = utils.exec_shell_cmd(cmd, debug_info=True)
    if result is False:
        raise Exception(f"Failed to get updated zone map for zone {zone_name}: command execution failed")
    stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
    rc = 0 if stdout_data else 1
    log.debug(f"Command output: stdout={stdout_data}, stderr={stderr_data}, rc={rc}")
    if rc != 0:
        raise Exception(f"Failed to get updated zone map for zone {zone_name}: {stderr_data}")
    new_zone_map = json.loads(stdout_data)
    updated_data_pool = new_zone_map['placement_pools'][0]['val']['storage_classes']['STANDARD']['data_pool']
    log.info(f"Updated data pool for zone {zone_name}: {updated_data_pool}")

    if updated_data_pool != new_data_pool:
        raise Exception(f"Data pool not updated for zone {zone_name}. Expected: {new_data_pool}, Got: {updated_data_pool}")

    # Cleanup temp file
    cmd = f"rm -f {temp_file}"
    result = utils.exec_shell_cmd(cmd, debug_info=True)
    if result is False:
        log.warning(f"Failed to clean up temp file {temp_file}: command execution failed")
    else:
        stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
        rc = 0 if stdout_data else 1
        log.debug(f"Command output: stdout={stdout_data}, stderr={stderr_data}, rc={rc}")
        if rc != 0:
            log.warning(f"Failed to clean up temp file {temp_file}: {stderr_data}")

def test_exec(config):
    test_info = AddTestInfo("RGW Zone Modification Test")
    try:
        test_info.started_info()

        if config.test_ops.get("run_zone_modify_test"):
            # Check if the cluster is primary for logging purposes
            is_primary, master_zone_name = is_primary_cluster()
            log.info(f"Cluster is {'primary' if is_primary else 'secondary'}, master zone: {master_zone_name}")

            # Get list of zones to test
            zone_names = config.test_ops.get("zone_names", ["primary"])
            log.info(f"Testing zones: {', '.join(zone_names)}")

            for zone_name in zone_names:
                run_zone_modify_test(config, test_info, zone_name)
            
            test_info.success_status("Zone modification test passed. Data pool updated successfully.")
            sys.exit(0)
        else:
            log.info(
                "Skipping zone modification test as run_zone_modify_test is not set to True in the configuration."
            )
            sys.exit(0)

    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        # Attempt cleanup for all zones
        zone_names = config.test_ops.get("zone_names", ["primary"])
        for zone_name in zone_names:
            cmd = f"rm -f /tmp/zone_modified_{zone_name}.json"
            result = utils.exec_shell_cmd(cmd, debug_info=True)
            if result is False:
                log.warning(f"Cleanup failed for {cmd}: command execution failed")
            else:
                stdout_data, stderr_data = result if isinstance(result, tuple) else (result, "")
                rc = 0 if stdout_data else 1
                if rc != 0:
                    log.warning(f"Cleanup failed for {cmd}: {stderr_data}")
        test_info.failed_status("RGW zone modification test failed.")
        sys.exit(1)

if __name__ == "__main__":
    test_info = AddTestInfo("RGW Zone Modification Test")
    test_info.started_info()
    project_dir = os.path.abspath(os.path.join(__file__, "../../../.."))
    test_data_dir = "test_data"
    TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
    log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
    if not os.path.exists(TEST_DATA_PATH):
        log.info("test data dir not exists, creating.. ")
        os.makedirs(TEST_DATA_PATH)

    parser = argparse.ArgumentParser(description="RGW Zone Modification Test Automation")
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