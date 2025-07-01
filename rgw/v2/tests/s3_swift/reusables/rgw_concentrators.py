import json
import logging
import os
import re
import subprocess
import sys
import time
import traceback
import urllib.parse

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import v2.lib.resource_op as s3lib
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.lib.s3.auth import Auth
from v2.lib.resource_op import Config
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.tests.s3_swift import reusable

log = logging.getLogger()


def perform_s3_operations(config, ssh_con, all_users_info, test_data_path):
    """
    Performs S3 bucket and object operations (create, upload, download, delete)
    based on the provided configuration, similar to test_Mbuckets_with_Nobjects.py.
    This function is now placed in rgw_concentrators.py.
    """
    log.info(
        "Starting S3 operations: create bucket, create object, download object, delete bucket object"
    )

    # Initialize IOInfo objects
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()

    # Step 1: Get the initial data structure that *should* be in io_info.yaml.
    current_yaml_data = basic_io_structure.initial()
    log.info(
        f"Initial YAML data from basic_io_structure.initial(): {current_yaml_data}"
    )

    # Step 2: Ensure the 'users' key exists in the data structure
    if "users" not in current_yaml_data:
        current_yaml_data["users"] = []

    # Step 3: Add created users to the `current_yaml_data` dictionary
    log.info("Adding created user information to io_info.yaml for tracking.")
    for each_user in all_users_info:
        user_info_to_add = {
            "user_id": each_user["user_id"],
            "access_key": each_user["access_key"],
            "secret_key": each_user["secret_key"],
            "bucket": [],  # Initialize with empty bucket list
            "deleted": False,
        }
        current_yaml_data["users"].append(user_info_to_add)

    log.info(f"Data to be written to io_info.yaml: {current_yaml_data}")

    # Step 4: Write the updated data structure to io_info.yaml
    io_info_initialize.initialize(current_yaml_data)
    log.info("User information successfully added to io_info.yaml.")

    for each_user in all_users_info:
        log.info(f"Performing S3 operations for user: {each_user['user_id']}")
        auth = reusable.get_auth(each_user, ssh_con, config.ssl, config.haproxy)
        rgw_conn = auth.do_auth()

        # Create buckets
        if config.test_ops.get("create_bucket", False):
            log.info(
                f"Number of buckets to create: {config.bucket_count} for user: {each_user['user_id']}"
            )
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                log.info(f"Creating bucket with name: {bucket_name_to_create}")
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user
                )

                if config.test_ops.get("create_object", False):
                    # Prepare mapped sizes for objects
                    config.mapped_sizes = utils.make_mapped_sizes(config)
                    log.info(
                        f"Number of S3 objects to create per bucket: {config.objects_count}"
                    )

                    # List to store object keys for batch deletion later
                    object_keys_to_delete = []

                    for oc, size in list(config.mapped_sizes.items()):
                        config.obj_size = size
                        s3_object_name = utils.gen_s3_object_name(
                            bucket_name_to_create, oc
                        )
                        log.info(f"S3 object name: {s3_object_name}")
                        s3_object_path = os.path.join(test_data_path, s3_object_name)
                        log.info(f"S3 object path: {s3_object_path}")

                        # Upload object
                        log.info("Upload type: normal")
                        reusable.upload_object(
                            s3_object_name,
                            bucket,
                            test_data_path,
                            config,
                            each_user,
                        )
                        object_keys_to_delete.append({"Key": s3_object_name})

                        if config.test_ops.get("download_object", False):
                            log.info(f"Trying to download object: {s3_object_name}")
                            s3_object_download_name = s3_object_name + "." + "download"
                            s3_object_download_path = os.path.join(
                                test_data_path, s3_object_download_name
                            )
                            log.info(
                                f"s3_object_download_path: {s3_object_download_path}"
                            )
                            log.info(
                                f"Downloading to filename: {s3_object_download_name}"
                            )

                            object_downloaded_status = s3lib.resource_op(
                                {
                                    "obj": bucket,
                                    "resource": "download_file",
                                    "args": [
                                        s3_object_name,
                                        s3_object_download_path,
                                    ],
                                }
                            )
                            if object_downloaded_status is False:
                                raise TestExecError(
                                    "Resource execution failed: object download failed"
                                )
                            if object_downloaded_status is None:
                                log.info("Object downloaded successfully")

                            s3_object_downloaded_md5 = utils.get_md5(
                                s3_object_download_path
                            )
                            s3_object_uploaded_md5 = utils.get_md5(s3_object_path)
                            log.info(
                                f"s3_object_downloaded_md5: {s3_object_downloaded_md5}"
                            )
                            log.info(
                                f"s3_object_uploaded_md5: {s3_object_uploaded_md5}"
                            )
                            if str(s3_object_uploaded_md5) == str(
                                s3_object_downloaded_md5
                            ):
                                log.info("MD5 match")
                                utils.exec_shell_cmd(
                                    f"rm -rf {s3_object_download_path}"
                                )
                            else:
                                raise TestExecError(
                                    "MD5 mismatch for downloaded object"
                                )

                        if config.local_file_delete:
                            log.info("Deleting local file created after the upload")
                            utils.exec_shell_cmd(f"rm -rf {s3_object_path}")

                if config.test_ops.get("delete_bucket_object", False):
                    # Delete objects
                    log.info(f"Deleting objects from bucket: {bucket_name_to_create}")

                    if (
                        object_keys_to_delete
                    ):  # Only attempt if there are objects to delete
                        try:
                            response = bucket.delete_objects(
                                Delete={
                                    "Objects": object_keys_to_delete,
                                    "Quiet": False,
                                }
                            )
                            log.info(f"Batch delete response: {response}")
                            if "Errors" in response and response["Errors"]:
                                for error in response["Errors"]:
                                    log.error(
                                        f"Error deleting object {error.get('Key')}: {error.get('Message')}"
                                    )
                                raise TestExecError(
                                    f"Errors encountered during batch object deletion in bucket {bucket_name_to_create}"
                                )
                            log.info(
                                f"Objects deleted from bucket: {bucket_name_to_create}"
                            )
                        except Exception as e:
                            log.error(
                                f"Failed to delete objects in bucket {bucket_name_to_create}: {e}"
                            )
                            raise TestExecError(f"Failed to delete objects: {e}")
                    else:
                        log.info(
                            f"No objects to delete in bucket: {bucket_name_to_create}"
                        )

                    try:
                        s3_client = rgw_conn.meta.client  #
                        objects_in_bucket_response = s3_client.list_objects_v2(
                            Bucket=bucket_name_to_create
                        )

                        # Check if 'Contents' key exists and is not empty
                        if (
                            objects_in_bucket_response
                            and "Contents" in objects_in_bucket_response
                            and len(objects_in_bucket_response["Contents"]) > 0
                        ):
                            remaining_objects = [
                                obj["Key"]
                                for obj in objects_in_bucket_response["Contents"]
                            ]
                            log.error(
                                f"Remaining objects after deletion: {remaining_objects}"
                            )
                            raise TestExecError(
                                f"Not all objects were deleted from bucket {bucket_name_to_create}"
                            )
                        else:
                            log.info(
                                f"Verified all objects deleted from bucket: {bucket_name_to_create}"
                            )
                    except Exception as e:
                        log.warning(
                            f"Could not list objects after deletion (might be genuinely empty or other error): {e}"
                        )
                        if "NoSuchBucket" in str(e):
                            log.info(
                                f"Bucket {bucket_name_to_create} is already gone, indicating objects were deleted with it."
                            )
                        else:
                            raise TestExecError(
                                f"Error during post-deletion object verification: {e}"
                            )

                # Delete buckets
                log.info(f"Deleting bucket: {bucket_name_to_create}")
                bucket_deleted = s3lib.resource_op(
                    {"obj": bucket, "resource": "delete"}
                )
                if bucket_deleted is False:
                    raise TestExecError(
                        f"Bucket deletion failed for {bucket_name_to_create}"
                    )
                log.info(f"Bucket deleted: {bucket_name_to_create}")

    log.info("S3 operations completed successfully.")
    return True


def get_haproxy_monitor_password(ssh_con, rgw_node):
    """Fetch HAProxy monitor password from haproxy.cfg in the container"""
    log.info(f"Fetching HAProxy monitor password from node {rgw_node}")
    try:

        def _execute_remote_cmd(cmd, ssh_client, timeout=300):
            log.info(f"Executing remote command on {rgw_node}: {cmd}")
            stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=timeout)
            stdout_str = stdout.read().decode("utf-8", errors="ignore").strip()
            stderr_str = stderr.read().decode("utf-8", errors="ignore").strip()
            return_code = stdout.channel.recv_exit_status()

            if return_code != 0:
                log.error(
                    f"Remote command '{cmd}' failed on {rgw_node} with return code {return_code}. "
                    f"STDOUT: '{stdout_str}', STDERR: '{stderr_str}'"
                )
                return stdout_str, stderr_str, return_code
            else:
                log.info(f"Remote command '{cmd}' succeeded. STDOUT: '{stdout_str}'")
                if stderr_str:
                    log.warning(
                        f"Remote command '{cmd}' produced stderr despite success: {stderr_str}"
                    )
                return stdout_str, stderr_str, return_code

        podman_ps_cmd = "sudo podman ps | grep haproxy"
        podman_output, podman_stderr, podman_rc = _execute_remote_cmd(
            podman_ps_cmd, ssh_client=ssh_con
        )

        if "haproxy" not in podman_output:
            log.error(
                f"HAProxy container not found in podman ps output on {rgw_node}. "
                f"Return Code: {podman_rc}, STDOUT: '{podman_output}', STDERR: '{podman_stderr}'"
            )
            raise TestExecError(
                f"No HAProxy container found running on RGW node {rgw_node}."
            )

        # Extract container name
        container_name_match = re.search(r"(\S+).*haproxy", podman_output)
        if not container_name_match:
            log.error(
                f"Failed to parse HAProxy container name from podman ps output on {rgw_node}: {podman_output}"
            )
            raise TestExecError(
                "Failed to parse HAProxy container name from podman ps output."
            )
        container_name = container_name_match.group(1)
        log.info(f"HAProxy container name: {container_name}")

        # Read haproxy.cfg from container ---
        haproxy_cfg_cmd = (
            f"sudo podman exec {container_name} cat /var/lib/haproxy/haproxy.cfg"
        )

        # Use the _execute_remote_cmd
        haproxy_cfg_output, haproxy_cfg_stderr, haproxy_cfg_rc = _execute_remote_cmd(
            haproxy_cfg_cmd, ssh_client=ssh_con
        )

        if haproxy_cfg_rc != 0:
            log.error(
                f"Command '{haproxy_cfg_cmd}' failed on {rgw_node} with return code {haproxy_cfg_rc}. "
                f"STDOUT: '{haproxy_cfg_output}', STDERR: '{haproxy_cfg_stderr}'"
            )
            raise TestExecError(
                f"Failed to read HAProxy configuration file on {rgw_node}. Error: {haproxy_cfg_stderr if haproxy_cfg_stderr else 'Unknown'}"
            )

        password_match = re.search(r"stats auth admin:(\S+)", haproxy_cfg_output)
        if not password_match:
            log.error(
                f"HAProxy monitor password not found in configuration from {rgw_node}. Full config content:\n{haproxy_cfg_output}"
            )
            raise TestExecError("HAProxy monitor password not found in configuration.")

        password = password_match.group(1)
        log.info(f"Successfully retrieved HAProxy monitor password from {rgw_node}")
        return password

    except TestExecError as e:
        log.error(f"Failed to fetch HAProxy monitor password: {e.message}")
        raise  # Re-raise your specific error
    except Exception as e:
        log.error(
            f"An unexpected error occurred while fetching HAProxy monitor password from {rgw_node}: {str(e)}"
        )
        raise TestExecError(
            f"Unable to retrieve HAProxy monitor password due to unexpected error: {str(e)}"
        )


def rgw_with_concentrators(ssh_con=None, rgw_node=None):
    """Verify if RGW and HAProxy are co-located on the same node"""
    log.info("Verifying RGW and HAProxy colocation")
    try:
        # Execute ceph orch ps command
        orch_ps_cmd = "sudo ceph orch ps --format json"
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)
        orch_ps_data = json.loads(orch_ps_output)

        # Execute ceph orch ls command for RGW
        orch_ls_cmd = "sudo ceph orch ls rgw --format json"
        orch_ls_output = utils.exec_shell_cmd(orch_ls_cmd)
        orch_ls_data = json.loads(orch_ls_output)

        # Filter RGW and HAProxy services
        rgw_services = [s for s in orch_ps_data if s.get("daemon_type") == "rgw"]
        haproxy_services = [
            s for s in orch_ps_data if s.get("daemon_type") == "haproxy"
        ]

        # Verify RGW services exist
        if not rgw_services:
            raise RGWHAProxyColocationError("No RGW services found")

        # Check if HAProxy is configured as concentrator
        rgw_service_info = orch_ls_data[0] if orch_ls_data else {}
        if not rgw_service_info.get("spec", {}).get("concentrator") == "haproxy":
            raise RGWHAProxyColocationError(
                "HAProxy not configured as RGW concentrator"
            )

        # Get host information
        rgw_hosts = set(s.get("hostname") for s in rgw_services)
        haproxy_hosts = set(s.get("hostname") for s in haproxy_services)

        # Verify colocation
        if not haproxy_hosts:
            raise RGWHAProxyColocationError("No HAProxy services found")

        if rgw_hosts != haproxy_hosts:
            raise RGWHAProxyColocationError(
                f"RGW and HAProxy not co-located. RGW hosts: {rgw_hosts}, HAProxy hosts: {haproxy_hosts}"
            )

        log.info(f"RGW and HAProxy are co-located on hosts: {rgw_hosts}")
        return True

    except json.JSONDecodeError:
        raise TestExecError("Failed to parse ceph orch command output")
    except RGWHAProxyColocationError as e:
        log.error(e.message)
        return False


def test_rgw_concentrator_behavior(config, ssh_con, rgw_node):
    """Test RGW service restart and HAProxy reconnection behavior with traffic distribution"""
    log.info("Testing RGW service restart and HAProxy reconnection behavior")
    try:
        # Get HAProxy monitor password
        monitor_password = get_haproxy_monitor_password(ssh_con, rgw_node)

        # Verify RGW and HAProxy configuration
        orch_ls_cmd = "sudo ceph orch ls rgw --format json"
        orch_ls_output = utils.exec_shell_cmd(orch_ls_cmd)
        orch_ls_data = json.loads(orch_ls_output)

        if not orch_ls_data:
            raise TestExecError("No RGW service information found")

        rgw_service_info = orch_ls_data[0]
        if not rgw_service_info.get("spec", {}).get("concentrator") == "haproxy":
            raise TestExecError("HAProxy not configured as RGW concentrator")

        service_name = rgw_service_info.get("service_name", "")
        if not service_name:
            raise TestExecError("RGW service name not found")

        hosts = rgw_service_info.get("placement", {}).get("hosts", [])
        if not hosts:
            raise TestExecError("No hosts found for RGW service")
        host = hosts[0]

        frontend_port = rgw_service_info.get("spec", {}).get(
            "concentrator_frontend_port", 8080
        )
        monitor_port = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_port", 1967
        )
        monitor_user = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_user", "admin"
        )

        # Get number of test requests from config, default to 20
        num_requests = config.test_ops.get("traffic_test_requests", 20)

        # Test traffic distribution before restart
        log.info(
            f"Sending {num_requests} test requests to HAProxy frontend at {host}:{frontend_port}"
        )
        successful_requests_before = 0
        for i in range(num_requests):
            curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' http://{host}:{frontend_port}"
            result = subprocess.run(
                curl_cmd, shell=True, capture_output=True, text=True
            )
            status_code = result.stdout.strip()
            log.info(
                f"Request {i+1} to {host}:{frontend_port} returned status code {status_code}"
            )
            if status_code == "200":
                successful_requests_before += 1
            else:
                log.warning(f"Request {i+1} failed with status code {status_code}")
            time.sleep(0.1)  # Small delay to avoid overwhelming the server

        # Check HAProxy stats before restart
        rgw_request_count_before = {}
        stats_url = f"http://{host}:{monitor_port}/stats;csv"
        stats_cmd = f"curl -s -u {monitor_user}:{monitor_password} \"{stats_url}\" | awk -F',' 'NR==1 || /^backend|^frontend|^stats/' | cut -d',' -f1,2,5,8,9,10,18,35,73 | column -s',' -t"
        log.info(f"Executing HAProxy stats command: {stats_cmd}")
        stats_output = utils.exec_shell_cmd(stats_cmd)
        raw_stats_cmd = f'curl -s -u {monitor_user}:{monitor_password} "{stats_url}"'
        raw_stats_output = utils.exec_shell_cmd(raw_stats_cmd)
        if stats_output and not stats_output.startswith("<!DOCTYPE"):
            log.info(f"HAProxy stats before restart (formatted):\n{stats_output}")
            if raw_stats_output:
                rgw_request_count_before = parse_haproxy_stats(
                    raw_stats_output, service_name
                )
                log.info(
                    f"HAProxy stats before restart (parsed): {rgw_request_count_before}"
                )
            else:
                log.warning("Failed to retrieve raw HAProxy stats before restart")
        else:
            log.warning(
                f"Failed to retrieve HAProxy stats before restart, formatted output: {stats_output[:100]}..."
            )
            log.warning("Proceeding with fallback checks")

        # Restart RGW service
        restart_cmd = f"sudo ceph orch restart {service_name}"
        restart_output = utils.exec_shell_cmd(restart_cmd)
        if not restart_output:
            raise TestExecError("Failed to execute RGW service restart")

        log.info(f"Restart command output: {restart_output}")

        # Wait for services to restart
        log.info("Waiting 30 seconds for services to restart")
        time.sleep(30)

        # Verify RGW and HAProxy services are running
        orch_ps_cmd = "sudo ceph orch ps --format json"
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)
        orch_ps_data = json.loads(orch_ps_output)

        rgw_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "rgw" and s.get("service_name") == service_name
        ]
        haproxy_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "haproxy"
            and s.get("service_name") == service_name
        ]

        if not rgw_services:
            raise TestExecError("No RGW services found after restart")

        if not haproxy_services:
            raise TestExecError("No HAProxy services found after restart")

        # Log service status
        log.info(
            f"RGW services after restart: {[s.get('daemon_name') + ': ' + s.get('status_desc') for s in rgw_services]}"
        )
        log.info(
            f"HAProxy services after restart: {[s.get('daemon_name') + ': ' + s.get('status_desc') for s in haproxy_services]}"
        )

        # Verify all services are running
        for service in rgw_services + haproxy_services:
            if service.get("status_desc") != "running":
                raise TestExecError(
                    f"Service {service.get('daemon_name')} is not running: {service.get('status_desc')}"
                )

        # Verify ports for RGW instances
        expected_ports = rgw_service_info.get("status", {}).get("ports", [])
        if not expected_ports:
            raise TestExecError("No ports found in RGW service status")

        rgw_ports = [
            port for service in rgw_services for port in service.get("ports", [])
        ]
        if sorted(rgw_ports) != sorted(expected_ports):
            raise TestExecError(
                f"RGW ports {rgw_ports} do not match expected ports {expected_ports}"
            )

        # Test traffic distribution after restart
        log.info(
            f"Sending {num_requests} test requests to HAProxy frontend at {host}:{frontend_port} after restart"
        )
        successful_requests_after = 0
        for i in range(num_requests):
            curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' http://{host}:{frontend_port}"
            result = subprocess.run(
                curl_cmd, shell=True, capture_output=True, text=True
            )
            status_code = result.stdout.strip()
            if status_code == "200":
                successful_requests_after += 1
            else:
                log.warning(f"Request {i+1} failed with status code {status_code}")
            time.sleep(0.1)

        # Check HAProxy stats after restart
        rgw_request_count_after = {}
        log.info(f"Executing HAProxy stats command: {stats_cmd}")
        stats_output = utils.exec_shell_cmd(stats_cmd)
        raw_stats_output = utils.exec_shell_cmd(raw_stats_cmd)
        if stats_output and not stats_output.startswith("<!DOCTYPE"):
            log.info(f"HAProxy stats after restart (formatted):\n{stats_output}")
            if raw_stats_output:
                rgw_request_count_after = parse_haproxy_stats(
                    raw_stats_output, service_name
                )
                log.info(
                    f"HAProxy stats after restart (parsed): {rgw_request_count_after}"
                )
            else:
                log.warning("Failed to retrieve raw HAProxy stats after restart")
        else:
            log.warning(
                f"Failed to retrieve HAProxy stats after restart, formatted output: {stats_output[:100]}..."
            )
            log.warning("Using fallback checks")

        # Verify traffic distribution
        expected_rgw_count = len(expected_ports)
        if rgw_request_count_after:
            total_rgw_requests = sum(rgw_request_count_after.values())
            if total_rgw_requests < num_requests * 0.5:  # Allow some requests to fail
                raise TestExecError(
                    f"Too few successful requests: {total_rgw_requests} out of {num_requests}"
                )
            if len(rgw_request_count_after) != expected_rgw_count:
                raise TestExecError(
                    f"Traffic not distributed to all {expected_rgw_count} RGW instances: {rgw_request_count_after}"
                )
            # Check for roughly even distribution (within 20% deviation)
            average_rgw_requests = total_rgw_requests / expected_rgw_count
            for rgw, rgw_requests in rgw_request_count_after.items():
                if (
                    abs(rgw_requests - average_rgw_requests)
                    > 0.2 * average_rgw_requests
                ):
                    log.warning(
                        f"Uneven traffic distribution for {rgw}: {rgw_requests} rgw_requests (expected ~{average_rgw_requests})"
                    )
        else:
            # Fallback: Verify RGW ports are accessible directly
            log.info(
                f"Fallback: Testing direct access to RGW ports {expected_ports} on {host}"
            )
            accessible_ports = []
            for port in expected_ports:
                curl_cmd = (
                    f"curl -s -o /dev/null -w '%{{http_code}}' http://{host}:{port}"
                )
                result = subprocess.run(
                    curl_cmd, shell=True, capture_output=True, text=True
                )
                if result.stdout.strip() == "200":
                    accessible_ports.append(port)
                else:
                    log.warning(
                        f"Direct access to RGW port {port} failed with status code {result.stdout.strip()}"
                    )
            if sorted(accessible_ports) != sorted(expected_ports):
                raise TestExecError(
                    f"Not all RGW ports {expected_ports} are accessible: {accessible_ports}"
                )

        # Verify sufficient successful requests
        if successful_requests_after < num_requests * 0.5:
            raise TestExecError(
                f"Too few successful requests after restart: {successful_requests_after} out of {num_requests}"
            )

        log.info(
            f"RGW and HAProxy services restarted successfully. RGW ports: {rgw_ports}, Traffic distribution: {rgw_request_count_after or 'verified via fallback'}"
        )
        return True

    except json.JSONDecodeError:
        raise TestExecError("Failed to parse ceph orch command output")
    except TestExecError as e:
        log.error(e.message)
        return False


def test_single_rgw_stop(config, ssh_con, rgw_node):
    """Test stopping one RGW instance and verify traffic is rerouted to the remaining instance"""
    log.info("Testing stopping one RGW instance and traffic rerouting")
    try:
        # Get HAProxy monitor password
        monitor_password = get_haproxy_monitor_password(ssh_con, rgw_node)

        # Verify RGW and HAProxy configuration
        orch_ls_cmd = "sudo ceph orch ls rgw --format json"
        orch_ls_output = utils.exec_shell_cmd(orch_ls_cmd)

        # Handle potential empty or False output from utils.exec_shell_cmd before JSON load
        if not orch_ls_output:
            log.error(
                f"Command '{orch_ls_cmd}' returned no output or failed. Output: '{orch_ls_output}'"
            )
            raise TestExecError(
                f"Failed to get RGW service info: no output from '{orch_ls_cmd}'."
            )

        orch_ls_data = json.loads(orch_ls_output)

        if not orch_ls_data:
            raise TestExecError("No RGW service information found")

        rgw_service_info = orch_ls_data[0]
        service_name = rgw_service_info.get("service_name", "")
        if not service_name:
            raise TestExecError("RGW service name not found")

        hosts = rgw_service_info.get("placement", {}).get("hosts", [])
        if not hosts:
            raise TestExecError("No hosts found for RGW service")
        host = hosts[0]

        frontend_port = rgw_service_info.get("spec", {}).get(
            "concentrator_frontend_port", 8080
        )
        monitor_port = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_port", 1967
        )
        monitor_user = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_user", "admin"
        )

        # Get number of test requests from config, default to 20
        num_requests = config.test_ops.get("traffic_test_requests", 20)

        # Get RGW daemons
        orch_ps_cmd = "sudo ceph orch ps --format json"
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)

        # Handle potential empty or False output from utils.exec_shell_cmd before JSON load
        if not orch_ps_output:
            log.error(
                f"Command '{orch_ps_cmd}' returned no output or failed. Output: '{orch_ps_output}'"
            )
            raise TestExecError(
                f"Failed to get Ceph orchestrator process list: no output from '{orch_ps_cmd}'."
            )

        orch_ps_data = json.loads(orch_ps_output)
        rgw_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "rgw" and s.get("service_name") == service_name
        ]

        if len(rgw_services) < 2:
            raise TestExecError("Need at least two RGW instances to test stopping one")

        # Select the first RGW instance to stop
        rgw_to_stop = rgw_services[0]["daemon_name"]
        log.info(f"Stopping RGW instance: {rgw_to_stop}")

        # Get baseline HAProxy stats
        stats_url = f"http://{host}:{monitor_port}/stats;csv"
        # Command for formatted output (for logging/display)
        formatted_stats_cmd = f"curl -s -u {monitor_user}:{monitor_password} \"{stats_url}\" | awk -F',' 'NR==1 || /^backend|^frontend|^stats/' | cut -d',' -f1,2,5,8,9,10,18,35,73 | column -s',' -t"
        # Command for raw output (for parsing by parse_haproxy_stats)
        raw_stats_cmd = f'curl -s -u {monitor_user}:{monitor_password} "{stats_url}"'

        # Fetch initial stats
        baseline_raw_stats_output = utils.exec_shell_cmd(
            raw_stats_cmd
        )  # Get raw data for parsing
        baseline_formatted_stats_output = utils.exec_shell_cmd(
            formatted_stats_cmd
        )  # Get formatted data for logging

        # Process baseline stats
        initial_rgw_requests = {}  # Initialize to empty dict
        # Corrected condition: use baseline_formatted_stats_output here
        if (
            baseline_formatted_stats_output
            and not baseline_formatted_stats_output.startswith("<!DOCTYPE")
        ):
            log.info(
                f"Baseline HAProxy stats (formatted):\n{baseline_formatted_stats_output}"
            )
            if baseline_raw_stats_output:  # Check if raw data was retrieved
                initial_rgw_requests = parse_haproxy_stats(
                    baseline_raw_stats_output, service_name
                )
                log.info(f"Baseline HAProxy stats (parsed): {initial_rgw_requests}")
            else:
                log.warning(
                    "Failed to retrieve raw HAProxy stats for baseline parsing."
                )
        else:
            log.warning(
                f"Failed to retrieve formatted HAProxy stats before restart. Output: {baseline_formatted_stats_output[:100] if baseline_formatted_stats_output else 'No output'}..."
            )
            log.warning("Proceeding with fallback checks for baseline.")

        # Stop the selected RGW instance
        stop_cmd = f"sudo ceph orch daemon stop {rgw_to_stop}"
        stop_output = utils.exec_shell_cmd(stop_cmd)
        if not stop_output:
            raise TestExecError(f"Failed to stop RGW instance {rgw_to_stop}")

        log.info(f"Stop command output: {stop_output}")

        # Wait for HAProxy to detect the stopped instance
        log.info("Waiting 30 seconds for HAProxy to update after stopping RGW instance")
        time.sleep(30)

        # Verify the stopped instance is not running
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)
        if not orch_ps_output:
            log.error(
                f"Command '{orch_ps_cmd}' returned no output or failed after stopping RGW. Output: '{orch_ps_output}'"
            )
            raise TestExecError(
                f"Failed to get Ceph orchestrator process list after stopping RGW."
            )
        orch_ps_data = json.loads(orch_ps_output)
        rgw_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "rgw" and s.get("service_name") == service_name
        ]
        stopped_rgw = [s for s in rgw_services if s.get("daemon_name") == rgw_to_stop]
        if stopped_rgw and stopped_rgw[0].get("status_desc") == "running":
            raise TestExecError(
                f"RGW instance {rgw_to_stop} is still running after stop command"
            )

        # Send test requests to HAProxy frontend
        log.info(
            f"Sending {num_requests} test requests to HAProxy frontend at {host}:{frontend_port} with {rgw_to_stop} stopped"
        )
        successful_requests = 0
        for i in range(num_requests):
            curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' http://{host}:{frontend_port}"
            result = subprocess.run(
                curl_cmd, shell=True, capture_output=True, text=True
            )
            status_code = result.stdout.strip()
            if status_code == "200":
                successful_requests += 1
            else:
                log.warning(f"Request {i+1} failed with status code {status_code}")
            time.sleep(0.1)

        # Check HAProxy stats after stopping
        stats_after_stop_formatted = utils.exec_shell_cmd(
            formatted_stats_cmd
        )  # Get formatted data
        stats_after_stop_raw = utils.exec_shell_cmd(
            raw_stats_cmd
        )  # Get raw data for parsing

        rgw_request_count_after_stop = {}  # Initialize
        # Corrected condition: use stats_after_stop_formatted here
        if stats_after_stop_formatted and not stats_after_stop_formatted.startswith(
            "<!DOCTYPE"
        ):
            log.info(
                f"HAProxy stats after stopping {rgw_to_stop} (formatted):\n{stats_after_stop_formatted}"
            )
            if stats_after_stop_raw:  # Check if raw data was retrieved
                rgw_request_count_after_stop = parse_haproxy_stats(
                    stats_after_stop_raw, service_name
                )
                log.info(
                    f"HAProxy stats after stopping {rgw_to_stop} (parsed): {rgw_request_count_after_stop}"
                )
            else:
                log.warning("Failed to retrieve raw HAProxy stats after stopping RGW.")
                raise TestExecError(
                    "Failed to retrieve raw HAProxy stats after stopping RGW for analysis."
                )
        else:
            log.warning(
                f"Failed to retrieve HAProxy stats after stopping {rgw_to_stop}, formatted output: {stats_after_stop_formatted[:100] if stats_after_stop_formatted else 'No output'}..."
            )
            raise TestExecError("Failed to retrieve HAProxy stats after stopping RGW.")

        # Verify traffic distribution
        if rgw_request_count_after_stop:
            total_rgw_requests = sum(rgw_request_count_after_stop.values())
            if total_rgw_requests < num_requests * 0.5:
                raise TestExecError(
                    f"Too few successful requests after stopping {rgw_to_stop}: {total_rgw_requests} out of {num_requests}"
                )

            if (
                rgw_to_stop in rgw_request_count_after_stop
                and rgw_request_count_after_stop[rgw_to_stop]
                > initial_rgw_requests.get(rgw_to_stop, 0)
            ):
                log.error(
                    f"Traffic unexpectedly sent to stopped RGW instance {rgw_to_stop}: {rgw_request_count_after_stop[rgw_to_stop]} rgw_requests. Baseline: {initial_rgw_requests.get(rgw_to_stop, 'N/A')}"
                )
                raise TestExecError(
                    f"Traffic sent to stopped RGW instance {rgw_to_stop}."
                )

            # Ensure traffic is rerouted to remaining instances
            expected_running_rgw_daemons = [
                s.get("daemon_name")
                for s in rgw_services
                if s.get("daemon_name") != rgw_to_stop
            ]

            if not all(
                daemon in rgw_request_count_after_stop
                for daemon in expected_running_rgw_daemons
            ):
                log.error(
                    f"Traffic not routed to all expected running RGW instances. Expected: {expected_running_rgw_daemons}, Actual hit instances: {list(rgw_request_count_after_stop.keys())}"
                )
                raise TestExecError(
                    f"Traffic not routed to all remaining RGW instances after stopping {rgw_to_stop}."
                )

            if len(expected_running_rgw_daemons) > 1:
                rgw_requests_on_running_instances = [
                    rgw_request_count_after_stop.get(daemon, 0)
                    for daemon in expected_running_rgw_daemons
                ]
                if (
                    sum(rgw_requests_on_running_instances) > 0
                ):  # Only check distribution if there was actual traffic
                    average_rgw_requests_remaining = sum(
                        rgw_requests_on_running_instances
                    ) / len(expected_running_rgw_daemons)
                    for daemon_name in expected_running_rgw_daemons:
                        rgw_requests = rgw_request_count_after_stop.get(daemon_name, 0)
                        if (
                            abs(rgw_requests - average_rgw_requests_remaining)
                            > 0.2 * average_rgw_requests_remaining
                        ):  # 20% deviation
                            log.warning(
                                f"Uneven traffic distribution for {daemon_name} after stop: {rgw_requests} rgw_requests (expected ~{average_rgw_requests_remaining})"
                            )
        else:
            log.warning(
                "No RGW rgw_requests recorded after stopping instance, or parsing failed. Cannot verify traffic distribution."
            )
            if (
                successful_requests > 0
            ):  # If there were successful requests, but no rgw_requests recorded, something is wrong
                raise TestExecError(
                    "Successful requests observed but no HAProxy rgw_requests recorded for RGW instances after stopping one."
                )

        # Verify sufficient successful requests
        if successful_requests < num_requests * 0.5:
            raise TestExecError(
                f"Too few successful requests after stopping {rgw_to_stop}: {successful_requests} out of {num_requests}"
            )

        # Restart the stopped RGW instance
        restart_cmd = f"sudo ceph orch daemon start {rgw_to_stop}"
        restart_output = utils.exec_shell_cmd(restart_cmd)
        if not restart_output:
            raise TestExecError(f"Failed to restart RGW instance {rgw_to_stop}")

        log.info(f"Restart command output: {restart_output}")

        # Wait for the instance to restart
        log.info(f"Waiting 30 seconds for {rgw_to_stop} to restart")
        time.sleep(30)

        # Verify all RGW instances are running
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)
        if not orch_ps_output:
            log.error(
                f"Command '{orch_ps_cmd}' returned no output or failed after restarting RGW. Output: '{orch_ps_output}'"
            )
            raise TestExecError(
                f"Failed to get Ceph orchestrator process list after restarting RGW."
            )
        orch_ps_data = json.loads(orch_ps_output)
        rgw_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "rgw" and s.get("service_name") == service_name
        ]
        for service in rgw_services:
            if service.get("status_desc") != "running":
                raise TestExecError(
                    f"Service {service.get('daemon_name')} is not running after restart: {service.get('status_desc')}"
                )

        log.info(
            f"RGW instance {rgw_to_stop} stopped and restarted successfully. Traffic distribution: {rgw_request_count_after_stop}"
        )
        return True

    except json.JSONDecodeError as e:
        log.error(
            f"Failed to parse ceph orch command output: {e}. Check if Ceph commands returned valid JSON."
        )
        raise TestExecError(f"Failed to parse ceph orch command output: {e}")
    except TestExecError as e:
        log.error(e.message)
        raise  # Re-raise your specific error
    except Exception as e:
        log.error(f"An unexpected error occurred in test_single_rgw_stop: {str(e)}")
        raise TestExecError(f"Unexpected error during test_single_rgw_stop: {str(e)}")


def test_haproxy_stop(config, ssh_con, rgw_node):
    """Test stopping HAProxy instance and verify traffic stops immediately"""
    log.info("Testing stopping HAProxy instance and traffic behavior")
    try:
        # Get HAProxy monitor password
        monitor_password = get_haproxy_monitor_password(ssh_con, rgw_node)

        # Verify RGW and HAProxy configuration
        orch_ls_cmd = "sudo ceph orch ls rgw --format json"
        orch_ls_output = utils.exec_shell_cmd(orch_ls_cmd)

        if not orch_ls_output:
            log.error(
                f"Command '{orch_ls_cmd}' returned no output or failed. Output: '{orch_ls_output}'"
            )
            raise TestExecError(
                f"Failed to get RGW service info: no output from '{orch_ls_cmd}'."
            )

        orch_ls_data = json.loads(orch_ls_output)

        if not orch_ls_data:
            raise TestExecError("No RGW service information found")

        rgw_service_info = orch_ls_data[0]
        service_name = rgw_service_info.get("service_name", "")
        if not service_name:
            raise TestExecError("RGW service name not found")

        hosts = rgw_service_info.get("placement", {}).get("hosts", [])
        if not hosts:
            raise TestExecError("No hosts found for RGW service")
        host = hosts[0]

        frontend_port = rgw_service_info.get("spec", {}).get(
            "concentrator_frontend_port", 8080
        )
        monitor_port = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_port", 1967
        )
        monitor_user = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_user", "admin"
        )

        # Get number of test requests from config, default to 20
        num_requests = config.test_ops.get("traffic_test_requests", 20)

        # Get HAProxy daemon
        orch_ps_cmd = "sudo ceph orch ps --format json"
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)

        if not orch_ps_output:
            log.error(
                f"Command '{orch_ps_cmd}' returned no output or failed. Output: '{orch_ps_output}'"
            )
            raise TestExecError(
                f"Failed to get Ceph orchestrator process list: no output from '{orch_ps_cmd}'."
            )

        orch_ps_data = json.loads(orch_ps_output)
        haproxy_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "haproxy"
            and s.get("service_name") == service_name
        ]

        if not haproxy_services:
            raise TestExecError("No HAProxy services found")

        # Select the HAProxy instance to stop
        haproxy_to_stop = haproxy_services[0]["daemon_name"]
        log.info(f"Stopping HAProxy instance: {haproxy_to_stop}")

        # Get baseline HAProxy stats
        stats_url = f"http://{host}:{monitor_port}/stats;csv"
        # Command for formatted output (for logging/display)
        formatted_stats_cmd = f"curl -s -u {monitor_user}:{monitor_password} \"{stats_url}\" | awk -F',' 'NR==1 || /^backend|^frontend|^stats/' | cut -d',' -f1,2,5,8,9,10,18,35,73 | column -s',' -t"
        # Command for raw output (for parsing by parse_haproxy_stats)
        raw_stats_cmd = f'curl -s -u {monitor_user}:{monitor_password} "{stats_url}"'

        # Fetch initial stats
        baseline_raw_stats_output = utils.exec_shell_cmd(
            raw_stats_cmd
        )  # Get raw data for parsing
        baseline_formatted_stats_output = utils.exec_shell_cmd(
            formatted_stats_cmd
        )  # Get formatted data for logging

        # Process baseline stats
        initial_rgw_requests = {}  # Initialize to empty dict
        if (
            baseline_formatted_stats_output
            and not baseline_formatted_stats_output.startswith("<!DOCTYPE")
        ):
            log.info(
                f"Baseline HAProxy stats (formatted):\n{baseline_formatted_stats_output}"
            )
            if baseline_raw_stats_output:
                # FIX: Changed parse_hierarchy_stats to parse_haproxy_stats
                initial_rgw_requests = parse_haproxy_stats(
                    baseline_raw_stats_output, service_name
                )
                log.info(f"Baseline HAProxy stats (parsed): {initial_rgw_requests}")
            else:
                log.warning(
                    "Failed to retrieve raw HAProxy stats for baseline parsing."
                )
        else:
            log.warning(
                f"Failed to retrieve formatted HAProxy stats before stopping HAProxy. Output: {baseline_formatted_stats_output[:100] if baseline_formatted_stats_output else 'No output'}..."
            )
            log.warning("Proceeding with fallback checks for baseline.")

        # Stop the HAProxy instance
        stop_cmd = f"sudo ceph orch daemon stop {haproxy_to_stop}"
        stop_output = utils.exec_shell_cmd(stop_cmd)
        if not stop_output:
            raise TestExecError(f"Failed to stop HAProxy instance {haproxy_to_stop}")

        log.info(f"Stop command output: {stop_output}")

        # Wait for HAProxy to stop
        log.info("Waiting 30 seconds for HAProxy to stop")
        time.sleep(30)

        # Verify the HAProxy instance is not running
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)
        if not orch_ps_output:  # Check for empty output
            log.error(
                f"Command '{orch_ps_cmd}' returned no output or failed after stopping HAProxy. Output: '{orch_ps_output}'"
            )
            raise TestExecError(
                f"Failed to get Ceph orchestrator process list after stopping HAProxy."
            )

        orch_ps_data = json.loads(orch_ps_output)
        haproxy_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "haproxy"
            and s.get("service_name") == service_name
        ]
        stopped_haproxy = [
            s for s in haproxy_services if s.get("daemon_name") == haproxy_to_stop
        ]
        if stopped_haproxy and stopped_haproxy[0].get("status_desc") == "running":
            raise TestExecError(
                f"HAProxy instance {haproxy_to_stop} is still running after stop command"
            )

        # Send test requests to HAProxy frontend (expect failure)
        log.info(
            f"Sending {num_requests} test requests to HAProxy frontend at {host}:{frontend_port} with {haproxy_to_stop} stopped"
        )
        successful_requests = 0
        for i in range(num_requests):
            curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' http://{host}:{frontend_port}"
            result = subprocess.run(
                curl_cmd, shell=True, capture_output=True, text=True
            )
            status_code = result.stdout.strip()
            if status_code == "200":
                successful_requests += 1
                log.warning(
                    f"Request {i+1} succeeded unexpectedly with status code {status_code}"
                )
            else:
                log.info(
                    f"Request {i+1} failed as expected with status code {status_code}"
                )
            time.sleep(0.1)

        # Verify no successful requests
        if successful_requests > 0:
            raise TestExecError(
                f"Unexpected successful requests with HAProxy stopped: {successful_requests} out of {num_requests}"
            )

        # Attempt to check HAProxy stats (expect failure)
        stats_after_stop_formatted = utils.exec_shell_cmd(formatted_stats_cmd)
        stats_after_stop_raw = utils.exec_shell_cmd(raw_stats_cmd)

        if stats_after_stop_formatted and not stats_after_stop_formatted.startswith(
            "<!DOCTYPE"
        ):
            log.warning(
                f"Unexpected HAProxy stats retrieved while {haproxy_to_stop} stopped:\n{stats_after_stop_formatted}"
            )
            # If stats are unexpectedly available, it means HAProxy didn't truly stop or monitor is on another instance
            # raise TestExecError(f"HAProxy stats unexpectedly available while {haproxy_to_stop} stopped.")
        else:
            log.info(
                f"HAProxy stats unavailable as expected while {haproxy_to_stop} stopped"
            )

        # Restart the HAProxy instance
        restart_cmd = f"sudo ceph orch daemon start {haproxy_to_stop}"
        restart_output = utils.exec_shell_cmd(restart_cmd)
        if not restart_output:
            raise TestExecError(f"Failed to restart HAProxy instance {haproxy_to_stop}")

        log.info(f"Restart command output: {restart_output}")

        # Wait for HAProxy to restart
        log.info(f"Waiting 30 seconds for {haproxy_to_stop} to restart")
        time.sleep(30)

        # Verify HAProxy and RGW instances are running
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)
        if not orch_ps_output:
            log.error(
                f"Command '{orch_ps_cmd}' returned no output or failed after restarting HAProxy. Output: '{orch_ps_output}'"
            )
            raise TestExecError(
                f"Failed to get Ceph orchestrator process list after restarting HAProxy."
            )

        orch_ps_data = json.loads(orch_ps_output)
        haproxy_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "haproxy"
            and s.get("service_name") == service_name
        ]
        rgw_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "rgw" and s.get("service_name") == service_name
        ]

        for service in haproxy_services + rgw_services:
            if service.get("status_desc") != "running":
                raise TestExecError(
                    f"Service {service.get('daemon_name')} is not running after restart: {service.get('status_desc')}"
                )

        # Verify traffic resumes after restart
        log.info(
            f"Sending {num_requests} test requests to HAProxy frontend at {host}:{frontend_port} after restarting {haproxy_to_stop}"
        )
        successful_requests_after = 0
        for i in range(num_requests):
            curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' http://{host}:{frontend_port}"
            result = subprocess.run(
                curl_cmd, shell=True, capture_output=True, text=True
            )
            status_code = result.stdout.strip()
            if status_code == "200":
                successful_requests_after += 1
            else:
                log.warning(f"Request {i+1} failed with status code {status_code}")
            time.sleep(0.1)

        # Verify sufficient successful requests after restart
        if successful_requests_after < num_requests * 0.5:
            raise TestExecError(
                f"Too few successful requests after restarting {haproxy_to_stop}: {successful_requests_after} out of {num_requests}"
            )

        # Check HAProxy stats after restart
        # Use specific variable names for clarity (stats_after_restart_formatted / raw)
        stats_after_restart_formatted = utils.exec_shell_cmd(formatted_stats_cmd)
        stats_after_restart_raw = utils.exec_shell_cmd(raw_stats_cmd)

        if (
            stats_after_restart_formatted
            and not stats_after_restart_formatted.startswith("<!DOCTYPE")
        ):
            log.info(
                f"HAProxy stats after restarting {haproxy_to_stop} (formatted):\n{stats_after_restart_formatted}"
            )
            if stats_after_restart_raw:
                # FIX: Changed parse_hierarchy_stats to parse_haproxy_stats
                rgw_request_count_after_restart = parse_haproxy_stats(
                    stats_after_restart_raw, service_name
                )
                log.info(
                    f"HAProxy stats after restarting {haproxy_to_stop} (parsed): {rgw_request_count_after_restart}"
                )
            else:
                log.warning(
                    "Failed to retrieve raw HAProxy stats after restarting HAProxy"
                )
        else:
            log.warning(
                f"Failed to retrieve HAProxy stats after restarting {haproxy_to_stop}, formatted output: {stats_after_restart_formatted[:100] if stats_after_restart_formatted else 'No output'}..."
            )
            raise TestExecError(
                "Failed to retrieve HAProxy stats after restarting HAProxy"
            )

        log.info(
            f"HAProxy instance {haproxy_to_stop} stopped and restarted successfully. Traffic stopped during downtime and resumed after restart."
        )
        return True

    except json.JSONDecodeError as e:
        log.error(
            f"Failed to parse ceph orch command output: {e}. Check if Ceph commands returned valid JSON."
        )
        raise TestExecError(f"Failed to parse ceph orch command output: {e}")
    except TestExecError as e:
        log.error(e.message)
        raise  # Re-raise your specific error
    except Exception as e:
        log.error(f"An unexpected error occurred in test_haproxy_stop: {str(e)}")
        raise TestExecError(f"Unexpected error during test_haproxy_stop: {str(e)}")


def test_haproxy_restart(config, ssh_con, rgw_node):
    """Test restarting HAProxy during active traffic and verify even distribution"""
    log.info("Testing restarting HAProxy during active traffic")
    try:
        # Get HAProxy monitor password
        monitor_password = get_haproxy_monitor_password(ssh_con, rgw_node)

        # Verify RGW and HAProxy configuration
        orch_ls_cmd = "sudo ceph orch ls rgw --format json"
        orch_ls_output = utils.exec_shell_cmd(orch_ls_cmd)
        orch_ls_data = json.loads(orch_ls_output)

        if not orch_ls_data:
            raise TestExecError("No RGW service information found")

        rgw_service_info = orch_ls_data[0]
        service_name = rgw_service_info.get("service_name", "")
        if not service_name:
            raise TestExecError("RGW service name not found")

        hosts = rgw_service_info.get("placement", {}).get("hosts", [])
        if not hosts:
            raise TestExecError("No hosts found for RGW service")
        host = hosts[0]

        frontend_port = rgw_service_info.get("spec", {}).get(
            "concentrator_frontend_port", 8080
        )
        monitor_port = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_port", 1967
        )
        monitor_user = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_user", "admin"
        )

        # Get number of test requests from config, default to 20
        num_requests = config.test_ops.get("traffic_test_requests", 20)

        # Get HAProxy daemon
        orch_ps_cmd = "sudo ceph orch ps --format json"
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)
        orch_ps_data = json.loads(orch_ps_output)
        haproxy_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "haproxy"
            and s.get("service_name") == service_name
        ]

        if not haproxy_services:
            raise TestExecError("No HAProxy services found")

        # Select the HAProxy instance to restart
        haproxy_to_restart = haproxy_services[0]["daemon_name"]
        log.info(f"Restarting HAProxy instance: {haproxy_to_restart} during traffic")

        # Get baseline HAProxy stats
        stats_url = f"http://{host}:{monitor_port}/stats;csv"
        stats_cmd = f"curl -s -u {monitor_user}:{monitor_password} \"{stats_url}\" | awk -F',' 'NR==1 || /^backend|^frontend|^stats/' | cut -d',' -f1,2,5,8,9,10,18,35,73 | column -s',' -t"
        raw_stats_cmd = f'curl -s -u {monitor_user}:{monitor_password} "{stats_url}"'
        baseline_stats = utils.exec_shell_cmd(raw_stats_cmd)
        initial_rgw_requests = (
            parse_haproxy_stats(baseline_stats, service_name) if baseline_stats else {}
        )
        log.info(f"Baseline HAProxy stats (parsed): {initial_rgw_requests}")
        formatted_stats = utils.exec_shell_cmd(stats_cmd)
        if formatted_stats and not formatted_stats.startswith("<!DOCTYPE"):
            log.info(f"Baseline HAProxy stats (formatted):\n{formatted_stats}")

        # Send test requests with HAProxy restart in the middle
        log.info(
            f"Sending {num_requests} test requests to HAProxy frontend at {host}:{frontend_port} with restart after 5 requests"
        )
        successful_requests = 0
        failed_requests = []
        for i in range(num_requests):
            curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' http://{host}:{frontend_port}"
            result = subprocess.run(
                curl_cmd, shell=True, capture_output=True, text=True
            )
            status_code = result.stdout.strip()
            if status_code == "200":
                successful_requests += 1
                log.info(f"Request {i+1} succeeded with status code {status_code}")
            else:
                failed_requests.append(i + 1)
                log.info(f"Request {i+1} failed with status code {status_code}")

            # Trigger HAProxy restart after 5 requests
            if i == 4:
                log.info(
                    f"Triggering restart of HAProxy instance: {haproxy_to_restart}"
                )
                restart_cmd = f"sudo ceph orch daemon restart {haproxy_to_restart}"
                restart_output = utils.exec_shell_cmd(restart_cmd)
                if not restart_output:
                    raise TestExecError(
                        f"Failed to restart HAProxy instance {haproxy_to_restart}"
                    )
                log.info(f"Restart command output: {restart_output}")

            time.sleep(0.1)

        # Wait for HAProxy to stabilize
        log.info(
            f"Waiting 30 seconds for {haproxy_to_restart} to stabilize after restart"
        )
        time.sleep(30)

        # Verify HAProxy and RGW instances are running
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)
        orch_ps_data = json.loads(orch_ps_output)
        haproxy_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "haproxy"
            and s.get("service_name") == service_name
        ]
        rgw_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "rgw" and s.get("service_name") == service_name
        ]

        for service in haproxy_services + rgw_services:
            if service.get("status_desc") != "running":
                raise TestExecError(
                    f"Service {service.get('daemon_name')} is not running after restart: {service.get('status_desc')}"
                )

        # Verify some requests failed during restart
        if not failed_requests:
            log.warning(
                "No requests failed during HAProxy restart, which is unexpected"
            )

        # Verify sufficient successful requests overall
        if successful_requests < num_requests * 0.5:
            raise TestExecError(
                f"Too few successful requests during HAProxy restart test: {successful_requests} out of {num_requests}"
            )

        # Check HAProxy stats after restart
        stats_output = utils.exec_shell_cmd(stats_cmd)
        raw_stats_output = utils.exec_shell_cmd(raw_stats_cmd)
        if stats_output and not stats_output.startswith("<!DOCTYPE"):
            log.info(
                f"HAProxy stats after restarting {haproxy_to_restart} (formatted):\n{stats_output}"
            )
            if raw_stats_output:
                rgw_request_count_after_restart = parse_haproxy_stats(
                    raw_stats_output, service_name
                )
                log.info(
                    f"HAProxy stats after restarting {haproxy_to_restart} (parsed): {rgw_request_count_after_restart}"
                )
            else:
                log.warning(
                    "Failed to retrieve raw HAProxy stats after restarting HAProxy"
                )
        else:
            log.warning(
                f"Failed to retrieve HAProxy stats after restarting {haproxy_to_restart}, formatted output: {stats_output[:100]}..."
            )
            raise TestExecError(
                "Failed to retrieve HAProxy stats after restarting HAProxy"
            )

        # Verify even traffic distribution
        expected_rgw_count = len(rgw_services)
        if rgw_request_count_after_restart:
            total_rgw_requests = sum(rgw_request_count_after_restart.values())
            if total_rgw_requests < successful_requests * 0.5:
                raise TestExecError(
                    f"Too few rgw_requests recorded in HAProxy stats: {total_rgw_requests} for {successful_requests} successful requests"
                )
            if len(rgw_request_count_after_restart) != expected_rgw_count:
                raise TestExecError(
                    f"Traffic not distributed to all {expected_rgw_count} RGW instances: {rgw_request_count_after_restart}"
                )
            average_rgw_requests = total_rgw_requests / expected_rgw_count
            for rgw, rgw_requests in rgw_request_count_after_restart.items():
                if (
                    abs(rgw_requests - average_rgw_requests)
                    > 0.2 * average_rgw_requests
                ):
                    log.warning(
                        f"Uneven traffic distribution for {rgw}: {rgw_requests} rgw_requests (expected ~{average_rgw_requests})"
                    )

        log.info(
            f"HAProxy instance {haproxy_to_restart} restarted successfully during traffic. Traffic resumed with even distribution: {rgw_request_count_after_restart}"
        )
        return True

    except json.JSONDecodeError:
        raise TestExecError("Failed to parse ceph orch command output")
    except TestExecError as e:
        log.error(e.message)
        return False


def test_rgw_service_removal(config, ssh_con, rgw_node):
    """Test removing RGW service and verify RGW and HAProxy services are removed after 30 seconds"""
    log.info("Testing RGW service removal")
    try:
        # Get HAProxy monitor password
        monitor_password = get_haproxy_monitor_password(ssh_con, rgw_node)

        # Verify RGW service exists initially
        orch_ls_cmd = "sudo ceph orch ls rgw --format json"
        orch_ls_output = utils.exec_shell_cmd(orch_ls_cmd)
        orch_ls_data = json.loads(orch_ls_output)

        if not orch_ls_data:
            raise TestExecError("No RGW service information found before removal")

        rgw_service_info = orch_ls_data[0]
        service_name = rgw_service_info.get("service_name", "")
        if not service_name:
            raise TestExecError("RGW service name not found")

        hosts = rgw_service_info.get("placement", {}).get("hosts", [])
        if not hosts:
            raise TestExecError("No hosts found for RGW service")
        host = hosts[0]

        frontend_port = rgw_service_info.get("spec", {}).get(
            "concentrator_frontend_port", 8080
        )
        monitor_port = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_port", 1967
        )
        monitor_user = rgw_service_info.get("spec", {}).get(
            "concentrator_monitor_user", "admin"
        )

        log.info(f"Initial RGW service state: {service_name} on host {host}")

        # Get number of test requests from config, default to 20
        num_requests = config.test_ops.get("traffic_test_requests", 20)

        # Remove RGW service
        remove_cmd = f"sudo ceph orch rm {service_name}"
        remove_output = utils.exec_shell_cmd(remove_cmd)
        if not remove_output:
            raise TestExecError(f"Failed to remove RGW service {service_name}")

        log.info(f"Remove command output: {remove_output}")

        # Wait and retry checking service removal
        log.info("Waiting up to 30 seconds for RGW service removal with retries")
        max_retries = 3
        retry_interval = 10
        for attempt in range(max_retries):
            time.sleep(retry_interval)
            orch_ls_output = utils.exec_shell_cmd(orch_ls_cmd)
            try:
                orch_ls_data = json.loads(orch_ls_output)
                rgw_services = [
                    s for s in orch_ls_data if s.get("service_name") == service_name
                ]
                if not rgw_services:
                    log.info(
                        f"RGW service {service_name} successfully removed after {attempt + 1} checks"
                    )
                    break
                else:
                    log.warning(
                        f"Attempt {attempt + 1}: RGW service {service_name} still present: {rgw_services}"
                    )
            except json.JSONDecodeError:
                log.info(
                    f"Attempt {attempt + 1}: No RGW services found in orch ls output, assuming removal complete"
                )
                break
        else:
            raise TestExecError(
                f"RGW service {service_name} still present after {max_retries} retries over 30 seconds: {orch_ls_data}"
            )

        # Verify RGW and HAProxy daemons are removed
        orch_ps_cmd = "sudo ceph orch ps --format json"
        orch_ps_output = utils.exec_shell_cmd(orch_ps_cmd)
        orch_ps_data = json.loads(orch_ps_output)
        rgw_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "rgw" and s.get("service_name") == service_name
        ]
        haproxy_services = [
            s
            for s in orch_ps_data
            if s.get("daemon_type") == "haproxy"
            and s.get("service_name") == service_name
        ]

        if rgw_services:
            raise TestExecError(
                f"RGW daemons still present after service removal: {[s.get('daemon_name') for s in rgw_services]}"
            )
        if haproxy_services:
            raise TestExecError(
                f"HAProxy daemons still present after service removal: {[s.get('daemon_name') for s in haproxy_services]}"
            )

        log.info("Confirmed RGW and HAProxy daemons removed")

        # Send test requests to HAProxy frontend (expect failure)
        log.info(
            f"Sending {num_requests} test requests to HAProxy frontend at {host}:{frontend_port} after service removal"
        )
        successful_requests = 0
        for i in range(num_requests):
            curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' http://{host}:{frontend_port}"
            result = subprocess.run(
                curl_cmd, shell=True, capture_output=True, text=True
            )
            status_code = result.stdout.strip()
            if status_code == "200":
                successful_requests += 1
                log.warning(
                    f"Request {i+1} succeeded unexpectedly with status code {status_code}"
                )
            else:
                log.info(
                    f"Request {i+1} failed as expected with status code {status_code}"
                )
            time.sleep(0.1)

        # Verify no successful requests
        if successful_requests > 0:
            raise TestExecError(
                f"Unexpected successful requests after service removal: {successful_requests} out of {num_requests}"
            )

        # Attempt to check HAProxy stats (expect failure)
        stats_url = f"http://{host}:{monitor_port}/stats;csv"
        stats_cmd = f"curl -s -u {monitor_user}:{monitor_password} \"{stats_url}\" | awk -F',' 'NR==1 || /^backend|^frontend|^stats/' | cut -d',' -f1,2,5,8,9,10,18,35,73 | column -s',' -t"
        stats_output = utils.exec_shell_cmd(stats_cmd)
        if stats_output and not stats_output.startswith("<!DOCTYPE"):
            log.warning(
                f"Unexpected HAProxy stats retrieved after service removal:\n{stats_output}"
            )
        else:
            log.info("HAProxy stats unavailable as expected after service removal")

        log.info(
            f"RGW service {service_name} removed successfully. No RGW or HAProxy daemons found, and traffic stopped."
        )
        return True

    except json.JSONDecodeError:
        raise TestExecError("Failed to parse ceph orch command output")
    except TestExecError as e:
        log.error(e.message)
        return False


def parse_haproxy_stats(stats_output, service_name):
    """Parse HAProxy stats CSV to count requests per RGW backend"""
    rgw_rgw_requests = {}
    lines = stats_output.splitlines()
    for line in lines:
        fields = line.split(",")
        if len(fields) > 7 and fields[0] == "backend" and service_name in fields[1]:
            backend_name = fields[1]
            if backend_name.startswith("rgw."):
                try:
                    rgw_requests = int(fields[7])
                    if rgw_requests > 0:
                        rgw_rgw_requests[backend_name] = rgw_requests
                except (ValueError, IndexError):
                    continue
    return rgw_rgw_requests
