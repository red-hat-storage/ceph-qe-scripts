"""
N+E signature and IBM IAM helpers for AssumeRoleWithWebIdentity tests.
"""
import base64
import json
import logging
import os
import shutil
import subprocess
import time
import urllib.request
from datetime import datetime
from urllib.parse import urlparse

import v2.utils.utils as utils
from botocore.exceptions import ClientError
from v2.lib.exceptions import TestExecError

log = logging.getLogger()


def install_ibm_cloud_cli(version="2.34.0", install_dir="/tmp/ibmcloud_install"):
    """
    Install IBM Cloud CLI if not already installed

    Args:
        version (str): Version of IBM Cloud CLI to install (default: 2.34.0)
        install_dir (str): Temporary directory for installation

    Returns:
        bool: True if installation successful or already installed
    """
    if shutil.which("ibmcloud"):
        try:
            existing_version = utils.exec_shell_cmd("ibmcloud --version")
            if existing_version and version in existing_version:
                log.info(f"IBM Cloud CLI {version} already installed")
                return True
            log.info(f"IBM Cloud CLI version mismatch: {existing_version}")
        except Exception:
            pass

    try:
        log.info(f"Installing IBM Cloud CLI {version}")
        os.makedirs(install_dir, exist_ok=True)
        tar_file = os.path.join(install_dir, f"IBM_Cloud_CLI_{version}_amd64.tar.gz")
        download_url = f"https://download.clis.cloud.ibm.com/ibm-cloud-cli/{version}/IBM_Cloud_CLI_{version}_amd64.tar.gz"
        log.info(f"Downloading IBM Cloud CLI from {download_url}")
        utils.exec_shell_cmd(f"curl -L {download_url} -o {tar_file}")
        log.info("Extracting IBM Cloud CLI")
        utils.exec_shell_cmd(f"cd {install_dir} && tar -xvf {tar_file}")
        log.info("Installing IBM Cloud CLI")
        install_script = os.path.join(install_dir, "Bluemix_CLI", "install")
        if os.path.exists(install_script):
            utils.exec_shell_cmd(f"bash {install_script}")
        else:
            install_script = os.path.join(install_dir, "install")
            if os.path.exists(install_script):
                utils.exec_shell_cmd(f"bash {install_script}")
            else:
                raise TestExecError("IBM Cloud CLI install script not found")

        if shutil.which("ibmcloud"):
            log.info("IBM Cloud CLI installed successfully")
            return True

        # Check default installation location
        default_install_path = "/usr/local/ibmcloud/bin/ibmcloud"
        if os.path.exists(default_install_path) and os.access(
            default_install_path, os.X_OK
        ):
            # Add to PATH for current process
            current_path = os.environ.get("PATH", "")
            ibmcloud_bin_dir = os.path.dirname(default_install_path)
            if ibmcloud_bin_dir not in current_path:
                os.environ["PATH"] = f"{ibmcloud_bin_dir}:{current_path}"
            log.info("IBM Cloud CLI installed successfully")
            return True

        # Check alternative locations
        alternative_paths = [
            "/usr/local/bin/ibmcloud",
            os.path.expanduser("~/ibmcloud/bin/ibmcloud"),
        ]
        for alt_path in alternative_paths:
            if os.path.exists(alt_path) and os.access(alt_path, os.X_OK):
                alt_bin_dir = os.path.dirname(alt_path)
                current_path = os.environ.get("PATH", "")
                if alt_bin_dir not in current_path:
                    os.environ["PATH"] = f"{alt_bin_dir}:{current_path}"
                log.info("IBM Cloud CLI installed successfully")
                return True

        raise TestExecError(
            "IBM Cloud CLI installation failed - command not found in PATH or default locations"
        )

    except Exception as e:
        raise TestExecError(f"Failed to install IBM Cloud CLI: {e}")
    finally:
        try:
            if os.path.exists(install_dir):
                utils.exec_shell_cmd(f"rm -rf {install_dir}")
        except Exception:
            pass


def create_ibm_cloud_apikey(
    name, description=None, ibm_cloud_cli_path=None, output_format="json"
):
    """
    Create a new IBM Cloud API key.

    Args:
        name (str): Name for the API key
        description (str): Optional description for the API key
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        output_format (str): Output format (json or text, default: json)

    Returns:
        dict: API key information including the API key value
    """
    log.info(f"Creating IBM Cloud API key: {name}")
    try:
        if ibm_cloud_cli_path:
            base_cmd = ibm_cloud_cli_path
        else:
            base_cmd = "ibmcloud"

        cmd_args = [
            base_cmd,
            "iam",
            "api-key-create",
            name,
            "--output",
            output_format,
        ]
        if description:
            cmd_args.extend(["--description", description])

        log.info("Executing API key creation command")
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            error_msg = stderr if stderr else stdout
            raise TestExecError(
                f"Failed to create API key. Return code: {process.returncode}, Error: {error_msg}"
            )

        if output_format == "json":
            try:
                api_key_data = json.loads(stdout)
                log.info(f"API key created successfully: {name}")
                return api_key_data
            except json.JSONDecodeError:
                raise TestExecError(
                    f"Failed to parse API key creation output: {stdout}"
                )
        else:
            log.info(f"API key created successfully: {name}")
            return {"output": stdout}

    except TestExecError:
        raise
    except Exception as e:
        raise TestExecError(f"Error creating IBM Cloud API key: {e}")


def list_ibm_cloud_apikeys(ibm_cloud_cli_path=None, output_format="json"):
    """
    List all IBM Cloud API keys for the current user.

    Args:
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        output_format (str): Output format (json or text, default: json)

    Returns:
        list: List of API key information dictionaries
    """
    log.info("Listing IBM Cloud API keys")
    try:
        if ibm_cloud_cli_path:
            base_cmd = ibm_cloud_cli_path
        else:
            base_cmd = "ibmcloud"

        cmd_args = [base_cmd, "iam", "api-keys", "--output", output_format]

        log.info("Executing API key list command")
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            error_msg = stderr if stderr else stdout
            raise TestExecError(
                f"Failed to list API keys. Return code: {process.returncode}, Error: {error_msg}"
            )

        if output_format == "json":
            try:
                api_keys_data = json.loads(stdout)
                if isinstance(api_keys_data, list):
                    log.info(f"Found {len(api_keys_data)} API key(s)")
                    return api_keys_data
                elif isinstance(api_keys_data, dict) and "apikeys" in api_keys_data:
                    api_keys = api_keys_data["apikeys"]
                    log.info(f"Found {len(api_keys)} API key(s)")
                    return api_keys
                else:
                    log.warning("Unexpected API key list format")
                    return []
            except json.JSONDecodeError:
                raise TestExecError(f"Failed to parse API key list output: {stdout}")
        else:
            log.info("API keys listed successfully")
            return {"output": stdout}

    except TestExecError:
        raise
    except Exception as e:
        raise TestExecError(f"Error listing IBM Cloud API keys: {e}")


def delete_ibm_cloud_apikey(api_key_id, ibm_cloud_cli_path=None, force=False):
    """
    Delete an IBM Cloud API key.

    Args:
        api_key_id (str): API key ID or name to delete
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        force (bool): If True, force deletion without confirmation

    Returns:
        bool: True if deletion successful
    """
    log.info(f"Deleting IBM Cloud API key: {api_key_id}")
    try:
        if ibm_cloud_cli_path:
            base_cmd = ibm_cloud_cli_path
        else:
            base_cmd = "ibmcloud"

        cmd_args = [base_cmd, "iam", "api-key-delete", api_key_id]
        if force:
            cmd_args.append("--force")

        log.info("Executing API key deletion command")
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            error_msg = stderr if stderr else stdout
            if (
                "not found" in error_msg.lower()
                or "does not exist" in error_msg.lower()
            ):
                log.warning(f"API key {api_key_id} not found (may already be deleted)")
                return False
            raise TestExecError(
                f"Failed to delete API key. Return code: {process.returncode}, Error: {error_msg}"
            )

        log.info(f"API key {api_key_id} deleted successfully")
        return True

    except TestExecError:
        raise
    except Exception as e:
        raise TestExecError(f"Error deleting IBM Cloud API key: {e}")


def rotate_ibm_cloud_apikey(
    old_api_key_id=None,
    new_name=None,
    description=None,
    ibm_cloud_cli_path=None,
    delete_old=True,
):
    """
    Rotate IBM Cloud API key by creating a new one and optionally deleting the old one.

    Args:
        old_api_key_id (str): ID or name of the old API key to delete (optional)
        new_name (str): Name for the new API key (default: auto-generated with timestamp)
        description (str): Optional description for the new API key
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        delete_old (bool): If True, delete the old API key after creating new one

    Returns:
        dict: New API key information including the API key value
    """
    log.info("Rotating IBM Cloud API key")
    try:
        if not new_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_name = f"rotated_apikey_{timestamp}"

        # Create new API key
        new_api_key_data = create_ibm_cloud_apikey(
            new_name, description, ibm_cloud_cli_path
        )

        # Extract the API key value from the response
        api_key_value = None
        if isinstance(new_api_key_data, dict):
            # Try different possible keys for the API key value
            api_key_value = (
                new_api_key_data.get("apikey")
                or new_api_key_data.get("apiKey")
                or new_api_key_data.get("value")
                or new_api_key_data.get("apikey_value")
            )
            if not api_key_value and "output" in new_api_key_data:
                # If output is text, try to extract from it
                output = new_api_key_data["output"]
                # Look for patterns like "API key: xxxxx" or similar
                for line in output.split("\n"):
                    if "apikey" in line.lower() or "api key" in line.lower():
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if len(part) > 40:  # API keys are typically long
                                api_key_value = part.strip()
                                break
                        if api_key_value:
                            break

        if not api_key_value:
            log.warning(
                "Could not extract API key value from creation response. "
                "You may need to retrieve it manually."
            )

        # Optionally delete old API key
        if delete_old and old_api_key_id:
            try:
                delete_ibm_cloud_apikey(old_api_key_id, ibm_cloud_cli_path, force=True)
                log.info(f"Old API key {old_api_key_id} deleted successfully")
            except Exception as delete_e:
                log.warning(
                    f"Failed to delete old API key {old_api_key_id}: {delete_e}. "
                    "New API key created successfully."
                )

        result = {
            "name": new_name,
            "api_key_value": api_key_value,
            "api_key_data": new_api_key_data,
        }
        log.info(f"API key rotation completed. New API key name: {new_name}")
        return result

    except TestExecError:
        raise
    except Exception as e:
        raise TestExecError(f"Error rotating IBM Cloud API key: {e}")


def load_and_set_api_key():
    """
    Load IBM Cloud API key from environment variable.
    The API key must be set via IBM_CLOUD_API_KEY environment variable.

    Returns:
        str: API key if found in environment, None otherwise
    """
    api_key = os.getenv("IBM_CLOUD_API_KEY")
    if api_key:
        is_ci = os.getenv("CI") == "true" or os.getenv("GITHUB_ACTIONS") == "true"
        if is_ci:
            log.info("IBM_CLOUD_API_KEY found in environment (GitHub Actions secret)")
        else:
            log.info("IBM_CLOUD_API_KEY found in environment")
        return api_key

    log.warning("IBM_CLOUD_API_KEY not found in environment variable")
    return None


def login_ibmcloud_with_apikey(api_key, region=None, ibm_cloud_cli_path=None):
    """
    Login to IBM Cloud CLI using API key.
    For security, use API key rotation (rotate_ibm_cloud_apikey) to manage API keys.

    Args:
        api_key (str): IBM Cloud API key (plain text)
        region (str): Region to target (e.g., 'in-che', 'us-south')
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary

    Returns:
        bool: True if login successful
    """
    log.info("Logging in to IBM Cloud CLI using API key")
    try:
        if not api_key:
            raise ValueError("API key cannot be empty")
        plain_api_key = api_key.strip()

        if ibm_cloud_cli_path:
            base_cmd = ibm_cloud_cli_path
        else:
            base_cmd = "ibmcloud"

        cmd_args = [base_cmd, "login", "--apikey", plain_api_key, "-a", "cloud.ibm.com"]
        if region:
            cmd_args.extend(["-r", region])

        log.info("Executing login command")
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            universal_newlines=True,
        )
        stdout, stderr = process.communicate()
        output = stdout or ""

        if process.returncode != 0:
            detail = (stderr or stdout or "").strip()
            log.error(
                "Login command failed with return code %s. stderr/stdout: %s",
                process.returncode,
                detail[:500] if detail else "(none)",
            )
            raise TestExecError(
                "IBM Cloud login failed (check API key and network). "
                f"returncode={process.returncode}; output: {detail[:300] or '(none)'}"
            )

        if output and (
            "OK" in output
            or "Authenticating..." in output
            or "Targeted account" in output
            or "Targeted region" in output
        ):
            time.sleep(2)
            verify_cmd = [base_cmd, "target"]
            verify_process = subprocess.Popen(
                verify_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                universal_newlines=True,
            )
            verify_stdout, verify_stderr = verify_process.communicate()
            if verify_stdout and (
                "Account:" in verify_stdout or "User:" in verify_stdout
            ):
                log.info("Login verified immediately after login command")
                return True
            else:
                log.warning("Login succeeded but verification failed")
                return True
        else:
            detail = (stderr or output or "").strip()
            log.error(
                "Login output missing success indicators. stdout: %s",
                (output or "(none)")[:500],
            )
            raise TestExecError(
                "IBM Cloud login failed - CLI output did not indicate success. "
                f"output: {(detail or output or '(none)')[:300]}"
            )
    except Exception as e:
        raise TestExecError(f"Error during IBM Cloud login with API key: {e}")


def get_ibm_iam_jwt_token(
    ibm_cloud_cli_path=None,
    api_key=None,
    region=None,
):
    """
    Get IBM IAM JWT token using IBM Cloud CLI

    Args:
        ibm_cloud_cli_path (str): Path to IBM Cloud CLI binary
        api_key (str): IBM Cloud API key for auto-login (required)
        region (str): Region to target for auto-login (e.g., 'in-che', 'us-south')

    Returns:
        str: JWT token (without Bearer prefix)
    """
    log.info("Getting IBM IAM JWT token")
    try:
        if ibm_cloud_cli_path:
            cli_cmd = ibm_cloud_cli_path
            if not os.path.exists(cli_cmd) or not os.access(cli_cmd, os.X_OK):
                if shutil.which("ibmcloud"):
                    log.info(
                        "IBM Cloud CLI already exists in PATH, skipping installation"
                    )
                    cli_cmd = "ibmcloud"
                else:
                    log.info("Attempting to auto-install IBM Cloud CLI")
                    install_ibm_cloud_cli()
                    cli_cmd = "ibmcloud"
        else:
            cli_cmd = "ibmcloud"
            cli_path = shutil.which(cli_cmd)
            if not cli_path:
                default_install_path = "/usr/local/ibmcloud/bin/ibmcloud"
                if os.path.exists(default_install_path) and os.access(
                    default_install_path, os.X_OK
                ):
                    log.info(
                        "IBM Cloud CLI found at default location, skipping installation"
                    )
                    current_path = os.environ.get("PATH", "")
                    ibmcloud_bin_dir = os.path.dirname(default_install_path)
                    if ibmcloud_bin_dir not in current_path:
                        os.environ["PATH"] = f"{ibmcloud_bin_dir}:{current_path}"
                    cli_path = default_install_path
                else:
                    log.info("Auto-installing IBM Cloud CLI")
                    install_ibm_cloud_cli()
                    cli_path = shutil.which(cli_cmd)
                    if not cli_path:
                        if os.path.exists(default_install_path) and os.access(
                            default_install_path, os.X_OK
                        ):
                            current_path = os.environ.get("PATH", "")
                            ibmcloud_bin_dir = os.path.dirname(default_install_path)
                            if ibmcloud_bin_dir not in current_path:
                                os.environ[
                                    "PATH"
                                ] = f"{ibmcloud_bin_dir}:{current_path}"
                            cli_path = default_install_path
                        if not cli_path:
                            raise TestExecError(
                                "IBM Cloud CLI auto-installation failed"
                            )

        if not api_key:
            raise TestExecError(
                "Unable to find API key. Set IBM_CLOUD_API_KEY environment variable"
            )
        # Endpoint is set by ibmcloud login --apikey -a cloud.ibm.com (no separate "ibmcloud api" call).
        log.info("API key found for auto-login, Checking login status")
        try:
            check_cmd = f"{cli_cmd} target"
            check_output = utils.exec_shell_cmd(check_cmd)
            is_logged_in = check_output and (
                "Account:" in check_output or "User:" in check_output
            )

            if is_logged_in:
                log.info("Already logged in")

            if not is_logged_in:
                log.info("Attempting auto-login")
                if api_key:
                    login_success = login_ibmcloud_with_apikey(api_key, region, cli_cmd)
                    if not login_success:
                        raise TestExecError("Failed to login with API key")
                    time.sleep(3)
                else:
                    raise TestExecError("API key required for login")

            time.sleep(2)
            verify_cmd = [cli_cmd, "target"]
            verify_process = subprocess.Popen(
                verify_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            verify_stdout, verify_stderr = verify_process.communicate()
            verify_output = verify_stdout
            if not verify_output or (
                "Account:" not in verify_output and "User:" not in verify_output
            ):
                if "Not logged in" in verify_output:
                    raise TestExecError(
                        f"Login verification failed - login may not have persisted. Output: {verify_output}"
                    )
                else:
                    raise TestExecError(
                        f"Login verification failed. Output: {verify_output}"
                    )

            log.info("Login verified successfully")
        except Exception as e:
            if isinstance(e, TestExecError):
                raise
            log.warning(
                f"Error checking/login status: {e}. Continuing to try getting token..."
            )

        if ibm_cloud_cli_path:
            cmd = f"{ibm_cloud_cli_path} iam oauth-tokens --output json"
        else:
            cmd = "ibmcloud iam oauth-tokens --output json"

        try:
            output = utils.exec_shell_cmd(cmd)
            if not output or output is False:
                raise TestExecError(
                    "Failed to get IBM IAM oauth tokens - command returned no output"
                )
        except Exception as e:
            error_msg = str(e)
            if (
                "No API endpoint set" in error_msg
                or "api endpoint" in error_msg.lower()
            ):
                raise TestExecError(
                    "IBM Cloud API endpoint not set. Login with API key sets it automatically; "
                    "if you see this, re-run the test or run: ibmcloud login --apikey <key> -a cloud.ibm.com. "
                    f"Error: {error_msg}"
                )
            raise TestExecError(f"Failed to get oauth tokens. Error: {error_msg}")

        token_data = json.loads(output)
        iam_token = token_data.get("iam_token", "")

        if not iam_token:
            raise TestExecError("IAM token not found. Ensure logged in")
        if iam_token.startswith("Bearer "):
            iam_token = iam_token[7:]
        log.info("JWT token obtained successfully")
        return iam_token
    except TestExecError:
        raise
    except json.JSONDecodeError as e:
        raise TestExecError(f"Failed to parse CLI output as JSON: {e}")
    except Exception as e:
        raise TestExecError(f"Failed to get JWT token: {e}")


def get_ibm_iam_thumbprint(region="us-south"):
    """
    Get IBM IAM certificate thumbprint

    Args:
        region (str): IBM Cloud region (default: us-south)

    Returns:
        str: Certificate thumbprint (without colons)
    """
    log.info(f"Getting certificate thumbprint for region: {region}")
    oidc_config_url = (
        "https://iam.cloud.ibm.com/identity/.well-known/openid-configuration"
    )
    try:
        with urllib.request.urlopen(oidc_config_url) as response:
            oidc_config = json.loads(response.read().decode())

        jwks_uri = oidc_config.get("jwks_uri", "")
        if not jwks_uri:
            raise TestExecError("jwks_uri not found in OIDC configuration")

        parsed_uri = urlparse(jwks_uri)
        server_name = parsed_uri.hostname
        if not server_name:
            raise TestExecError(f"Could not extract hostname from jwks_uri: {jwks_uri}")
    except Exception as e:
        raise TestExecError(f"Failed to get jwks_uri from OIDC configuration: {e}")

    try:
        cert_file = "/tmp/ibm_cert.crt"
        temp_all_certs = "/tmp/ibm_all_certs.crt"
        cmd_get_all = f"openssl s_client -servername {server_name} -showcerts -connect {server_name}:443 < /dev/null 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > {temp_all_certs}"
        utils.exec_shell_cmd(cmd_get_all)
        if not os.path.exists(temp_all_certs) or os.path.getsize(temp_all_certs) == 0:
            raise TestExecError(f"Failed to retrieve certificates from {server_name}")

        last_begin_cmd = (
            f"grep -n 'BEGIN CERTIFICATE' {temp_all_certs} | tail -1 | cut -d: -f1"
        )
        last_begin_output = utils.exec_shell_cmd(last_begin_cmd)
        last_begin_line = last_begin_output.strip() if last_begin_output else ""
        if not last_begin_line or not last_begin_line.isdigit():
            error_msg = f"Could not find BEGIN CERTIFICATE in {temp_all_certs}"
            if os.path.exists(temp_all_certs):
                error_msg += f". File size: {os.path.getsize(temp_all_certs)} bytes"
            raise TestExecError(error_msg)

        cmd_extract_last = f"sed -n '{last_begin_line},/END CERTIFICATE/p' {temp_all_certs} > {cert_file}"
        utils.exec_shell_cmd(cmd_extract_last)
        utils.exec_shell_cmd(f"rm -f {temp_all_certs}")
        if not os.path.exists(cert_file) or os.path.getsize(cert_file) == 0:
            raise TestExecError(
                f"Failed to extract certificate. File {cert_file} is empty or missing"
            )

        cmd = f"openssl x509 -in {cert_file} -fingerprint -sha1 -noout"
        output = utils.exec_shell_cmd(cmd)
        if not output:
            raise TestExecError("Failed to get certificate thumbprint")

        thumbprint = output.split("=")[1].strip().replace(":", "")
        log.info(f"Successfully obtained thumbprint: {thumbprint}")
        utils.exec_shell_cmd(f"rm -f {cert_file}")
        return thumbprint

    except Exception as e:
        if os.path.exists(cert_file):
            utils.exec_shell_cmd(f"rm -f {cert_file}")
        if os.path.exists("/tmp/ibm_all_certs.crt"):
            utils.exec_shell_cmd(f"rm -f /tmp/ibm_all_certs.crt")
        raise TestExecError(f"Error getting thumbprint: {e}")


def get_jwt_client_id(jwt_token):
    """
    Extract client_id from JWT token

    Args:
        jwt_token (str): JWT token

    Returns:
        str: Client ID from JWT
    """
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            raise TestExecError("Invalid JWT token format")

        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload)
        payload_json = json.loads(decoded)
        client_id = payload_json.get("client_id", "")
        log.info(f"Extracted client_id: {client_id}")
        return client_id
    except Exception as e:
        raise TestExecError(f"Failed to extract client_id: {e}")


def create_oidc_provider_ibm_iam(iam_client, oidc_url, client_id, thumbprint):
    """
    Create OIDC provider for IBM IAM

    Args:
        iam_client: IAM client object
        oidc_url (str): OIDC provider URL
        client_id (str): Client ID from JWT
        thumbprint (str): Certificate thumbprint

    Returns:
        dict: OIDC provider response
    """
    log.info(f"Creating OIDC provider: {oidc_url}")

    try:
        oidc_response = iam_client.create_open_id_connect_provider(
            Url=oidc_url,
            ClientIDList=[client_id],
            ThumbprintList=[thumbprint],
        )
        log.info("OIDC provider created")
        return oidc_response

    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            log.info("OIDC provider already exists, deleting and recreating...")
            try:
                provider_arn = f"arn:aws:iam:::oidc-provider/{oidc_url.replace('https://', '').replace('http://', '')}"
                iam_client.delete_open_id_connect_provider(
                    OpenIDConnectProviderArn=provider_arn
                )
                time.sleep(2)
            except Exception as del_e:
                log.warning(f"Error deleting existing provider: {del_e}")
            oidc_response = iam_client.create_open_id_connect_provider(
                Url=oidc_url,
                ClientIDList=[client_id],
                ThumbprintList=[thumbprint],
            )
            log.info(f"OIDC provider recreated: {oidc_response}")
            return oidc_response

        else:
            raise
