"""Module to trigger COS Bench workloads."""
import argparse
import json
import logging
import subprocess
import sys
from os.path import dirname, join
from tempfile import NamedTemporaryFile
from typing import Dict, Optional, Tuple

from jinja2 import Template
from yaml import safe_load

APP_DIR = "/opt/cosbench"
LOG = logging.getLogger(__name__)


def exec_command(cmd: str) -> subprocess.CompletedProcess:
    """Execute the given command.

    Args:
        cmd (str):  The command that needs to be executed.

    Returns:

    """
    LOG.debug("Executing command: %s", cmd)
    return subprocess.run([cmd], shell=True, check=True, stdout=subprocess.PIPE)


def get_user_info() -> Dict:
    """Returns cosbench01 user info available in realm."""
    try:
        proc = exec_command(cmd="radosgw-admin user info --uid cosbench01")
    except subprocess.CalledProcessError:
        proc = exec_command(
            cmd="radosgw-admin user create --uid cosbench01 "
            "--display-name cosbench01 --email cosbench01@noreply.com"
        )

    return json.loads(proc.stdout)


def get_swauth_secret() -> str:
    """Returns the secret key of cosbench01:swift user.

    Creates the user if not found in realm. The sub user required for swift auth is also
    created.

    Returns:
        secret_key  of the standard user.
    """
    user_info = get_user_info()

    if not user_info["subusers"]:
        exec_command(
            cmd="radosgw-admin subuser create --uid cosbench01 "
            "--subuser cosbench01:swift --access full"
        )
        user_info = get_user_info()

    return user_info["swift_keys"][0]["secret_key"]


def get_s3_keys() -> Tuple:
    """Returns a tuple containing access and secret keys of cosbench01."""
    user_info = get_user_info()
    return user_info["keys"][0]["access_key"], user_info["keys"][0]["secret_key"]


def dict_to_str(data: Dict, sep: Optional[str] = " ") -> str:
    """Converts the given dictionary to a string separated by the given separator.

    Args:
        data (dict):    dict that needs to be transformed
        sep (str):     Separator to be used.

    Returns:
        (str)   string value of the given data.
    """
    rtn = ""
    for key, value in data.items():
        rtn += f"{key}={value};" if sep == ";" else f'{key}="{value}"{sep}'

    return rtn.rstrip(sep)


def get_attributes(data: Dict) -> str:
    """Converts the given dictionary to XML attributes.

    This is a custom method that is specific to COS Bench XML template requirements. It
    has a special separation for "config".

    Args:
        data (dict):    data that needs to be converted to attributes.

    Returns:
        (str)   attributes for the element.
    """
    if "config" in data.keys():
        data["config"] = dict_to_str(data.pop("config"), sep=";")

    return dict_to_str(data)


def load_config(conf_file: str) -> Dict:
    """Reads the given YAML file and converts it to dict."""
    abs_file = join(dirname(__file__), f"conf/{conf_file}")
    LOG.debug("Loading the given YAML: %s", abs_file)

    with open(abs_file, "r") as fh:
        return safe_load(fh)


def render_xml(data: Dict) -> str:
    """Render the given data as an XML file."""
    tmpl_file = join(dirname(__file__), "cosbench.xml.tmpl")
    with open(tmpl_file) as fd:
        with NamedTemporaryFile(
            prefix="ci-", suffix=".xml", delete=False, mode="w+t"
        ) as xml_fd:
            content = Template(fd.read()).render(data=data)
            xml_fd.write(content)
            xml_fd.flush()
            return xml_fd.name


def generate_payload(config: argparse.Namespace) -> Dict:
    """Submits the workload based on the given config.

    Args:
        config:     CLI parameters passed for submit subcommand.

    Returns:
        dict -> that can be used for generating the XML file

    """
    LOG.debug("Creating the payload based on the config file.")

    conf = load_config(config.conf_file)
    auth = conf["workload"].pop("auth")
    storage = conf["workload"].pop("storage")
    workflows = conf["workload"].pop("workflows")

    # get auth properties
    if auth == "swauth":
        auth = {
            "type": "swauth",
            "config": {
                "username": "cosbench01:swift",
                "password": get_swauth_secret(),
                "auth_url": f"{config.rgw_endpoint}/auth/v1.0",
            },
        }

    # insert s3
    if storage["type"] == "s3":
        storage["config"]["path_style_access"] = True
        storage["config"]["endpoint"] = config.rgw_endpoint
        access_key, secret_key = get_s3_keys()
        storage["config"]["accesskey"] = access_key
        storage["config"]["secretkey"] = secret_key

    # Processing workflow
    workflow_list = list()
    for workflow in workflows:
        LOG.info(workflow)
        ops = workflow.pop("operations", None)
        workflow_data = {"attrs": get_attributes(workflow)}

        if ops:
            workflow_data["operations"] = [{"attrs": get_attributes(x)} for x in ops]

        workflow_list.append(workflow_data)

    # Payload to be used for rendering
    payload = dict(
        {
            "workload": {
                "workflows": list(),
                "storage": dict(),
                "auth": dict(),
                "attrs": "",
            }
        }
    )
    payload["workload"]["workflows"] = workflow_list
    payload["workload"]["storage"]["attrs"] = get_attributes(storage)
    payload["workload"]["auth"]["attrs"] = get_attributes(auth)
    payload["workload"]["attrs"] = get_attributes(conf["workload"])

    LOG.debug("The generated dictionary is \n %s", payload)
    return payload


def submit_workload(config: argparse.Namespace) -> int:
    """Submits the workload based on the given config.

    Args:
        config:     CLI parameters passed for submit subcommand.

    Returns:
        0 on Success else 1
    """
    LOG.info("Preparing to submit workload.")
    data = generate_payload(config)
    workload = render_xml(data)
    return exec_command(cmd=f"cd {APP_DIR} && ./cli.sh submit {workload}").returncode


def run(config: argparse.Namespace) -> int:
    """Method that executes the main workload.

    Here, the provided configuration is converted to XML and then

    Args:
        config:     The arguments passed via CLI.

    Returns:
        0 on Success else 1
    """
    if config.ops == "cancel":
        return exec_command(
            cmd=f"cd {APP_DIR} && ./cli.sh cancel {config.job_id}"
        ).returncode

    if config.ops == "submit":
        return submit_workload(config)


def module_args() -> argparse.Namespace:
    """Specifies the arguments for the module."""
    p = argparse.ArgumentParser(description="COS Bench Workload utility.")
    sub_p = p.add_subparsers(description="Operation to be performed", dest="ops")

    # submit options
    submit_p = sub_p.add_parser("submit", help="submit the workload")
    submit_p.add_argument("conf_file", help="Workload configuration.")
    submit_p.add_argument(
        "--rgw-endpoint",
        dest="rgw_endpoint",
        help="Endpoint against which workloads are executed.",
    )

    # cancel options
    cancel_p = sub_p.add_parser("cancel", help="cancel a work in progress job.")
    cancel_p.add_argument("job_id", help="workload to be cancelled.")

    return p.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s : %(message)s", level=logging.DEBUG
    )
    args = module_args()
    rc = 0

    try:
        rc = run(args)
    except BaseException as be:  # noqa
        LOG.exception("Got an exception")
        sys.exit(1)

    if rc != 0:
        LOG.info("Execution completed with errors")
        sys.exit(rc)

    LOG.info("Execution completed successfully.")
