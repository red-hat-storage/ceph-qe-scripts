import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import inspect
import json
import logging
import random
import string

import names
import v2.lib.s3.write_io_info as write_io_info
import v2.utils.utils as utils
import yaml
from v2.lib.admin import AddUserInfo, BasicIOInfoStructure, TenantInfo, UserMgmt
from v2.lib.exceptions import ConfigError

# import v2.lib.frontend_configure as frontend_configure
from v2.lib.frontend_configure import Frontend, Frontend_CephAdm

log = logging.getLogger()

lib_dir = os.path.abspath(os.path.join(__file__, "../"))


@write_io_info.logioinfo
def resource_op(exec_info):
    """
    This function is for resource

    Parameters:
        exec_info:

    Returns:
        result:
    """
    log.info("resource Name: %s" % exec_info["resource"])
    obj = exec_info["obj"]
    resource = exec_info["resource"]
    result = None
    log.info("function type: %s" % inspect.ismethod(getattr(obj, resource)))

    try:
        if inspect.ismethod(getattr(obj, resource)) or inspect.isfunction(
            getattr(obj, resource)
        ):
            if "args" in exec_info:
                log.info("in args")
                log.info("args_val: %s" % exec_info["args"])
                if exec_info["args"] is not None:
                    result = getattr(obj, resource)(*tuple(exec_info["args"]))
                else:
                    result = getattr(obj, resource)()
            if "kwargs" in exec_info:
                log.info("in kwargs")
                log.info("kwargs value: %s" % exec_info["kwargs"])
                result = getattr(obj, resource)(**dict(exec_info["kwargs"]))
        else:
            log.info(" type is: %s" % type(getattr(obj, resource)))
            result = getattr(obj, resource)
        return result

    except (Exception, AttributeError) as e:
        log.error("Resource Execution failed")
        log.error(e)
        return False


def create_users(no_of_users_to_create, user_names=None, cluster_name="ceph"):
    """
    This function is to create n users on the cluster

    Parameters:
        no_of_users_to_create(int): users to create
        cluster_name(char): Name of the ceph cluster. defaults to 'ceph'

    Returns:
        all_users_details
    """
    admin_ops = UserMgmt()
    all_users_details = []
    primary = utils.is_cluster_primary()
    user_detail_file = os.path.join(lib_dir, "user_details.json")
    if primary:
        for i in range(no_of_users_to_create):
            if user_names:
                user_details = admin_ops.create_admin_user(
                    user_id=user_names,
                    displayname=user_names,
                    cluster_name=cluster_name,
                )
                all_users_details.append(user_details)
            else:
                user_details = admin_ops.create_admin_user(
                    user_id=names.get_first_name().lower()
                    + random.choice(string.ascii_lowercase)
                    + "."
                    + str(random.randint(1, 1000)),
                    displayname=names.get_full_name().lower(),
                    cluster_name=cluster_name,
                )
                all_users_details.append(user_details)
        with open(user_detail_file, "w") as fout:
            json.dump(all_users_details, fout)
    elif not primary:
        if not os.path.exists(user_detail_file):
            raise FileNotFoundError(
                "user_details.json missing, this is needed in multisite setup"
            )
        with open(user_detail_file, "r") as fout:
            all_users_details = json.load(fout)
        for each_user_info in all_users_details:
            write_user_info = AddUserInfo()
            basic_io_structure = BasicIOInfoStructure()
            user_info = basic_io_structure.user(
                **{
                    "user_id": each_user_info["user_id"],
                    "access_key": each_user_info["access_key"],
                    "secret_key": each_user_info["secret_key"],
                }
            )
            write_user_info.add_user_info(user_info)
    return all_users_details


def create_tenant_users(no_of_users_to_create, tenant_name, cluster_name="ceph"):
    """
    This function is to create n users with tenant on the cluster

    Parameters:
        no_of_users_to_create(int): users to create with tenant
        cluster_name(char): Name of the ceph cluster. defaults to 'ceph'

    Returns:
        all_users_details
    """
    admin_ops = UserMgmt()
    all_users_details = []
    primary = utils.is_cluster_primary()
    user_detail_file = os.path.join(lib_dir, "user_details.json")
    if primary:
        for i in range(no_of_users_to_create):
            user_details = admin_ops.create_tenant_user(
                user_id=names.get_first_name().lower()
                + random.choice(string.ascii_lowercase)
                + "."
                + str(random.randint(1, 1000)),
                displayname=names.get_full_name().lower(),
                cluster_name=cluster_name,
                tenant_name=tenant_name,
            )
            all_users_details.append(user_details)
        with open(user_detail_file, "w") as fout:
            json.dump(all_users_details, fout)
    elif not primary:
        if not os.path.exists(user_detail_file):
            raise FileNotFoundError(
                "user_details.json missing, this is needed in multisite setup"
            )
        with open(user_detail_file, "r") as fout:
            all_users_details = json.load(fout)
        log.info("dump user_info into io_info.yaml")
        for each_user_info in all_users_details:
            write_user_info = AddUserInfo()
            basic_io_structure = BasicIOInfoStructure()
            tenant_info = TenantInfo()
            user_info = basic_io_structure.user(
                **{
                    "user_id": each_user_info["user_id"],
                    "access_key": each_user_info["access_key"],
                    "secret_key": each_user_info["secret_key"],
                }
            )
            write_user_info.add_user_info(
                dict(user_info, **tenant_info.tenant(each_user_info["tenant"]))
            )
    return all_users_details


class Config(object):
    def __init__(self, conf_file=None):
        self.doc = None
        if not os.path.exists(conf_file):
            raise ConfigError("config file not given")
        with open(conf_file, "r") as f:
            self.doc = yaml.safe_load(f)
        log.info("got config: \n%s" % self.doc)

    def read(self):
        """
        This function reads all the configurations parameters
        """
        if self.doc is None:
            raise ConfigError("config file not given")
        self.shards = self.doc["config"].get("shards")
        # todo: better suited to be added under ceph_conf
        self.max_objects_per_shard = self.doc["config"].get("max_objects_per_shard")
        self.max_objects = None
        self.user_count = self.doc["config"].get("user_count")
        self.user_remove = self.doc["config"].get("user_remove", True)
        self.user_type = self.doc["config"].get("user_type")
        self.bucket_count = self.doc["config"].get("bucket_count")
        self.objects_count = self.doc["config"].get("objects_count")
        self.pseudo_dir_count = self.doc["config"].get("pseudo_dir_count")
        self.use_aws4 = self.doc["config"].get("use_aws4", None)
        self.objects_size_range = self.doc["config"].get("objects_size_range")
        self.sharding_type = self.doc["config"].get("sharding_type")
        self.split_size = self.doc["config"].get("split_size", 5)
        self.test_ops = self.doc["config"].get("test_ops", {})
        self.lifecycle_conf = self.doc["config"].get("lifecycle_conf")
        self.delete_marker_ops = self.doc["config"].get("delete_marker_ops")
        self.mapped_sizes = self.doc["config"].get("mapped_sizes")
        self.bucket_policy_op = self.doc["config"].get("bucket_policy_op")
        self.container_count = self.doc["config"].get("container_count")
        self.version_count = self.doc["config"].get("version_count")
        self.version_enable = self.doc["config"].get("version_enable", False)
        self.copy_version_object = self.doc["config"].get("copy_version_object", False)
        self.object_expire = self.doc["config"].get("object_expire", False)
        self.dynamic_resharding = self.doc["config"].get("dynamic_resharding", False)
        self.manual_resharding = self.doc["config"].get("manual_resharding", False)
        self.reshard_cancel_cmd = self.doc["config"].get("reshard_cancel_cmd", False)
        self.large_object_upload = self.doc["config"].get("large_object_upload", False)
        self.bucket_sync_run_with_disable_sync_thread = self.doc["config"].get(
            "bucket_sync_run_with_disable_sync_thread", False
        )
        self.large_object_download = self.doc["config"].get(
            "large_object_download", False
        )
        self.local_file_delete = self.doc["config"].get("local_file_delete", False)
        self.sts = self.doc["config"].get("sts")
        self.ceph_conf = self.doc["config"].get("ceph_conf")
        self.gc_verification = self.doc["config"].get("gc_verification", False)
        self.bucket_sync_crash = self.doc["config"].get("bucket_sync_crash", False)
        self.bucket_sync_status = self.doc["config"].get("bucket_sync_status", False)
        self.bucket_sync_run = self.doc["config"].get("bucket_sync_run", False)
        self.bucket_stats = self.doc["config"].get("bucket_stats", False)
        self.header_size = self.doc["config"].get("header_size", False)
        self.test_datalog_trim_command = self.doc["config"].get(
            "test_datalog_trim_command", False
        )
        self.rgw_gc_obj_min_wait = self.doc["config"].get("rgw_gc_obj_min_wait", False)
        self.ssl = self.doc["config"].get(
            "ssl",
        )
        self.frontend = self.doc["config"].get("frontend")
        self.io_op_config = self.doc.get("config").get("io_op_config")
        self.radoslist_all = self.test_ops.get("radoslist_all", False)
        self.dbr_scenario = self.doc["config"].get("dbr_scenario", None)
        self.enable_sharding = self.doc["config"].get("enable_sharding", False)
        self.change_datalog_backing = self.test_ops.get("change_datalog_backing", False)
        self.modify_user = self.doc["config"].get("modify_user", False)
        self.suspend_user = self.doc["config"].get("suspend_user", False)
        self.enable_user = self.doc["config"].get("enable_user", False)
        self.delete_user = self.doc["config"].get("delete_user", False)
        self.persistent_flag = self.test_ops.get("persistent_flag", False)
        self.copy_object = self.test_ops.get("copy_object", False)
        self.get_topic_info = self.test_ops.get("get_topic_info", False)
        ceph_version_id, ceph_version_name = utils.get_ceph_version()
        # todo: improve Frontend class
        if ceph_version_name in ["luminous", "nautilus"]:
            frontend_config = Frontend()
        else:
            frontend_config = Frontend_CephAdm()

        # if frontend is set in config yaml
        if self.frontend:
            log.info("frontend is set in config.yaml: {}".format(self.frontend))
            if self.ssl is None:
                # if ssl is not set in config.yaml
                log.info("ssl is not set in config.yaml")
                self.ssl = frontend_config.curr_ssl
            # configuring frontend
            frontend_config.set_frontend(self.frontend, ssl=self.ssl)

        # if ssl is True or False in config yaml
        # and if frontend is not set in config yaml,
        elif self.ssl is not None and not self.frontend:
            # get the current frontend and add ssl to it.
            log.info("ssl is set in config.yaml")
            log.info("frontend is not set in config.yaml")
            frontend_config.set_frontend(frontend_config.curr_frontend, ssl=self.ssl)

        elif self.ssl is None:
            # if ssl is not set in config yaml, check if ssl_enabled and configured by default,
            # set sel.ssl = True or False based on ceph conf
            log.info("ssl is not set in config.yaml")
            self.ssl = frontend_config.curr_ssl
