import json
import logging
import os
import sys
from errno import ESTALE

import v2.utils.utils as utils
from v2.lib.exceptions import InvalidCephConfigOption
from v2.utils.utils import ConfigParse, FileOps

log = logging.getLogger()
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))


class ConfigOpts(object):
    def __init__(self):
        pass

    rgw_override_bucket_index_max_shards = "rgw_override_bucket_index_max_shards"
    rgw_data_log_num_shards = "rgw_data_log_num_shards"
    rgw_d3n_l1_local_datacache_enabled = "rgw_d3n_l1_local_datacache_enabled"
    rgw_d3n_l1_datacache_persistent_path = "rgw_d3n_l1_datacache_persistent_path"
    rgw_d3n_l1_datacache_size = "rgw_d3n_l1_datacache_size"
    rgw_bucket_default_quota_max_objects = "rgw_bucket_default_quota_max_objects"
    rgw_dynamic_resharding = "rgw_dynamic_resharding"
    rgw_max_objs_per_shard = "rgw_max_objs_per_shard"
    rgw_max_dynamic_shards = "rgw_max_dynamic_shards"
    rgw_reshard_thread_interval = "rgw_reshard_thread_interval"
    rgw_lc_debug_interval = "rgw_lc_debug_interval"
    rgw_enable_lc_threads = "rgw_enable_lc_threads"
    rgw_bucket_eexist_override = "rgw_bucket_eexist_override"
    rgw_lifecycle_work_time = "rgw_lifecycle_work_time"
    rgw_lc_max_worker = "rgw_lc_max_worker"
    rgw_lc_max_wp_worker = "rgw_lc_max_wp_worker"
    debug_rgw = "debug_rgw"
    log_to_file = "log_to_file"
    rgw_crypt_require_ssl = "rgw_crypt_require_ssl"
    bluestore_block_size = "bluestore_block_size"
    rgw_gc_max_queue_size = "rgw_gc_max_queue_size"
    rgw_gc_processor_max_time = "rgw_gc_processor_max_time"
    rgw_gc_max_concurrent_io = "rgw_gc_max_concurrent_io"
    rgw_gc_max_trim_chunk = "rgw_gc_max_trim_chunk"
    rgw_objexp_gc_interval = "rgw_objexp_gc_interval"
    rgw_gc_obj_min_wait = "rgw_gc_obj_min_wait"
    rgw_run_sync_thread = "rgw_run_sync_thread"
    rgw_gc_processor_period = "rgw_gc_processor_period"
    rgw_swift_versioning_enabled = "rgw_swift_versioning_enabled"
    rgw_sts_key = "rgw_sts_key"
    rgw_s3_auth_use_sts = "rgw_s3_auth_use_sts"
    rgw_crypt_require_ssl = "rgw_crypt_require_ssl"
    rgw_crypt_sse_s3_backend = "rgw_crypt_sse_s3_backend"
    rgw_crypt_sse_s3_vault_addr = "rgw_crypt_sse_s3_vault_addr"
    rgw_crypt_sse_s3_vault_auth = "rgw_crypt_sse_s3_vault_auth"
    rgw_crypt_sse_s3_vault_prefix = "rgw_crypt_sse_s3_vault_prefix"
    rgw_crypt_sse_s3_vault_secret_engine = "rgw_crypt_sse_s3_vault_secret_engine"
    rgw_enable_static_website = "rgw_enable_static_website"
    rgw_swift_url_prefix = "rgw_swift_url_prefix"
    rgw_dynamic_resharding_reduction_wait = "rgw_dynamic_resharding_reduction_wait"
    rgw_reshard_debug_interval = "rgw_reshard_debug_interval"


class CephConfFileOP(FileOps, ConfigParse):
    """
    To check/create ceph.conf file
    """

    def __init__(self, ssh_con=None, ceph_conf_path="/etc/ceph/ceph.conf"):
        if ssh_con is not None:
            self.ceph_conf_path = ceph_conf_path
            self.ceph_conf_path_tmp = ceph_conf_path + ".rgw.tmp"
            FileOps.__init__(self, self.ceph_conf_path_tmp, type="ceph.conf")
            ConfigParse.__init__(self, self.ceph_conf_path, ssh_con)
        else:
            self.ceph_conf_path = ceph_conf_path
            FileOps.__init__(self, self.ceph_conf_path, type="ceph.conf")
            ConfigParse.__init__(self, self.ceph_conf_path)

    def check_if_config_exists(self, config):
        """
        This function is to check if the ceph.conf file exists with the config

        Parameters:
            config(char): config file

        Returns:
            tmp: if the config file exists, Else returns false
        """
        log.info("checking if config: %s exists" % config)
        contents = self.get_data()
        config_exists = next((s for s in contents if config in s), None)
        if config_exists is None:
            log.info("no config found")
            return False
        else:
            tmp = config_exists.split("=")
            log.info("config: %s exists" % tmp[0])
            log.info("%s value set to: %s" % (tmp[0], tmp[1]))
            return tmp

    def create_section(self, section):
        """
        This function is to create a new section

        Parameters:
            section: section to be created

        """
        log.info("creating new section: %s" % section)
        new_section = self.add_section(section)
        self.add_data(new_section)

    def set_to_ceph_conf_file(self, section, option, value=None, ssh_con=None):
        """
        This function is to add section, option, value to the ceph.conf file

        Parameters:
            section:
            option:
            value:
        """
        log.info("adding to ceph conf")
        log.info("section: %s" % section)
        log.info("option: %s" % option)
        log.info("value: %s" % value)
        cfg = self.set(section, option, value)
        if ssh_con is not None:
            self.add_data(cfg, ssh_con)
        else:
            self.add_data(cfg)


class CephConfigSet:
    def set_to_ceph_cli(self, key, value, set_to_all=False, remote_ssh_con=None):
        log.info("setting key and value using ceph config set cli")
        self.prefix = "sudo ceph config set"

        cmd_ps = "ceph orch ps --daemon_type rgw -f json"
        if remote_ssh_con:
            out_ps = utils.remote_exec_shell_cmd(
                remote_ssh_con, cmd_ps, return_output=True
            )
        else:
            out_ps = utils.exec_shell_cmd(cmd_ps)
        out = json.loads(out_ps)
        daemon_name_list = []
        for node in out:
            daemon_name = node.get("service_name")
            daemon_name_list.append(daemon_name)

        for daemon in daemon_name_list:
            self.who = "client." + daemon  # naming convention as ceph conf
            if value is True:
                value = "true"
            log.info(f"got key: {key}")
            log.info(f"got value: {value}")
            cmd_list = [self.prefix, self.who, key, str(value)]
            cmd = " ".join(cmd_list)
            if remote_ssh_con:
                config_set = utils.remote_exec_shell_cmd(
                    remote_ssh_con, cmd, return_output=False
                )
            else:
                config_set = utils.exec_shell_cmd(cmd)
            if config_set is False:
                raise InvalidCephConfigOption("Invalid ceph config options")
            if not set_to_all:
                break


class CephConfOp(CephConfFileOP, CephConfigSet):
    def __init__(self, ssh_con=None) -> None:
        super().__init__(ssh_con)

    def set_to_ceph_conf(
        self,
        section,
        option,
        value=None,
        ssh_con=None,
        set_to_all=False,
        remote_ssh_con=None,
    ):
        version_id, version_name = utils.get_ceph_version()
        log.info(f"ceph version id: {version_id}")
        log.info(f"version name: {version_name}")

        if version_name in ["luminous", "nautilus"]:
            log.info("using ceph_conf to config values")
            if ssh_con is not None:
                self.set_to_ceph_conf_file(section, option, value, ssh_con)
            else:
                self.set_to_ceph_conf_file(section, option, value)
        else:
            log.info("using ceph config cli to set the config values")
            log.info(option)
            log.info(value)
            self.set_to_ceph_cli(
                option, value, set_to_all=set_to_all, remote_ssh_con=remote_ssh_con
            )
