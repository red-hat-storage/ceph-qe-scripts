import os, sys
import logging
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
from v2.utils.utils import FileOps, ConfigParse

log = logging.getLogger()


class ConfigOpts(object):
    def __init__(self):
        pass

    rgw_override_bucket_index_max_shards = 'rgw_override_bucket_index_max_shards'
    rgw_bucket_default_quota_max_objects = 'rgw_bucket_default_quota_max_objects'
    rgw_dynamic_resharding = 'rgw_dynamic_resharding'
    rgw_max_objs_per_shard = 'rgw_max_objs_per_shard'
    rgw_lc_debug_interval = 'rgw_lc_debug_interval'
    rgw_lc_max_worker = 'rgw_lc_max_worker'
    debug_rgw = 'debug_rgw'
    rgw_crypt_require_ssl = 'rgw_crypt_require_ssl'
    bluestore_block_size = 'bluestore_block_size'
    rgw_gc_max_queue_size = 'rgw_gc_max_queue_size'
    rgw_gc_processor_max_time = 'rgw_gc_processor_max_time'
    rgw_gc_max_concurrent_io = 'rgw_gc_max_concurrent_io'
    rgw_gc_max_trim_chunk = 'rgw_gc_max_trim_chunk'
    rgw_objexp_gc_interval = 'rgw_objexp_gc_interval'
    rgw_gc_obj_min_wait = 'rgw_gc_obj_min_wait'
    rgw_gc_processor_period = 'rgw_gc_processor_period'
    rgw_swift_versioning_enabled = 'rgw_swift_versioning_enabled'



class CephConfOp(FileOps, ConfigParse):
    """
        To check/create ceph.conf file
    """
    def __init__(self, ceph_conf_path='/etc/ceph/ceph.conf'):
        self.ceph_conf_path = ceph_conf_path
        FileOps.__init__(self, self.ceph_conf_path, type='ceph.conf')
        ConfigParse.__init__(self, self.ceph_conf_path)

    def check_if_config_exists(self, config):
        """
            This function is to check if the ceph.conf file exists with the config

            Parameters:
                config(char): config file

            Returns:
                tmp: if the config file exists, Else returns false
        """
        log.info('checking if config: %s exists' % config)
        contents = self.get_data()
        config_exists = next((s for s in contents if config in s), None)
        if config_exists is None:
            log.info('no config found')
            return False
        else:
            tmp = config_exists.split("=")
            log.info('config: %s exists' % tmp[0])
            log.info('%s value set to: %s' % (tmp[0], tmp[1]))
            return tmp

    def create_section(self, section):
        """
            This function is to create a new section 

            Parameters:
                section: section to be created

        """
        log.info('creating new section: %s' % section)
        new_section = self.add_section(section)
        self.add_data(new_section)

    def set_to_ceph_conf(self, section, option, value=None):
        """
            This function is to add section, option, value to the ceph.conf file

            Parameters:
                section:
                option:
                value:
        """
        log.info('adding to ceph conf')
        log.info('section: %s' % section)
        log.info('option: %s' % option)
        log.info('value: %s' % value)
        cfg = self.set(section, option, value)
        self.add_data(cfg)

