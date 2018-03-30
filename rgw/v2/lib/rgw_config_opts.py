import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
from v2.utils.utils import FileOps, ConfigParse
import v2.utils.log as log


class ConfigOpts(object):
    def __init__(self):
        pass

    rgw_override_bucket_index_max_shards = 'rgw_override_bucket_index_max_shards'
    rgw_bucket_default_quota_max_objects = 'rgw_bucket_default_quota_max_objects'


class CephConfOp(FileOps, ConfigParse):
    def __init__(self, ceph_conf_path='/etc/ceph/ceph.conf'):

        self.ceph_conf_path = ceph_conf_path

        FileOps.__init__(self, self.ceph_conf_path, type='ceph.conf')
        ConfigParse.__init__(self, self.ceph_conf_path)

    def check_if_config_exists(self, config):

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

        log.info('creating new section: %s' % section)

        new_section = self.add_section(section)
        self.add_data(new_section)

    def set_to_ceph_conf(self, section, option, value=None):

        log.info('adding to ceph conf')

        log.info('section: %s' % section)
        log.info('option: %s' % option)
        log.info('value: %s' % value)

        cfg = self.set(section, option, value)
        self.add_data(cfg)


