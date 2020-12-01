import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
from v2.lib.admin import UserMgmt
# import v2.lib.frontend_configure as frontend_configure
from v2.lib.frontend_configure import Frontend
from v2.lib.exceptions import ConfigError
import names
import random
import string
import inspect
import yaml
import v2.lib.s3.write_io_info as write_io_info
import v2.lib.pem as pem
import traceback
import logging

log = logging.getLogger()


@write_io_info.logioinfo
def resource_op(exec_info):
    """
        This function is for resource 
        
        Parameters:
            exec_info: 

        Returns:
            result: 
    """
    log.info('resource Name: %s' % exec_info['resource'])
    obj = exec_info['obj']
    resource = exec_info['resource']
    result = None
    log.info('function type: %s' % inspect.ismethod(getattr(obj, resource)))

    try:
        if inspect.ismethod(getattr(obj, resource)) or inspect.isfunction(getattr(obj, resource)):
            if "args" in exec_info:
                log.info('in args')
                log.info('args_val: %s' % exec_info['args'])
                if exec_info['args'] is not None:
                    result = getattr(obj, resource)(*tuple(exec_info['args']))
                else:
                    result = getattr(obj, resource)()
            if 'kwargs' in exec_info:
                log.info('in kwargs')
                log.info('kwargs value: %s' % exec_info['kwargs'])
                result = getattr(obj, resource)(**dict(exec_info['kwargs']))
        else:
            log.info(' type is: %s' % type(getattr(obj, resource)))
            result = getattr(obj, resource)
        return result

    except (Exception, AttributeError) as e:
        log.error('Resource Execution failed')
        log.error(e)
        return False


def create_users(no_of_users_to_create, cluster_name='ceph'):
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
    for i in range(no_of_users_to_create):
        user_details = admin_ops.create_admin_user(
            user_id=names.get_first_name().lower() + random.choice(string.ascii_lowercase) + "." + str(
                random.randint(1, 1000)),
            displayname=names.get_full_name().lower(),
            cluster_name=cluster_name)
        all_users_details.append(user_details)
    return all_users_details


def create_tenant_users(no_of_users_to_create, tenant_name, cluster_name='ceph'):
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
    for i in range(no_of_users_to_create):
        user_details = admin_ops.create_tenant_user(
            user_id=names.get_first_name().lower() + random.choice(string.ascii_lowercase) + "." + str(
                random.randint(1, 1000)),
            displayname=names.get_full_name().lower(),
            cluster_name=cluster_name,
            tenant_name=tenant_name)
        all_users_details.append(user_details)
    return all_users_details


class Config(object):
    def __init__(self, conf_file=None):
        self.doc = None
        if not os.path.exists(conf_file):
            raise ConfigError('config file not given')
        with open(conf_file, 'r') as f:
            self.doc = yaml.safe_load(f)
        log.info('got config: \n%s' % self.doc)

    def read(self):
        """
            This function reads all the configurations parameters
        """
        if self.doc is None:
            raise ConfigError('config file not given')
        self.shards = self.doc['config'].get('shards')
        # todo: better suited to be added under ceph_conf
        self.max_objects_per_shard = self.doc['config'].get('max_objects_per_shard')
        self.max_objects = None
        self.user_count = self.doc['config'].get('user_count')
        self.bucket_count = self.doc['config'].get('bucket_count')
        self.objects_count = self.doc['config'].get('objects_count')
        self.pseudo_dir_count = self.doc['config'].get('pseudo_dir_count')
        self.use_aws4 = self.doc['config'].get('use_aws4', None)
        self.objects_size_range = self.doc['config'].get('objects_size_range')
        self.sharding_type = self.doc['config'].get('sharding_type')
        self.split_size = self.doc['config'].get('split_size', 5)
        self.test_ops = self.doc['config'].get('test_ops')
        self.lifecycle_conf = self.doc['config'].get('lifecycle_conf')
        self.delete_marker_ops = self.doc['config'].get('delete_marker_ops')
        self.mapped_sizes = self.doc['config'].get('mapped_sizes')
        self.bucket_policy_op = self.doc['config'].get('bucket_policy_op')
        self.container_count = self.doc['config'].get('container_count')
        self.version_count = self.doc['config'].get('version_count')
        self.local_file_delete = self.doc['config'].get('local_file_delete', False)
        self.ceph_conf = self.doc['config'].get('ceph_conf')
        self.gc_verification = self.doc['config'].get('gc_verification', False)
        self.ssl = self.doc['config'].get('ssl',)
        self.frontend = self.doc['config'].get('frontend')
        self.io_op_config = self.doc.get('config').get('io_op_config')
        frontend_config = Frontend()

        # if frontend is set in config yaml
        if self.frontend:
            log.info('frontend is set in config.yaml: {}'.format(self.frontend))
            if self.ssl is None:
                # if ssl is not set in config.yaml
                log.info('ssl is not set in config.yaml')
                self.ssl = frontend_config.curr_ssl
            # configuring frontend
            frontend_config.set_frontend(self.frontend, ssl=self.ssl)

        # if ssl is True or False in config yaml
        # and if frontend is not set in config yaml,
        elif self.ssl is not None and not self.frontend:
            # get the current frontend and add ssl to it.
            log.info('ssl is set in config.yaml')
            log.info('frontend is not set in config.yaml')
            frontend_config.set_frontend(frontend_config.curr_frontend, ssl=self.ssl)

        elif self.ssl is None:
            # if ssl is not set in config yaml, check if ssl_enabled and configured by default,
            # set sel.ssl = True or False based on ceph conf
            log.info('ssl is not set in config.yaml')
            self.ssl = frontend_config.curr_ssl
