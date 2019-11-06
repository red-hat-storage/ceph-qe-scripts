import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.log as log
from v2.lib.admin import UserMgmt
import names
import random
import string
import inspect
import yaml
import v2.lib.s3.write_io_info as write_io_info


@write_io_info.logioinfo
def resource_op(exec_info):
    log.info('resource Name: %s' % exec_info['resource'])
    obj = exec_info['obj']
    resource = exec_info['resource']
    result = None
    log.info('function tye: %s' % inspect.ismethod(getattr(obj, resource)))

    try:
        if inspect.ismethod(getattr(obj, resource)) or inspect.isfunction(getattr(obj, resource)):
            if exec_info.has_key("args"):
                log.info('in args')
                log.info('args_val: %s' % exec_info['args'])
                if exec_info['args'] is not None:
                    result = getattr(obj, resource)(*tuple(exec_info['args']))
                else:
                    result = getattr(obj, resource)()
            if exec_info.has_key('kwargs'):
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


def create_pem():
    """
    :param pem_file: Name of the Certificate (.pem) file to be created in the present working directory
    """
    log.info('Creating pem file')
    cmd = 'openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.csr -days 365 -nodes ' \
          '-subj "/C=IN/ST=KA/L=BLR/O=Carina Company/OU=Redhat/CN=*.ceph.redhat.com"'
    out = utils.exec_shell_cmd(cmd)
    pem_file = 'server.pem'
    if out is False:
        raise TestExecError("Key file creation error")
    log.info('output :%s' % out)
    cmd2 = 'cat server.csr server.key > %s' % pem_file
    out2 = utils.exec_shell_cmd(cmd2)
    if out2 is False:
        raise TestExecError("Pem file generation error")
    log.info('output :%s' % out2)
    cmd3 = 'cp %s /etc/ssl/certs/%s' % (pem_file, pem_file)
    out3 = utils.exec_shell_cmd(cmd3)
    if out3 is False:
        raise TestExecError("Linux copy error")
    log.info('output :%s' % out3)
    return


class Config(object):
    def __init__(self, conf_file):
        with open(conf_file, 'r') as f:
            self.doc = yaml.load(f)
        log.info('got config: \n%s' % self.doc)

    def read(self):
        self.shards = None
        self.max_objects = None
        self.user_count = self.doc['config'].get('user_count')
        self.bucket_count = self.doc['config'].get('bucket_count')
        self.objects_count = self.doc['config'].get('objects_count')
        self.use_aws4 = self.doc['config'].get('use_aws4', None)
        self.objects_size_range = self.doc['config'].get('objects_size_range')
        self.sharding_type = self.doc['config'].get('sharding_type')
        self.split_size = self.doc['config'].get('split_size', 5)
        self.test_ops = self.doc['config'].get('test_ops')
        self.mapped_sizes = self.doc['config'].get('mapped_sizes')
        self.bucket_policy_op = self.doc['config'].get('bucket_policy_op')
        self.container_count = self.doc['config'].get('container_count')
        self.version_count = self.doc['config'].get('version_count')
        self.local_file_delete = self.doc['config'].get('local_file_delete', False)
