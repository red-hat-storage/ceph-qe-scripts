import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.log as log
from v2.lib.admin import UserMgmt
import names
import random
import string
import inspect
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


class Config(object):
    def __init__(self):
        pass
