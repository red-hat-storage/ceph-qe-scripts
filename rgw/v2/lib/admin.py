import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import subprocess
import v2.utils.log as log
import v2.utils.utils as utils
import json
from v2.lib.s3.write_io_info import BasicIOInfoStructure, TenantInfo
from v2.lib.s3.write_io_info import AddUserInfo


class UserMgmt(object):

    def __init__(self):

        self.exec_cmd = lambda cmd: subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

    def create_admin_user(self, user_id, displayname, cluster_name='ceph'):

        try:

            write_user_info = AddUserInfo()
            basic_io_structure = BasicIOInfoStructure()

            log.info('cluster name: %s' % cluster_name)

            cmd = 'radosgw-admin user create --uid=%s --display-name=%s --cluster %s' % (
                user_id, displayname, cluster_name)
            log.info('cmd to execute:\n%s' % cmd)
            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            v = variable.stdout.read()

            v_as_json = json.loads(v)

            log.info(v_as_json)

            user_details = {}

            user_details['user_id'] = v_as_json['user_id']
            user_details['display_name'] = v_as_json['display_name']

            user_details['access_key'] = v_as_json['keys'][0]['access_key']

            user_details['secret_key'] = v_as_json['keys'][0]['secret_key']

            user_info = basic_io_structure.user(**{'user_id': user_details['user_id'],
                                                   'access_key': user_details['access_key'],
                                                   'secret_key': user_details['secret_key']})

            write_user_info.add_user_info(user_info)

            log.info('access_key: %s' % user_details['access_key'])
            log.info('secret_key: %s' % user_details['secret_key'])
            log.info('user_id: %s' % user_details['user_id'])

            return user_details

        except (subprocess.CalledProcessError) as e:
            error = e.output + str(e.returncode)
            log.error(error)
            # traceback.print_exc(e)
            return False

    def create_tenant_user(self, tenant_name, user_id, displayname, cluster_name="ceph"):

        try:

            write_user_info = AddUserInfo()
            basic_io_structure = BasicIOInfoStructure()
            tenant_info = TenantInfo()

            keys = utils.gen_access_key_secret_key(user_id)

            cmd = 'radosgw-admin --tenant %s --uid %s --display-name "%s" ' \
                  '--access_key %s --secret %s user create --cluster %s' % \
                  (tenant_name, user_id, displayname, keys['access_key'], keys['secret_key'], cluster_name)

            log.info('cmd to execute:\n%s' % cmd)

            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

            v = variable.stdout.read()

            v_as_json = json.loads(v)

            log.info(v_as_json)

            user_details = {}

            user_details['user_id'] = v_as_json['user_id']
            user_details['display_name'] = v_as_json['display_name']

            user_details['access_key'] = v_as_json['keys'][0]['access_key']

            user_details['secret_key'] = v_as_json['keys'][0]['secret_key']

            user_details['tenant'], user_details['user_id'] = user_details['user_id'].split('$')

            user_info = basic_io_structure.user(**{'user_id': user_details['user_id'],
                                                   'access_key': user_details['access_key'],
                                                   'secret_key': user_details['secret_key']})

            write_user_info.add_user_info(dict(user_info, **tenant_info.tenant(user_details['tenant'])))

            log.info('access_key: %s' % user_details['access_key'])
            log.info('secret_key: %s' % user_details['secret_key'])
            log.info('user_id: %s' % user_details['user_id'])
            log.info('tenant: %s' % user_details['tenant'])

            return user_details

        except (subprocess.CalledProcessError) as e:
            error = e.output + str(e.returncode)
            log.error(error)
            return False

    def create_subuser(self, tenant_name, user_id, cluster_name="ceph"):

        try:

            write_user_info = AddUserInfo()
            basic_io_structure = BasicIOInfoStructure()
            tenant_info = TenantInfo()

            keys = utils.gen_access_key_secret_key(user_id)

            cmd = 'radosgw-admin subuser create --uid=%s$%s --subuser=%s:swift --tenant=%s --access=full' % (
            tenant_name, user_id, user_id, tenant_name)

            log.info('cmd to execute:\n%s' % cmd)

            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

            v = variable.stdout.read()

            v_as_json = json.loads(v)

            log.info(v_as_json)

            user_details = {}

            user_details['user_id'] = v_as_json['subusers'][0]['id']

            user_details['key'] = v_as_json['swift_keys'][0]['secret_key']

            user_details['tenant'], _ = user_details['user_id'].split('$')

            user_info = basic_io_structure.user(**{'user_id': user_details['user_id'],
                                                   'secret_key': user_details['key'],
                                                   'access_key': ' '})

            write_user_info.add_user_info(dict(user_info, **tenant_info.tenant(user_details['tenant'])))

            log.info('secret_key: %s' % user_details['key'])
            log.info('user_id: %s' % user_details['user_id'])
            log.info('tenant: %s' % user_details['tenant'])

            return user_details

        except (subprocess.CalledProcessError) as e:
            error = e.output + str(e.returncode)
            log.error(error)
            return False


class QuotaMgmt(object):

    def __init__(self):
        self.exec_cmd = lambda cmd: subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

    def set_bucket_quota(self, uid, max_objects):

        cmd = 'radosgw-admin quota set --uid=%s --quota-scope=bucket --max-objects=%s' % (uid, max_objects)

        status = utils.exec_shell_cmd(cmd)

        if not status[0]:
            raise AssertionError, status[1]

        log.info('quota set complete')

    def enable_bucket_quota(self, uid):

        cmd = 'radosgw-admin quota enable --quota-scope=bucket --uid=%s' % uid

        status = utils.exec_shell_cmd(cmd)

        if not status[0]:
            raise AssertionError, status[1]

        log.info('quota set complete')
