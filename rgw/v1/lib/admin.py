import subprocess
import v1.utils.log as log
import v1.utils.utils as utils
import json
from v1.lib.io_info import AddIOInfo


class UserMgmt(object):
    def __init__(self):
        self.exec_cmd = lambda cmd: subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

    def create_admin_user(self, username, displayname, cluster_name='ceph'):
        try:
            add_io_info = AddIOInfo()
            cmd = 'radosgw-admin user create --uid=%s --display-name=%s --cluster %s' % (
            username, displayname, cluster_name)
            log.info('cmd: %s' % cmd)
            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            v = variable.stdout.read()
            v_as_json = json.loads(v)
            # log.info(v_as_json)
            user_details = {}
            user_details['user_id'] = v_as_json['user_id']
            user_details['display_name'] = v_as_json['display_name']
            user_details['access_key'] = v_as_json['keys'][0]['access_key']
            user_details['secret_key'] = v_as_json['keys'][0]['secret_key']
            add_io_info.add_user_info(**{'user_id': user_details['user_id'],
                                         'access_key': user_details['access_key'],
                                         'secret_key': user_details['secret_key']})
            return user_details
        except subprocess.CalledProcessError as e:
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
            raise AssertionError(status[1])
        log.info('quota set complete')

    def enable_bucket_quota(self, uid):
        cmd = 'radosgw-admin quota enable --quota-scope=bucket --uid=%s' % uid
        status = utils.exec_shell_cmd(cmd)
        if not status[0]:
            raise AssertionError(status[1])
        log.info('quota set complete')


if __name__ == '__main__':
    o = UserMgmt()
    o.create_admin_user('rakesh', 'rakesh123')
