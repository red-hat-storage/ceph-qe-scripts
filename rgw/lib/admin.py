import subprocess
import utils.log as log
import json


class RGWAdminOps(object):

    def __init__(self):

        self.exec_cmd = lambda cmd: subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

    def create_admin_user(self, username, displayname):

        try:
            cmd = 'radosgw-admin user create --uid="%s" --display-name="%s"' % (username, displayname)
            log.info('cmd')
            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            v = variable.stdout.read()

            v_as_json = json.loads(v)

            # log.info(v_as_json)

            user_details = {}

            user_details['user_id'] = v_as_json['user_id']
            user_details['display_name'] = v_as_json['display_name']

            user_details['access_key'] = v_as_json['keys'][0]['access_key']

            user_details['secret_key'] = v_as_json['keys'][0]['secret_key']

            return user_details

        except subprocess.CalledProcessError as e:
            error = e.output + str(e.returncode)
            log.error(error)
            return False
