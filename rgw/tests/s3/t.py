import os
import boto
import boto.s3.connection
import sys
from boto.s3.key import Key
from random import randint
import subprocess
# import utils.log as log
import json


class RGWAdminOps(object):

    def __init__(self):

        self.exec_cmd = lambda cmd: subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

    def create_admin_user(self, username, displayname):

        try:
            cmd = 'radosgw-admin user create --uid="%s" --display-name="%s"' % (username, displayname)
            # log.info('cmd')
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
            # og.error(error)
            return False

u1_bucket = 'sandy2.bucky.0'
u2_bucket = 'margaret2.bucky.0'


#ua = RGWAdminOps()
#user_details = ua.create_admin_user('rakesh', 'rakeshgm')


access_key = "9I61W6PMDXX8FOBEKOCE"
secret_key = "LMw7MciduMP6V4b7EjYm9T7al5UKkcXjavGF9J9L"

conn = boto.connect_s3(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    host='magna022',
    port=8080,
    is_secure=False,
    calling_format=boto.s3.connection.OrdinaryCallingFormat(),
)


conn.get_canonical_user_id()

bu = conn.get_bucket(u1_bucket)


acp = bu.get_acl()

for grant in acp.acl.grants:
    print grant.permission, grant.id



"""

all_keys = bu.get_all_keys()
for key in all_keys:
    print 'all keys 1--------------'
    print 'name: %s' % key.name
    print 'version_id %s' % key.version_id
    print 'size: %s' % key.size
    print 'etag: %s' % key.etag
    print 'md5: %s' % key.md5

    print '--------------'
"""