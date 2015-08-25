# Owner: Shilpa
# Email: smanjara@redhat.com
# Script to modify nova.conf file
# This script assumes that ceph cluster and openstack node is already set up.
#  Test Description:
#   a) Open the nova.conf file and read the contents
#   b) Set the ceph configuration options in the nova.conf file 
#  Success: exit code: 0
#  Failure: Non Zero Exit or ERROR message in output

import ConfigParser

# Read the cinder config file
config = ConfigParser.ConfigParser()
config.read('/etc/cinder/cinder.conf')

# Add the following lines to configure cinder to use ceph as backend driver
config.set('DEFAULT', 'enabled_backends', 'rbd')
config.set('DEFAULT', 'glance_api_version', '2')

config.add_section('rbd')
config.set('rbd', 'volume_driver', 'cinder.volume.drivers.rbd.RBDDriver')
config.set('rbd', 'rbd_pool', 'volumes')
config.set('rbd', 'rbd_ceph_conf', ' /etc/ceph/ceph.conf')
config.set('rbd', 'rbd_flatten_volume_from_snapshot', 'false')
config.set('rbd', 'rbd_max_clone_depth', '5')
config.set('rbd', 'rbd_store_chunk_size', '4')
config.set('rbd', 'rados_connect_timeout', '-1')
config.set('rbd', 'rbd_user', 'cinder')
config.set('rbd', 'rbd_secret_uuid', '457eb676-33da-42ec-9a8c-9293d545c337')

# Write to the config file and close
with open('/etc/cinder/cinder.conf', 'a') as configfile:
     config.write(configfile)
configfile.close()

