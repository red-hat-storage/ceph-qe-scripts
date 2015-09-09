# Owner: Shilpa
# Email: smanjara@redhat.com
# Script to modify glance-api.conf file
# This script assumes that ceph cluster and openstack node is already set up.
#  Test Description:
#   a) Open the nova.conf file and read the contents
#   b) Set the ceph configuration options in the nova.conf file
#  Success: exit code: 0
#  Failure: Non Zero Exit or ERROR message in output

import ConfigParser

# Read the glance-api.conf file
cfg = ConfigParser.ConfigParser()
cfg.read('/etc/glance/glance-api.conf')

# Add the following lines to section "glance_store". This configures glance to use ceph as backend driver
cfg.set('glance_store', 'rbd_store_user', 'glance')
cfg.set('glance_store', 'rbd_store_pool', 'images')
cfg.set('glance_store', 'rbd_store_chunk_size', '8')
cfg.set('glance_store', 'rbd_store_ceph_conf', '/etc/ceph/ceph.conf')

# Add the following lines to enable glance to use ceph copy-on-write cloning of images
cfg.set('', 'show_image_direct_url', 'True')
cfg.set('', 'default_store', 'rbd')
cfg.set('', 'enable_v2_api', 'True')

# Write to the  config file and close
with open('/etc/glance/glance-api.conf', 'a') as configfile:
     cfg.write(configfile)
configfile.close()  

