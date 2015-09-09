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

# Read the nova config file
cfg = ConfigParser.ConfigParser()
cfg.read('/etc/nova/nova.conf')

# Add the following lines to section "libvirt". This configures nova to use ceph as backend driver
cfg.set('libvirt', 'images_type', 'rbd')
cfg.set('libvirt', 'images_rbd_pool', 'vms')
cfg.set('libvirt', 'images_rbd_ceph_conf', '/etc/ceph/ceph.conf')
cfg.set('libvirt', 'rbd_user', 'cinder')
cfg.set('libvirt', 'rbd_secret_uuid', '457eb676-33da-42ec-9a8c-9293d545c337')
cfg.set('libvirt', 'disk_cachemodes', '"network=writeback"')
cfg.set('libvirt', 'inject_password', 'false')
cfg.set('libvirt', 'inject_key', 'false')
cfg.set('libvirt', 'inject_partition', '-2')
cfg.set('libvirt', 'live_migration_flag', 'VIR_MIGRATE_UNDEFINE_SOURCE,VIR_MIGRATE_PEER2PEER,VIR_MIGRATE_LIVE,VIR_MIGRATE_PERSIST_DEST')
  
# Write to the config file and close. 
with open('/etc/nova/nova.conf', 'a') as configfile:
     cfg.write(configfile)
configfile.close()    
