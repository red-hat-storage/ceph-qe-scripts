# Owner: Shilpa
# Email: smanjara@redhat.com
# Script to configure Swift-storage-policy
# This script assumes that ceph cluster is already set up. 
# The script also assumes that a new pool called ".rgw.buckets.special" is already created on the Ceph cluster with required settings. See https://www.smanjara.in/swift-storage-policies-for-ceph-rados-gateway/ for more details on Swift Storage Policies.
#  Test Description:
#   a) Open the region and zone config files and read the contents
#   b) Edit both the files to add new placement rules and update the files.
#  Success: exit code: 0
#  Failure: Non Zero Exit or ERROR message in output

import json
import os
 
#Get region and zone files and save them
os.system("radosgw-admin region get > ~/region.json")
os.system("radosgw-admin zone get > ~/zone.json")

#Edit the region file to add the new placement target and update it.
with open('/root/region.json', 'r+') as region_file:
     region_data = json.load(region_file)
     placement_targets = region_data['placement_targets']
     placement =  {'name': 'custom-placement', 'tags': '[]'}
     placement_targets.append(dict(placement))
     region_file.seek(0,0)
     region_file.write(json.dumps(region_data, region_file, indent = 4))
     region_file.truncate()
os.system("radosgw-admin region set < ~/region.json")
print "\n\033[1;34m*Region file updated succesfully*\033[1;m\n"


#Edit the zone file to add the new placement rules and update it
with open('/root/zone.json', 'r+') as zone_file:
     zone_data = json.load(zone_file)
     placement_pools = zone_data['placement_pools']
     placement = {'key': 'custom-placement', 'val': {'index_pool': '.rgw.buckets.index', 'data_pool': '.rgw.buckets.special', 'data_extra_pool': '.rgw.buckets.extra'}}
     placement_pools.append(dict(placement))
     zone_file.seek(0,0)
     zone_file.write(json.dumps(zone_data, zone_file, indent = 4))
     zone_file.truncate()
os.system("radosgw-admin zone set < ~/zone.json")
print "\n\033[1;34m*Zone file updated successfully*\033[1;m\n"

#Update the regionmap
print "\033[1;34m*Showing updated regionmap*\033[1;m"
os.system("radosgw-admin regionmap update")

