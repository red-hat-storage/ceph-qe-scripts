import subprocess
import json
import datetime
from time import sleep
from subprocess import Popen, PIPE

# Variables

START = datetime.datetime.now()
ITERATOR = 0
ITERATOR2 = 0
ITERATOR3 = 1
CLUSTER_NAME = "ceph"
FEATUREVAR = ' '
F_COUNT = 0
# Empty List and dictionary
failed_commands = []
parameters = {}


# Exception Class

class CmdError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# Function Executing the command

def cmd(args):
    global F_COUNT
    while ' ' in args:
        args.remove(' ')
    print '************************************************************************************************************'
    command = ' '.join(map(str, args))
    print 'Executing the command :', command

    try:
        process = Popen(args, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        print '-----Output-----'
        print stdout, stderr
        if process.returncode != 0:
            F_COUNT += 1
            raise CmdError(process.returncode)
    except CmdError as e:
        failed_commands.append(['Command : ' + command, ', Error Code : ' + str(e.value)])


pool_name = {'pool_name': {'pool1': {'arg': '-p', 'val': 'test_rbd_pool'},
                           'pool2': {'arg': '-p', 'val': 'test_rbd_pool2'}}}

image_format_parameters = {'image_format_parameters': {'null': {'arg': ' ', 'val': ' '},
                                                       'image-format 1': {'arg': '--image-format', 'val': '1'},
                                                       'image-format 2': {'arg': '--image-format', 'val': '2'}}}

image_feature_parameters = {'image_feature_parameters': {'null': {'arg': ' ', 'val': ' '},
                                                         'layering': {'arg': '--image-feature', 'val': 'layering'},
                                                         'striping': {'arg': '--image-feature', 'val': 'striping'},
                                                         'exclusive-lock': {'arg': '--image-feature',
                                                                            'val': 'exclusive-lock'},
                                                         'object-map': {'arg': '--image-feature',
                                                                        'val': 'exclusive-lock,object-map'},
                                                         'fast-diff': {'arg': '--image-feature',
                                                                       'val': 'exclusive-lock,object-map,fast-diff'},
                                                         'deep-flatten': {'arg': '--image-feature',
                                                                          'val': 'deep-flatten'},
                                                         'journaling': {'arg': '--image-feature',
                                                                        'val': 'exclusive-lock,journaling'}}}

image_feature_disable_parameters = ['layering', 'striping', 'fast-diff', 'object-map', 'deep-flatten', 'journaling', 'exclusive-lock']

image_feature_enable_parameters = list(reversed(image_feature_disable_parameters))

image_shared_parameters = {'image_shared_parameters': {'image-shared': {'arg': '--image-shared', 'val': ' '}}}

image_size_parameters = {'image_size_parameters': {'size_MB': {'arg': '-s', 'val': '100M'},
                                                   'size_GB': {'arg': '-s', 'val': '10G'},
                                                   'size_TB': {'arg': '-s', 'val': '1T'}}}

image_resize_parameters = {'image_resize_parameters': {'expand_size_TB': {'arg': '-s', 'val': '2T'},
                                                       'shrink_size_GB': {'arg': '-s 512G', 'val': '--allow-shrink'},
                                                       'shrink_size_MB': {'arg': '-s 1536M', 'val': '--allow-shrink'}}}

object_size_parameters = {'object_size_parameters': {'null':{'arg': ' ', 'val': ' '},
                                                     'size_B': {'arg': '--object-size', 'val': '8192B'},
                                                     'size_KB': {'arg': '--object-size', 'val': '256K'},
                                                     'size_MB': {'arg': '--object-size', 'val': '32M'}}}

stripe_parameters_2 = {'stripe_parameters': {'null': {'stripe-unit': {'arg': ' ', 'val': ' '}, 'stripe-count': {'arg': ' ', 'val': ' '}},
                                             'size_B': {'stripe-unit': {'arg': '--stripe-unit', 'val': '2048'}, 'stripe-count': {'arg': '--stripe-count', 'val': '16'}},
                                             'size_KB': {'stripe-unit': {'arg': '--stripe-unit', 'val': '65536'}, 'stripe-count': {'arg': '--stripe-count', 'val': '16'}},
                                             'size_MB': {'stripe-unit': {'arg': '--stripe-unit', 'val': '16777216'}, 'stripe-count': {'arg': '--stripe-count', 'val': '16'}}}}

stripe_parameters_3 = {'stripe_parameters': {'null':{'stripe-unit': {'arg': ' ', 'val': ' '}, 'stripe-count': {'arg': ' ', 'val': ' '}},
                                             'size_B': {'stripe-unit': {'arg': '--stripe-unit', 'val': '2048B'}, 'stripe-count': {'arg': '--stripe-count', 'val': '16'}},
                                             'size_KB': {'stripe-unit': {'arg': '--stripe-unit', 'val': '64K'}, 'stripe-count': {'arg': '--stripe-count', 'val': '16'}},
                                             'size_MB': {'stripe-unit': {'arg': '--stripe-unit', 'val': '16M'}, 'stripe-count': {'arg': '--stripe-count', 'val': '16'}}}}

io_type_parameters_2 = {'io_type_parameters': {'write': {'arg': ' ', 'val': 'write'}}}

io_type_parameters_3 = {'io_type_parameters': {'read': {'arg': '--io-type', 'val': 'read'},
                                               'write': {'arg': '--io-type', 'val': 'write'}}}

io_size_parameters = {'io_size_parameters': {'null': {'arg': ' ', 'val': ' '},
                                             'size_KB': {'arg': '--io-size', 'val': '256K'}}}

io_threads_parameters = {'io_threads_parameters': {'null':{'arg': ' ', 'val': ' '},
                                                   'num1':{'arg': '--io-threads', 'val': '20'}}}

io_total_parameters = {'io_total_parameters': {'size_MB': {'arg': '--io-total', 'val': '50M'}}}

io_pattern_parameters = {'io_pattern_parameters': {'null':{'arg': ' ', 'val': ' '},
                                                   'pattern_seq': {'arg': '--io-pattern', 'val': 'seq'},
                                                   'pattern_rand': {'arg': '--io-pattern', 'val': 'rand'}}}

limit_parameters = {'limit_parameters': {'arg': '--limit', 'val': '10'}}

parameters.update(pool_name)
parameters.update(image_format_parameters)
parameters.update(image_feature_parameters)
parameters.update(image_size_parameters)
parameters.update(image_resize_parameters)
parameters.update(object_size_parameters)
parameters.update(io_size_parameters)
parameters.update(io_threads_parameters)
parameters.update(io_total_parameters)
parameters.update(io_pattern_parameters)
parameters.update(image_shared_parameters)

ceph_version = subprocess.check_output(['ceph', '--cluster', '{}'.format(CLUSTER_NAME), '-v'])
if "version 10" in ceph_version:
    parameters.update(stripe_parameters_2)
    parameters.update(io_type_parameters_2)
elif "version 12" in ceph_version:
    parameters.update(stripe_parameters_3)
    parameters.update(io_type_parameters_3)
    parameters.update(limit_parameters)

# Deletion Of existing Test Pools
for _, v in parameters['pool_name'].iteritems():
    cmd(['ceph', 'osd', '--cluster', '{}'.format(CLUSTER_NAME), 'pool', 'delete', v['val'], v['val'],
         '--yes-i-really-really-mean-it'])


# Pool Creation
timer = datetime.datetime.now()
cmd(['ceph', 'osd', '--cluster', '{}'.format(CLUSTER_NAME), 'pool', 'create', parameters['pool_name']['pool1']['val'], '128', '128'])
cmd(['ceph', 'osd', '--cluster', '{}'.format(CLUSTER_NAME), 'pool', 'create', parameters['pool_name']['pool2']['val'], '128', '128'])
print "Execution time for Pool Creation : " + str(datetime.datetime.now() - timer)

# Simple Image Creation
timer = datetime.datetime.now()
for k, v in parameters['image_format_parameters'].iteritems():
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'create', parameters['image_size_parameters']['size_GB']['arg'],
         parameters['image_size_parameters']['size_GB']['val'], v['arg'], v['val'], parameters['pool_name']['pool1']['arg'],
         parameters['pool_name']['pool1']['val'], 'testimg'+str(ITERATOR)])
    ITERATOR += 1
print "Execution time for Image Creation : " + str(datetime.datetime.now() - timer)

# Image Creation With Options
timer = datetime.datetime.now()
for k1, v1 in parameters['image_size_parameters'].iteritems():
    for k2, v2 in parameters['object_size_parameters'].iteritems():
        for k3, v3 in parameters['stripe_parameters'].iteritems():
            for k4, v4 in parameters['image_feature_parameters'].iteritems():
                if ' ' in v3['stripe-unit']['arg']:
                    if 'striping' in k4:
                        continue

                if k2 != k3:
                    continue

                else:
                    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'create',
                         v1['arg'], v1['val'], v2['arg'], v2['val'], v3['stripe-unit']['arg'],v3['stripe-unit']['val'],
                         v3['stripe-count']['arg'], v3['stripe-count']['val'],
                         v4['arg'], v4['val'], parameters['pool_name']['pool1']['val']+'/'+'testimg'+str(ITERATOR)])
                    ITERATOR += 1
print "Execution time for Image Creation with various options : " + str(datetime.datetime.now() - timer)

# Feature Disable & Enable and Object-map rebuild
timer = datetime.datetime.now()
for _ in range(0, 2):
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'create', '-s', '10G', '--object-size', '32M', '--stripe-unit', '16777216',
         '--stripe-count', '16', '--image-feature', 'layering,striping,exclusive-lock,object-map,fast-diff,deep-flatten,journaling',
         parameters['pool_name']['pool1']['val']+'/'+'testimg'+str(ITERATOR)])
    ITERATOR += 1

ITERATOR -= 1
for k in image_feature_disable_parameters:
    if 'layering' not in k and 'striping' not in k:
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'feature', 'disable',
             parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), k])

for k in image_feature_enable_parameters:
    if 'deep-flatten' not in k and 'layering' not in k and 'striping' not in k:
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME),'feature', 'enable',
             parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), k])
        if str(k) == 'fast-diff' or str(k) == 'object-map':
            cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'object-map', 'rebuild',
                 parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
print "Execution time for Image Features Disable and Enable : " + str(datetime.datetime.now() - timer)

# Resize
timer = datetime.datetime.now()
for k, v in parameters['image_resize_parameters'].iteritems():
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'resize', v['arg'], v['val'],
         parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
print "Execution time for Resizing Images : " + str(datetime.datetime.now() - timer)

# Images Deletion
timer = datetime.datetime.now()
for _ in range(0, 10):
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'rm',
         parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(_)])
print "Execution time for Image Deletion : " + str(datetime.datetime.now() - timer)

# Snap Creation
timer = datetime.datetime.now()
ITERATOR -= 1
for _ in range(0, 2):
    for ITERATOR2 in range(1, 4):
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'create',
             parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2)])
    ITERATOR += 1
print "Execution time for Snap Creation : " + str(datetime.datetime.now() - timer)

ITERATOR -= 1
ITERATOR2 = 1
# Copy Images and Snaps
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'cp', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR),
     parameters['pool_name']['pool2']['val'] + '/' + 'cptestimg'])

cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'cp', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2),
     parameters['pool_name']['pool2']['val'] + '/' + 'cpsnapimg'])
print "Execution time for Copying Images & Snaps : " + str(datetime.datetime.now() - timer)

# Renaming Images
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'mv', parameters['pool_name']['pool2']['val'] + '/' + 'cptestimg',
     parameters['pool_name']['pool2']['val'] + '/' + 'mvtestimg'])
print "Execution time for Renaming Images : " + str(datetime.datetime.now() - timer)

# Image-meta set
timer = datetime.datetime.now()
for num in range(0, 2):
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'image-meta', 'set', parameters['pool_name']['pool2']['val'] + '/' + 'mvtestimg', 'key'+str(num), str(num)])
print "Execution time for Setting Image-meta : " + str(datetime.datetime.now() - timer)

# Image-meta list
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'image-meta', 'list', parameters['pool_name']['pool2']['val'] + '/' + 'mvtestimg'])
print "Execution time for Listing Image-meta : " + str(datetime.datetime.now() - timer)

# Image-meta get
timer = datetime.datetime.now()
for num in range(0, 2):
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'image-meta', 'get', parameters['pool_name']['pool2']['val'] + '/' + 'mvtestimg', 'key'+str(num)])
print "Execution time for Getting Image-meta : " + str(datetime.datetime.now() - timer)

# Image-meta Removing
timer = datetime.datetime.now()
for num in range(0, 2):
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'image-meta', 'remove', parameters['pool_name']['pool2']['val'] + '/' + 'mvtestimg', 'key'+str(num)])
print "Execution time for Removing Image-meta : " + str(datetime.datetime.now() - timer)

# Listing Images and Snapshots In the Pool
timer = datetime.datetime.now()
for k, v in parameters['pool_name'].iteritems():
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'ls', '-l', parameters['pool_name'][k]['val']])
print "Execution time for Listing Images & Snaps in the pool : " + str(datetime.datetime.now() - timer)

# Listing Snap of Images
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'ls', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
print "Execution time for Listing Snaps of a Image: " + str(datetime.datetime.now() - timer)

# Bench
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'create', '-s', '10G', parameters['pool_name']['pool1']['val']+'/'+'testbench'])
for k, v in parameters['io_type_parameters'].iteritems():
    for key1, v1 in parameters['io_size_parameters'].iteritems():
        for k2, v2 in parameters['io_threads_parameters'].iteritems():
            for k3, v3 in parameters['io_total_parameters'].iteritems():
                for key4, v4 in parameters['io_pattern_parameters'].iteritems():
                    if "version 10" in ceph_version:
                        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'bench-' + v['val'],
                             v1['arg'], v1['val'], v2['arg'], v2['val'], v3['arg'], v3['val'],
                             v4['arg'], v4['val'], parameters['pool_name']['pool1']['val'] + '/' + 'testbench'])
                    elif "version 12" in ceph_version:

                        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'bench', v['arg'], v['val'],
                            v1['arg'], v1['val'], v2['arg'], v2['val'], v3['arg'], v3['val'],
                            v4['arg'], v4['val'], parameters['pool_name']['pool1']['val'] + '/' + 'testbench'])
print "Execution time for Bench : " + str(datetime.datetime.now() - timer)

# Image Rollback
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'rollback', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2)])
print "Execution time for Image Rollback : " + str(datetime.datetime.now() - timer)

# Snap Protection
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'protect', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2)])
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'protect', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR - 1) + '@' + 'snapimg' + str(ITERATOR2)])
print "Execution time for Snap Protection : " + str(datetime.datetime.now() - timer)

# Cloning
timer = datetime.datetime.now()
for k1, v1 in parameters['object_size_parameters'].iteritems():
    for k2, v2 in parameters['stripe_parameters'].iteritems():
        for k3, v3 in parameters['image_feature_parameters'].iteritems():
            for keys4, v4 in parameters['image_shared_parameters'].iteritems():
                if ' ' in v2['stripe-unit']['arg']:
                    if 'striping' in k3:
                        continue

                if k3 == 'null' or k3 == 'layering':
                    FEATUREVAR = ''

                else:
                    FEATUREVAR = 'layering,'

                if k1 != k2:
                    continue

                else:
                    if ITERATOR3 > 15 and ITERATOR3 < 17:
                        ITERATOR -= 1

                    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'clone',
                         v1['arg'], v1['val'], v2['stripe-unit']['arg'],v2['stripe-unit']['val'],
                         v2['stripe-count']['arg'], v2['stripe-count']['val'], v3['arg'], FEATUREVAR + v3['val'],
                         v4['arg'], parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2),
                         parameters['pool_name']['pool1']['val'] + '/' + 'clonetestimg' + str(ITERATOR3)])

                    ITERATOR3 += 1

print "Execution time for Cloning : " + str(datetime.datetime.now() - timer)

# Listing Clones
timer = datetime.datetime.now()
for _ in range(0, 2):
    for ITERATOR2 in range(1, 4):
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'children', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2)])
    ITERATOR += 1
print "Execution time for Listing Clones of Snaps : " + str(datetime.datetime.now() - timer)

ITERATOR -= 1
ITERATOR2 = 1
# Making child independent of the parent
# flatten image-spec
timer = datetime.datetime.now()
for _ in range(1, 16):
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'flatten', parameters['pool_name']['pool1']['val'] + '/' + 'clonetestimg' + str(_)])
print "Execution time for Flatten Images : " + str(datetime.datetime.now() - timer)

# Snap Unprotect
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'unprotect', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2)])
print "Execution time for Unprotecting snap : " + str(datetime.datetime.now() - timer)

if "version 12" in ceph_version:
    # Setting limit for number of snapshots
    timer = datetime.datetime.now()
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'limit', 'set', parameters['limit_parameters']['arg'], parameters['limit_parameters']['val'],
         parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
    print "Execution time for setting limit for number of snapshots : " + str(datetime.datetime.now() - timer)

    #Remove previous limit for number of snapshots
    timer = datetime.datetime.now()
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'limit', 'clear' , parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
    print "Execution time for Removing the limit previously set : " + str(datetime.datetime.now() - timer)

# Image or Snap Info
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'info', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'info', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2)])
print "Execution time for showing image/snap info : " + str(datetime.datetime.now() - timer)

# Disk Usage
timer = datetime.datetime.now()
#cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'du', parameters['pool_name']['pool1']['arg'], parameters['pool_name']['pool1']['val']])
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'du', parameters['pool_name']['pool2']['arg'], parameters['pool_name']['pool2']['val']])
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'du',parameters['pool_name']['pool1']['arg'], parameters['pool_name']['pool1']['val'],
     parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'du', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2)])
print "Execution time for Disk usage : " + str(datetime.datetime.now() - timer)

# Snap Deletion
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'rm', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR2)])
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'purge', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
print "Execution time for Snap deletion : " + str(datetime.datetime.now() - timer)

# Add Lock
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'lock', 'add', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), '007'])
ITERATOR -= 1

for lock_id in range(0,2):
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'lock', 'add', '--shared', 'tag', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), str(lock_id)])
print "Execution time for Adding Lock : " + str(datetime.datetime.now() - timer)

# List Lock
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'lock', 'list', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
ITERATOR += 1
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'lock', 'list', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
print "Execution time for List locked Images : " + str(datetime.datetime.now() - timer)


# Remove Lock
timer = datetime.datetime.now()
for _ in range(0, 2):
    cmd_output = subprocess.check_output(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'lock', 'list', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), '--format=json'])
    json_output = json.loads(cmd_output)
    for k, v in json_output.iteritems():
        subprocess.Popen(['rbd', 'lock', 'remove', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), k, v['locker']]).wait()
    ITERATOR -= 1
print "Execution time for Removing Lock : " + str(datetime.datetime.now() - timer)


#Mapping Images to block-device
timer = datetime.datetime.now()
ITERATOR += 3
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'create', '-s', '5G', '--image-feature', 'layering', parameters['pool_name']['pool1']['val']+'/'+'testimg'+str(ITERATOR)])
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'create', parameters['pool_name']['pool1']['val']+ '/' + 'testimg' + str(ITERATOR) + '@' + 'snapmapimg'])

cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'map', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'map', '--read-only', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapmapimg'])
print "Execution time for Mapping Images : " + str(datetime.datetime.now() - timer)


#Listing Mapped Images
timer = datetime.datetime.now()
cmd(['rbd', 'showmapped'])
print "Execution time for Listing Mapped Images : " + str(datetime.datetime.now() - timer)

#Unmapping
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'unmap', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'unmap', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapmapimg'])
print "Execution time for Unmapping Images : " + str(datetime.datetime.now() - timer)

if "version 12" in ceph_version:
    # Moving Image to trash
    timer = datetime.datetime.now()
    for _ in range(0,11):
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'mv', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
        ITERATOR -= 1
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'mv', parameters['pool_name']['pool2']['val'] + '/' + 'cpsnapimg'])
    print "Execution time for moving image to trash : " + str(datetime.datetime.now() - timer)

    # Listing trash entries
    timer = datetime.datetime.now()
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'ls', parameters['pool_name']['pool1']['val']])
    print "Execution time for listing trash entries : " + str(datetime.datetime.now() - timer)

    #  Restoring image from trash
    timer = datetime.datetime.now()
    cmd_output = subprocess.check_output(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'ls', parameters['pool_name']['pool1']['val'], '--format=json'])
    json_output = json.loads(cmd_output)
    for num in range(0, 18, 2):
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'restore', parameters['pool_name']['pool1']['val'] + '/' + json_output[num]])
    print "Execution time for restoring trash entry : " + str(datetime.datetime.now() - timer)

    #  Removing image from trash
    timer = datetime.datetime.now()
    cmd_output = subprocess.check_output(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'ls', parameters['pool_name']['pool2']['val'], '--format=json'])
    json_output = json.loads(cmd_output)
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'rm', parameters['pool_name']['pool2']['val'] + '/' + json_output[0]])
    print "Execution time for removing image from trash : " + str(datetime.datetime.now() - timer)

# Deletion Of Pools
timer = datetime.datetime.now()
for k, v in parameters['pool_name'].iteritems():
    cmd(['ceph', 'osd', '--cluster', '{}'.format(CLUSTER_NAME), 'pool', 'delete', v['val'], v['val'], '--yes-i-really-really-mean-it'])
print "Execution time for Pool Deletion : " + str(datetime.datetime.now() - timer)

print "Execution time for the script : " + str(datetime.datetime.now() - START)

if F_COUNT == 0:
    exit(0)

else:
    print 'Total Failed Commands: ', F_COUNT
    print '*******FAILED COMMANDS*******'
    for command in failed_commands:
        print command[0], command[1]
    exit(1)




