import subprocess
import datetime
from subprocess import Popen, PIPE

# Variables
START = datetime.datetime.now()
ITERATOR = 0
ITERATOR2 = 0
ITERATOR3 = 0
PATH = "/path"
PATH2 = "/path2"
PATH3 = "/path3"
CLUSTER_NAME = "ceph"
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


# Directories Creation
def create_dir():
    for dir_path in [PATH, PATH2, PATH3]:
        cmd(['mkdir', '{}'.format(dir_path)])


# Directories deletion
def delete_dir():
    for dir_path in [PATH, PATH2, PATH3]:
        cmd(['rm', '-rf', '{}'.format(dir_path)])


pool_name = {'pool_name': {'pool1': {'arg': '-p', 'val': 'test_rbd_pool'}}}

image_format_parameters = {'image_format_parameters': {'image-format 1': {'arg': '--image-format', 'val': '1'},
                                                       'image-format 2': {'arg': '--image-format', 'val': '2'}}}

export_format_parameters_2 = {'export_format_parameters': {'null': {'arg': ' ', 'val': ' '}}}

export_format_parameters_3 = {'export_format_parameters': {'null': {'arg': ' ', 'val': ' '},
                                                           'export-format 1': {'arg': '--export-format', 'val': '1'},
                                                           'export-format 2': {'arg': '--export-format', 'val': '2'}}}

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

image_size_parameters = {'image_size_parameters': {'size_GB': {'arg': '-s', 'val': '1G'}}}

image_shared_parameters = {'image_shared_parameters': {'null': {'arg': ' ', 'val': ' '},
                                                       'image-shared': {'arg': '--image-shared', 'val': ' '}}}

whole_object_parameters = {'whole_object_parameters': {'null': {'arg': ' ', 'val': ' '},
                                                       'whole-object': {'arg': '--whole-object', 'val': ' '}}}

object_size_parameters = {'object_size_parameters': {'null': {'arg': ' ', 'val': ' '},
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


parameters.update(pool_name)
parameters.update(image_format_parameters)
parameters.update(image_size_parameters)
parameters.update(image_feature_parameters)
parameters.update(object_size_parameters)
parameters.update(image_shared_parameters)
parameters.update(whole_object_parameters)

ceph_version = subprocess.check_output(['ceph', '--cluster', '{}'.format(CLUSTER_NAME), '-v'])
if "version 10" in ceph_version:
    parameters.update(stripe_parameters_2)
    parameters.update(export_format_parameters_2)
elif "version 12" in ceph_version:
    parameters.update(stripe_parameters_3)
    parameters.update(export_format_parameters_3)

# Deletion of existing Test Pool
cmd(['ceph', 'osd', '--cluster', '{}'.format(CLUSTER_NAME), 'pool', 'delete', parameters['pool_name']['pool1']['val'], parameters['pool_name']['pool1']['val'],
     '--yes-i-really-really-mean-it'])

# Deletion of existing directories
delete_dir()

# Pool Creation
timer = datetime.datetime.now()
cmd(['ceph', 'osd', '--cluster', '{}'.format(CLUSTER_NAME), 'pool', 'create', parameters['pool_name']['pool1']['val'], '128', '128'])
print "Execution time for Pool Creation : " + str(datetime.datetime.now() - timer)

# Simple Image Creation
timer = datetime.datetime.now()
for _, v in parameters['image_format_parameters'].iteritems():
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'create', parameters['image_size_parameters']['size_GB']['arg'],
         parameters['image_size_parameters']['size_GB']['val'], v['arg'], v['val'], parameters['pool_name']['pool1']['val'] + '/' + 'testimg'+str(ITERATOR)])
    ITERATOR += 1
print "Execution time for Image Creation : " + str(datetime.datetime.now() - timer)

# Snap Creation
timer = datetime.datetime.now()
for ITERATOR in range(0, 2):
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'snap', 'create', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR)])
print "Execution time for Snap Creation : " + str(datetime.datetime.now() - timer)

# Creation of directories
create_dir()

# Export
timer = datetime.datetime.now()
for _, v in parameters['export_format_parameters'].iteritems():
    for ITERATOR in range(0, 2):
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'export', v['arg'], v['val'], parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), '{}/'.format(PATH) +
             'testimg' + str(ITERATOR)])
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'export', v['arg'], v['val'], parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR), '{}/'.format(PATH) +
             'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR)])

        if "version 12" in ceph_version and ITERATOR2 < 2:
            cmd(['rm', '{}/'.format(PATH) + 'testimg' + str(ITERATOR)])
            cmd(['rm', '{}/'.format(PATH) + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR)])
    ITERATOR2 += 1
print "Execution time for Export : " + str(datetime.datetime.now() - timer)

# Import
timer = datetime.datetime.now()
for _, v in parameters['export_format_parameters'].iteritems():
    for k1, v1 in parameters['image_format_parameters'].iteritems():
        for k2, v2 in parameters['object_size_parameters'].iteritems():
            for k3, v3 in parameters['stripe_parameters'].iteritems():
                for k4, v4 in parameters['image_feature_parameters'].iteritems():
                    for k5, v5 in parameters['image_shared_parameters'].iteritems():
                        if 'image-format 1' in k1:
                            continue

                        if ' ' in v3['stripe-unit']['arg']:
                            if 'striping' in k4:
                                continue

                        if k2 != k3:
                            continue

                        else:
                            cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'import', v['arg'], v['val'],
                                 v1['arg'], v1['val'], v2['arg'], v2['val'], v3['stripe-unit']['arg'],v3['stripe-unit']['val'],
                                 v3['stripe-count']['arg'], v3['stripe-count']['val'],
                                 v4['arg'], v4['val'], v5['arg'], '{}/'.format(PATH) + 'testimg' + str(ITERATOR), parameters['pool_name']['pool1']['val']+'/'+'testimgimport'+str(ITERATOR3)])
                            ITERATOR3 += 1
print "Execution time for Import : " + str(datetime.datetime.now() - timer)

# Export-diff
timer = datetime.datetime.now()

ITERATOR = 0
ITERATOR2 = 0
for _, v in parameters['whole_object_parameters'].iteritems():
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'export-diff', v['arg'], parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), '{}/'.format(PATH2) + 'testimg' + str(ITERATOR)])
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'export-diff', '--from-snap', 'snapimg' + str(ITERATOR), v['arg'], parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), '{}/'.format(PATH3) + 'testimg' + str(ITERATOR)])
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'export-diff', v['arg'],
         parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR), '{}/'.format(PATH2) +
         'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR)])
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'export-diff', '--from-snap', 'snapimg' + str(ITERATOR),
         v['arg'], parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR), '{}/'.format(PATH3) +
         'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR)])

    if ITERATOR2 == 0:
        for path in [PATH2, PATH3]:
            cmd(['rm', '{}/'.format(path) + 'testimg' + str(ITERATOR)])
            cmd(['rm', '{}/'.format(path) + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(ITERATOR)])
    ITERATOR2 += 1
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'export-diff', parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR), '{}/'.format(PATH2) + 'testimgex' + str(ITERATOR)])
print "Execution time for Export-diff : " + str(datetime.datetime.now() - timer)

# Merge-diff
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'merge-diff', '{}/'.format(PATH2) + 'testimg' + str(ITERATOR), '{}/'.format(PATH2) + 'testimgex' + str(ITERATOR), '{}/'.format(PATH) + 'merge-diff-img' + str(ITERATOR)])
print "Execution time for Merge-diff : " + str(datetime.datetime.now() - timer)

# Import-diff
timer = datetime.datetime.now()
cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'import-diff', '{}/'.format(PATH2) +
         'testimg' + str(ITERATOR), parameters['pool_name']['pool1']['val']+'/'+'testimg'+str(ITERATOR)])
print "Execution time for Import-diff : " + str(datetime.datetime.now() - timer)

# diff
timer = datetime.datetime.now()
for _, v in parameters['whole_object_parameters'].iteritems():
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'diff', v['arg'],
         parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'diff', '--from-snap', 'snapimg' + str(ITERATOR),
         v['arg'], parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR)])
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'diff', v['arg'],
         parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(
             ITERATOR)])
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'diff', '--from-snap', 'snapimg' + str(ITERATOR),
         v['arg'], parameters['pool_name']['pool1']['val'] + '/' + 'testimg' + str(ITERATOR) + '@' + 'snapimg' + str(
            ITERATOR)])
print "Execution time for diff : " + str(datetime.datetime.now() - timer)

# CleanUp
timer = datetime.datetime.now()
delete_dir()
cmd(['ceph', 'osd', '--cluster', '{}'.format(CLUSTER_NAME), 'pool', 'delete', parameters['pool_name']['pool1']['val'], parameters['pool_name']['pool1']['val'], '--yes-i-really-really-mean-it'])
print "Execution time for CleanUp : " + str(datetime.datetime.now() - timer)

print "Execution time for the script : " + str(datetime.datetime.now() - START)


if F_COUNT == 0:
    exit(0)

else:
    print 'Toatal Failed Commands: ', F_COUNT
    print '*******FAILED COMMANDS*******'
    for value in failed_commands:
        print value[0], value[1]
    exit(1)
