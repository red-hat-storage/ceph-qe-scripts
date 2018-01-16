# Script to execute various rbd delayed deletion tests
#  Test Description:
#   a) Test the workitem CEPH 11390
#   b) Test the workitem CEPH 11394
#   c) Test the workitem CEPH 11407
#  Success: exit code: 0
#  Failure: Failed commands (those which are not expected to fail) with Error code in output and Non Zero Exit

import subprocess
import json
import datetime
from time import sleep
from subprocess import Popen, PIPE

# Variables and List
START = datetime.datetime.now()
CLUSTER_NAME = 'ceph'
POOL_NAME = 'test_rbd_pool'
F_COUNT = 0
failed_commands = []


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
        if process.returncode == 0:
            return 0
        else:
            F_COUNT += 1
            print 'Command Failed'
            raise CmdError(process.returncode)
    except CmdError as e:
        failed_commands.append(['Command : ' + command, ', Error Code : ' + str(e.value)])


def delete_trash_image(imageid):
    return cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'rm', '{}/'.format(POOL_NAME) + imageid])


if __name__ == "__main__":
    cmd(['ceph', 'osd', '--cluster', '{}'.format(CLUSTER_NAME), 'pool', 'delete', '{}'.format(POOL_NAME),
         '{}'.format(POOL_NAME), '--yes-i-really-really-mean-it'])

    cmd(['ceph', 'osd', '--cluster', '{}'.format(CLUSTER_NAME), 'pool', 'create', '{}'.format(POOL_NAME), '100', '100'])

    for _ in range(1, 3):
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'create', '-s', '1G',
             '{}/'.format(POOL_NAME) + 'testimg' + str(_)])
        cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'bench', '--io-type', 'write',
             '{}/'.format(POOL_NAME) + 'testimg' + str(_)])
        sleep(5)

    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'mv', '{}/'.format(POOL_NAME) + 'testimg1'])
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'mv', '--delay', '300',
         '{}/'.format(POOL_NAME) + 'testimg2'])
    endTime = datetime.datetime.now() + datetime.timedelta(minutes=5)

    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'ls', '{}'.format(POOL_NAME)])

    cmd_output = subprocess.check_output(
        ['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'ls', '{}'.format(POOL_NAME),
         '--format=json'])
    json_output = json.loads(cmd_output)

    if json_output[1] == 'testimg1' and json_output[3] == 'testimg2':
        print 'Verified: Images are in trash'

    else:
        print 'Verification failed: Images are not in trash'

    while datetime.datetime.now() < endTime:
        is_del = delete_trash_image(json_output[2])
        if is_del == 0:
            break
        else:
            F_COUNT -= 1
            del failed_commands[-1]
        sleep(30)

    delete_trash_image(json_output[2])

    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'trash', 'restore', '{}/'.format(POOL_NAME) + json_output[0]])
    cmd(['rbd', '--cluster', '{}'.format(CLUSTER_NAME), 'bench', '--io-type', 'write',
         '{}/'.format(POOL_NAME) + 'testimg1'])

    print 'Execution time for the script : ' + str(datetime.datetime.now() - START)

    if F_COUNT == 0:
        print '********** TEST PASSED **********'
        exit(0)
    else:
        print '********** TEST FAILED **********'
        print 'FAILED COMMANDS:'
        for values in failed_commands:
            print values[0], values[1]
        exit(1)
