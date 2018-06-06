import os
import sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import json
import parameters
import utils.log as log
import utils.utils as rbd

FAILED_COUNT = 0
PASSED_COUNT = 0
FAILED_COMMANDS = []


def exec_cmd(args):
    rc = rbd.exec_cmd(args)
    if rc is False:
        globals()['FAILED_COUNT'] += 1
        FAILED_COMMANDS.append(args)
    else:
        globals()['PASSED_COUNT'] += 1
    return rc


if __name__ == "__main__":

    cli = parameters.CliParams()
    pool_name = {'arg': '-p', 'val': rbd.random_string()}

    # Creation Of Pool
    exec_cmd('ceph osd pool create {} 64 64'.format(pool_name['val']))
    if cli.ceph_version > 2:
        exec_cmd('rbd pool init {} {}'.format(pool_name['arg'], pool_name['val']))

    # Simple Image Creation
    combinations = cli.generate_combinations('image_size')
    combinations = filter(lambda val: cli.search_param_val('-s', val)
                          .find('G') != -1,
                          combinations)
    [exec_cmd('rbd create {} {}/img{}'.format(combinations[0],
                                              pool_name['val'], iterator))
     for iterator in range(0, 2)]

    # Bench
    combinations = cli.generate_combinations('io_type', 'io_size', 'io_threads',
                                             'io_total', 'io_pattern')
    if cli.ceph_version == 2:
        [exec_cmd('rbd bench-{} {}/img{}'
                  .format(param, pool_name['val'], iterator))
         for param in combinations]
    else:
        [exec_cmd('rbd bench {} {}/img{}'
                  .format(param, pool_name['val'], iterator))
         for param in combinations]

    # Snap Creation
    exec_cmd('rbd snap create {}/img{}@snapimg'
             .format(pool_name['val'], iterator))

    # Disk Usage
    exec_cmd('rbd du {} {}'.format(pool_name['arg'], pool_name['val']))
    exec_cmd('rbd du {}/img{}'.format(pool_name['val'], iterator))
    exec_cmd('rbd du {}/img{}@snapimg'.format(pool_name['val'], iterator))

    # Add Lock
    exec_cmd('rbd lock add {}/img{} 007'.format(pool_name['val'], iterator))

    [exec_cmd('rbd lock add --shared tag {}/img{} {}'
              .format(pool_name['val'], iterator - 1, lock_id))
     for lock_id in range(0, 2)]

    # List Lock
    [exec_cmd('rbd lock list {}/img{}'.format(pool_name['val'], iterator))
     for iterator in range(0, 2)]

    # Remove Lock
    for iterator in range(0, 2):
        if exec_cmd('rbd lock list {}/img{} --format=json'
                    .format(pool_name['val'], iterator)):
            json_output = json.loads(
                exec_cmd('rbd lock list {}/img{} --format=json'
                         .format(pool_name['val'], iterator)))
            [exec_cmd('rbd lock remove {}/img{} {} {}'.
             format(pool_name['val'], iterator, key, val['locker']))
             for key, val in json_output.iteritems()]

    # Mapping Images to block-device
    iterator += 1
    if 'ubuntu' in exec_cmd('lsb_release -is').lower():
        exec_cmd('ceph osd crush tunables hammer')
    exec_cmd('rbd create -s 5G --image-feature layering {}/img{}'
             .format(pool_name['val'], iterator))
    exec_cmd('rbd snap create {}/img{}@snapmapimg'
             .format(pool_name['val'], iterator))
    exec_cmd('rbd map {}/img{}'.format(pool_name['val'], iterator))
    exec_cmd('rbd map --read-only {}/img{}@snapmapimg'
             .format(pool_name['val'], iterator))

    # Listing Mapped Images
    exec_cmd('rbd showmapped')

    # Unmap Images
    exec_cmd('rbd unmap {}/img{}'.format(pool_name['val'], iterator))
    exec_cmd('rbd unmap {}/img{}@snapmapimg'.format(pool_name['val'], iterator))

    # Deletion Of Pool
    exec_cmd('ceph osd pool delete {pool} {pool} --yes-i-really-really-mean-it'
             .format(pool=pool_name['val']))

    log.info('Result'.center(80, '-'))
    log.info('Total Commands Executed: {}'.format(PASSED_COUNT + FAILED_COUNT))
    log.info('Commands Passed: {}'.format(PASSED_COUNT))
    log.info('Commands Failed: {}'.format(FAILED_COUNT))

    if FAILED_COUNT > 0:
        [log.info(fc) for fc in FAILED_COMMANDS]
        exit(1)

    exit(0)
