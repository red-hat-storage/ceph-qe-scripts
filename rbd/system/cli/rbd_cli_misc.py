import os
import sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import argparse
import json
import parameters
import utils.log as log

FAILED_COUNT = 0
PASSED_COUNT = 0
FAILED_COMMANDS = []
PASSED_COMMANDS = []

def exec_cmd(args):
    rc = cli.rbd.exec_cmd(args)
    if rc is False:
        globals()['FAILED_COUNT'] += 1
        FAILED_COMMANDS.append(args)
    else:
        globals()['PASSED_COUNT'] += 1
        PASSED_COMMANDS.append(args)
    return rc


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='RBD CLI Test')
    parser.add_argument('-e', '--ec-pool-k-m', required=False)
    args = parser.parse_args()
    k_m = args.ec_pool_k_m
    cli = parameters.CliParams(k_m=k_m, num_rep_pool=1, num_data_pool=1 if k_m else 0)
    iterator = 0

    # Simple Image Creation
    combinations = cli.generate_combinations('image_size')
    combinations = list(filter(lambda val: cli.search_param_val('-s', val)
                          .find('G') != -1,
                          combinations))
    [exec_cmd('rbd create {} {} {}/img{}'.format(combinations[0], parameters.data_pool['arg'] +
                                                 ' ' + parameters.data_pool['val']['pool0'],
                                                 parameters.rep_pool['val']['pool0'], iterator))
     for iterator in range(0, 2)]

    # Bench
    combinations = cli.generate_combinations('io_type', 'io_size', 'io_threads',
                                             'io_total', 'io_pattern')
    if cli.ceph_version == 2:
        [exec_cmd('rbd bench-{} {}/img{}'
                  .format(param, parameters.rep_pool['val']['pool0'], iterator))
         for param in combinations]
    else:
        [exec_cmd('rbd bench {} {}/img{}'
                  .format(param, parameters.rep_pool['val']['pool0'], iterator))
         for param in combinations]

    # Snap Creation
    iterator = 0
    exec_cmd('rbd snap create {}/img{}@snapimg'
             .format(parameters.rep_pool['val']['pool0'], iterator))

    # Disk Usage
    exec_cmd('rbd du {} {}'.format(parameters.rep_pool['arg'], parameters.rep_pool['val']['pool0']))
    exec_cmd('rbd du {}/img{}'.format(parameters.rep_pool['val']['pool0'], iterator))
    exec_cmd('rbd du {}/img{}@snapimg'.format(parameters.rep_pool['val']['pool0'], iterator))

    # Add Lock
    exec_cmd('rbd lock add {}/img{} 007'.format(parameters.rep_pool['val']['pool0'], iterator))

    [exec_cmd('rbd lock add --shared lock-tag {}/img{} {}'
              .format(parameters.rep_pool['val']['pool0'], iterator + 1, lock_id))
     for lock_id in range(0, 2)]

    # List Lock
    [exec_cmd('rbd lock list {}/img{}'.format(parameters.rep_pool['val']['pool0'], iterator))
     for iterator in range(0, 2)]

    # Remove Lock
    for iterator in range(0, 2):
        if exec_cmd('rbd lock list {}/img{} --format=json'
                    .format(parameters.rep_pool['val']['pool0'], iterator)):
            json_output = json.loads(
                exec_cmd('rbd lock list {}/img{} --format=json'
                         .format(parameters.rep_pool['val']['pool0'], iterator)))
            if cli.ceph_version == 3:
                [exec_cmd('rbd lock remove {}/img{} {} {}'
                          .format(parameters.rep_pool['val']['pool0'], iterator, key, val['locker']))
                 for key, val in json_output.items()]
            else:
                [exec_cmd('rbd lock remove {}/img{} {} {}'
                          .format(parameters.rep_pool['val']['pool0'], iterator, lock['id'], lock['locker']))
                 for lock in json_output]

    # Mapping Images to block-device
    iterator += 1
    if 'ubuntu' in exec_cmd('lsb_release -is').lower():
        exec_cmd('ceph osd crush tunables hammer')
    exec_cmd('rbd create -s 5G --image-feature layering {}/img{}'
             .format(parameters.rep_pool['val']['pool0'], iterator))
    exec_cmd('rbd snap create {}/img{}@snapmapimg'
             .format(parameters.rep_pool['val']['pool0'], iterator))
    exec_cmd('rbd map {}/img{}'.format(parameters.rep_pool['val']['pool0'], iterator))
    exec_cmd('rbd map --read-only {}/img{}@snapmapimg'
             .format(parameters.rep_pool['val']['pool0'], iterator))

    # Listing Mapped Images
    exec_cmd('rbd showmapped')

    # Unmap Images
    exec_cmd('rbd unmap {}/img{}'.format(parameters.rep_pool['val']['pool0'], iterator))
    exec_cmd('rbd unmap {}/img{}@snapmapimg'.format(parameters.rep_pool['val']['pool0'], iterator))

    # Clean Up
    cli.rbd.clean_up(pools=parameters.rep_pool['val'])
    if k_m:
        cli.rbd.clean_up(pools=parameters.data_pool['val'], profile=cli.ec_profile)

    log.info('Result'.center(80, '-'))
    log.info('Total Commands Executed: {}'.format(PASSED_COUNT + FAILED_COUNT))
    log.info('Commands Passed: {}'.format(PASSED_COUNT))
    log.info('Commands Failed: {}'.format(FAILED_COUNT))

    if FAILED_COUNT > 0:
        log.info('Failed commands')
        [log.info(fc) for fc in FAILED_COMMANDS]
        log.info('Passed commands')
        [log.info(fc) for fc in PASSED_COMMANDS]
        exit(1)

    exit(0)
