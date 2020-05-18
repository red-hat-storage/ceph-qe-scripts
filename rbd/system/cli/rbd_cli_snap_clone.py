import os
import sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import argparse
import itertools
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
    cli = parameters.CliParams(k_m=k_m, num_rep_pool=2, num_data_pool=2 if k_m else 0)

    # Simple Image Creation
    combinations = cli.generate_combinations('image_size')
    combinations = filter(lambda val: cli.search_param_val('-s', val)
                          .find('G') != -1, combinations)
    combinations = list(combinations)
    [exec_cmd('rbd create {} {} {}/img{}'
              .format(combinations[0], parameters.data_pool['arg'] + ' ' + parameters.data_pool['val']['pool0'],
                      parameters.rep_pool['val']['pool0'], iterator))
     for iterator in range(0, 2)]

    # Snap Creation
    [exec_cmd('rbd snap create {}/img{}@snapimg{}'
              .format(parameters.rep_pool['val']['pool0'], iterator, iterator2))
     for iterator, iterator2 in itertools.product(range(0, 2), range(0, 3))]

    iterator = iterator2 = 0
    # Copy Images and Snaps
    combinations = cli.generate_combinations('data_pool')
    [exec_cmd('rbd cp {}/img{}@snapimg{} {} {}/cpsnapimg{}'
              .format(parameters.rep_pool['val']['pool0'], iterator, iterator2,
                      param, parameters.rep_pool['val']['pool1'], index))
     for index, param in enumerate(combinations, start=0)]

    # Listing Images and Snapshots In the Pool
    [exec_cmd('rbd ls -l {}'.format(parameters.rep_pool['val'][key]))
     for key, val in parameters.rep_pool['val'].items()]

    # Listing Snap of Images
    exec_cmd('rbd snap ls {}/img{}'.format(parameters.rep_pool['val']['pool0'], iterator))

    # Bench-write
    exec_cmd('rbd bench-write --io-total 100M {}/img{}'
             .format(parameters.rep_pool['val']['pool0'], iterator))

    # Image Rollback
    exec_cmd('rbd snap rollback {}/img{}@snapimg{}'
             .format(parameters.rep_pool['val']['pool0'], iterator, iterator2))

    # Snap Protection
    exec_cmd('rbd snap protect {}/img{}@snapimg{}'
             .format(parameters.rep_pool['val']['pool0'], iterator, iterator2))
    exec_cmd('rbd snap protect {}/img{}@snapimg{}'
             .format(parameters.rep_pool['val']['pool0'], iterator + 1, iterator2))

    # Cloning
    iterator3 = 0
    combinations = cli.generate_combinations('object_size', 'stripe',
                                             'image_feature', 'image_shared')
    if cli.ceph_version == 2:
        invalid = [val for val in combinations
                   if (cli.search_param_val('--image-feature', val) != 0 and
                       cli.search_param_val('--image-feature', val)
                       .find('striping') != -1 and
                       cli.search_param_val('--stripe-unit', val) == 0)]
        map(lambda val: combinations.remove(val), invalid)

    combinations = filter(lambda val:
                          cli.get_byte_size(cli.search_param_val('--stripe-unit', val)) <=
                          cli.get_byte_size(cli.search_param_val('--object-size', val)),
                          combinations)
    rem_list = []
    add_list = []
    combinations = list(combinations)
    for val in combinations:
        if cli.search_param_val('--image-feature', val) != 0 and \
                cli.search_param_val('--image-feature',
                                     val).find('layering') == -1:
            index = val.find('--image-feature') + len('--image-feature')
            tmp_list = list(val)
            tmp_list[index] = ' layering,'
            rem_list.append(val)
            add_list.append(''.join(tmp_list))

        if cli.search_param_val('--image-feature', val) == 0:
            tmp_list = list(val)
            tmp_list.append(' --image-feature layering')
            rem_list.append(val)
            add_list.append(''.join(tmp_list))
 
    for val in rem_list:
        combinations.remove(val)
    for val in add_list:
        combinations.append(val)

    for iterator3, param in enumerate(combinations, start=0):
        if iterator3 == 4:
            iterator += 1
        exec_cmd('rbd clone {} {pool}/img{}@snapimg{} {} {pool}/cloneimg{}'
                 .format(param, iterator, iterator2, parameters.data_pool['arg'] +
                         ' ' + parameters.data_pool['val']['pool0'], iterator3,
                         pool=parameters.rep_pool['val']['pool0']))

    # Listing Clones
    [exec_cmd('rbd children {}/img{}@snapimg{}'
              .format(parameters.rep_pool['val']['pool0'], iterator, iterator2))
     for iterator in range(0, 2)]

    # Making child independent of the parent
    [exec_cmd('rbd flatten {}/cloneimg{}'
              .format(parameters.rep_pool['val']['pool0'],
                      iterator3)) for iterator3 in range(0, 4)]

    # Snap Unprotect
    iterator = 0
    exec_cmd('rbd snap unprotect {}/img{}@snapimg{}'
             .format(parameters.rep_pool['val']['pool0'], iterator, iterator2))

    if cli.ceph_version > 2:
        # Setting limit for number of snapshots
        combinations = cli.generate_combinations('limit')
        [exec_cmd('rbd snap limit set {} {}/img{}'
                  .format(param, parameters.rep_pool['val']['pool0'],
                          iterator)) for param in combinations]

        # Remove previous limit for number of snapshots
        exec_cmd('rbd snap limit clear {}/img{}'
                 .format(parameters.rep_pool['val']['pool0'], iterator))

    # Snap Info
    exec_cmd('rbd info {}/img{}@snapimg{}'
             .format(parameters.rep_pool['val']['pool0'], iterator, iterator2))

    # Snap Rename
    exec_cmd(
        'rbd snap rename {pool}/img{}@snapimg{} {pool}/img{}@snapimgrenamed'
        .format(iterator, iterator2, iterator, pool=parameters.rep_pool['val']['pool0']))

    # Snap Deletion
    exec_cmd('rbd snap rm {}/img{}@snapimgrenamed'
             .format(parameters.rep_pool['val']['pool0'], iterator))
    exec_cmd('rbd snap purge {}/img{}'.format(parameters.rep_pool['val']['pool0'],
                                              iterator))

    # Clean Up
    cli.rbd.clean_up(pools=parameters.rep_pool['val'])
    if k_m:
        cli.rbd.clean_up(pools=parameters.data_pool['val'], profile=cli.ec_profile)

    log.info('Result'.center(80, '-'))
    log.info('Total Commands Executed: {}'.format(PASSED_COUNT + FAILED_COUNT))
    log.info('Commands Passed: {}'.format(PASSED_COUNT))
    log.info('Commands Failed: {}'.format(FAILED_COUNT))

    if FAILED_COUNT > 0:
        [log.info(fc) for fc in FAILED_COMMANDS]
        log.info('passed')
        [log.info(fc) for fc in PASSED_COMMANDS]
        exit(1)

    exit(0)
