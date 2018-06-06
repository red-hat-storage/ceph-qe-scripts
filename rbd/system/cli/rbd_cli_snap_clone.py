import os
import sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import itertools
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
    pool_name = {'arg': '-p', 'val': {'pool1': rbd.random_string(),
                                      'pool2': rbd.random_string()}}

    # Creation Of Pools
    [exec_cmd('ceph osd pool create {} 64 64'.format(val))
     for key, val in pool_name['val'].iteritems()]
    if cli.ceph_version > 2:
        [exec_cmd('rbd pool init {} {}'.format(pool_name['arg'], val)) for key, val in pool_name['val'].iteritems()]

    # Simple Image Creation
    combinations = cli.generate_combinations('image_size')
    combinations = filter(lambda val: cli.search_param_val('-s', val)
                          .find('G') != -1, combinations)
    [exec_cmd('rbd create {} {}/img{}'
              .format(combinations[0], pool_name['val']['pool1'], iterator))
     for iterator in range(0, 2)]

    # Snap Creation
    [exec_cmd('rbd snap create {}/img{}@snapimg{}'
              .format(pool_name['val']['pool1'], iterator, iterator2))
     for iterator, iterator2 in itertools.product(range(0, 2), range(0, 3))]

    iterator = iterator2 = 0
    # Copy Images and Snaps
    exec_cmd('rbd cp {}/img{}@snapimg{} {}/cpsnapimg'
             .format(pool_name['val']['pool1'], iterator, iterator2,
                     pool_name['val']['pool2']))

    # Listing Images and Snapshots In the Pool
    [exec_cmd('rbd ls -l {}'.format(pool_name['val'][key]))
     for key, val in pool_name['val'].iteritems()]

    # Listing Snap of Images
    exec_cmd('rbd snap ls {}/img{}'.format(pool_name['val']['pool1'], iterator))

    # Bench-write
    exec_cmd('rbd bench-write --io-total 100M {}/img{}'
             .format(pool_name['val']['pool1'], iterator))

    # Image Rollback
    exec_cmd('rbd snap rollback {}/img{}@snapimg{}'
             .format(pool_name['val']['pool1'], iterator, iterator2))

    # Snap Protection
    exec_cmd('rbd snap protect {}/img{}@snapimg{}'
             .format(pool_name['val']['pool1'], iterator, iterator2))
    exec_cmd('rbd snap protect {}/img{}@snapimg{}'
             .format(pool_name['val']['pool1'], iterator + 1, iterator2))

    # Cloning
    iterator3 = 0
    combinations = cli.generate_combinations('object_size', 'stripe',
                                             'image_feature', 'image_shared')
    if cli.ceph_version == 2:
        invalid = [val for val in combinations
                   if (cli.search_param_val('--image-feature', val) != 0
                       and cli.search_param_val('--image-feature', val)
                       .find('striping') != -1
                       and cli.search_param_val('--stripe-unit', val) == 0)]
        map(lambda val: combinations.remove(val), invalid)

    combinations = filter(lambda val:
                          cli.get_byte_size(cli.search_param_val('--stripe-unit'
                                                                 , val)) <=
                          cli.get_byte_size(cli.search_param_val('--object-size'
                                                                 , val)),
                          combinations)
    rem_list = []
    add_list = []
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

    map(lambda val: combinations.remove(val), rem_list)
    map(lambda val: combinations.append(val), add_list)
    for iterator3, param in enumerate(combinations, start=0):
        if 3 < iterator3 < 5:
            iterator += 1
        exec_cmd('rbd clone {} {pool}/img{}@snapimg{} {pool}/cloneimg{}'
                 .format(param, iterator, iterator2, iterator3,
                         pool=pool_name['val']['pool1']))

    # Listing Clones
    [exec_cmd('rbd children {}/img{}@snapimg{}'
              .format(pool_name['val']['pool1'], iterator, iterator2))
     for iterator in range(0, 2)]

    # Making child independent of the parent
    [exec_cmd('rbd flatten {}/cloneimg{}'
              .format(pool_name['val']['pool1'],
                      iterator3)) for iterator3 in range(0, 4)]

    # Snap Unprotect
    iterator = 0
    exec_cmd('rbd snap unprotect {}/img{}@snapimg{}'
             .format(pool_name['val']['pool1'], iterator, iterator2))

    if cli.ceph_version > 2:
        # Setting limit for number of snapshots
        combinations = cli.generate_combinations('limit')
        [exec_cmd('rbd snap limit set {} {}/img{}'
                  .format(param, pool_name['val']['pool1'],
                          iterator)) for param in combinations]

        # Remove previous limit for number of snapshots
        exec_cmd('rbd snap limit clear {}/img{}'
                 .format(pool_name['val']['pool1'], iterator))

    # Snap Info
    exec_cmd('rbd info {}/img{}@snapimg{}'
             .format(pool_name['val']['pool1'], iterator, iterator2))

    # Snap Rename
    exec_cmd(
        'rbd snap rename {pool}/img{}@snapimg{} {pool}/img{}@snapimgrenamed'
        .format(iterator, iterator2, iterator, pool=pool_name['val']['pool1']))

    # Snap Deletion
    exec_cmd('rbd snap rm {}/img{}@snapimgrenamed'
             .format(pool_name['val']['pool1'], iterator))
    exec_cmd('rbd snap purge {}/img{}'.format(pool_name['val']['pool1'],
                                              iterator))

    # Deletion Of Pools
    [exec_cmd('ceph osd pool delete {pool} {pool} --yes-i-really-really-mean-it'
              .format(pool=val)) for key, val in pool_name['val'].iteritems()]

    log.info('Result'.center(80, '-'))
    log.info('Total Commands Executed: {}'.format(PASSED_COUNT + FAILED_COUNT))
    log.info('Commands Passed: {}'.format(PASSED_COUNT))
    log.info('Commands Failed: {}'.format(FAILED_COUNT))

    if FAILED_COUNT > 0:
        [log.info(fc) for fc in FAILED_COMMANDS]
        exit(1)

    exit(0)
