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
    pool_name = {'arg': '-p', 'val': {'pool1': rbd.random_string(),
                                      'pool2': rbd.random_string()}}
    image_feature = ['layering', 'striping', 'fast-diff', 'object-map',
                     'deep-flatten', 'journaling', 'exclusive-lock']

    # Creation Of Pools
    [exec_cmd('ceph osd pool create {} 64 64'
              .format(val)) for key, val in pool_name['val'].iteritems()]
    if cli.ceph_version > 2:
        [exec_cmd('rbd pool init {} {}'.format(pool_name['arg'], val)) for key, val in pool_name['val'].iteritems()]

    # Simple Image Creation
    combinations = cli.generate_combinations('image_size', 'image_format')
    combinations = filter(lambda val: cli.search_param_val('-s', val)
                          .find('M') != -1, combinations)
    [exec_cmd('rbd create {} {}/img{}'.format(param, pool_name['val']['pool1'],
                                              iterator))
     for iterator, param in enumerate(combinations, start=0)]

    # Image Creation With Options
    combinations = cli.generate_combinations('image_size', 'object_size',
                                             'stripe', 'image_feature',
                                             'image_shared')

    if cli.ceph_version == 2:
        invalid = [val for val in combinations if
                   (cli.search_param_val('--image-feature', val) != 0
                    and cli.search_param_val('--image-feature',
                                             val).find('striping') != -1
                    and cli.search_param_val('--stripe-unit', val) == 0)]
        map(lambda val: combinations.remove(val), invalid)

    combinations = filter(
        lambda val: cli.search_param_val('--stripe-unit', val) == 0 or (
                cli.get_byte_size(cli.search_param_val('--stripe-unit', val)) <=
                cli.get_byte_size(cli.search_param_val('--object-size', val))),
        combinations)
    [exec_cmd('rbd create {} {}/img{}'.format(param, pool_name['val']['pool1'],
                                              iterator))
     for iterator, param in enumerate(combinations, start=iterator + 1)]

    # Feature Disable & Enable and Object-map rebuild
    [exec_cmd('rbd create -s 10G --object-size 32M --stripe-unit 16777216 '
              '--stripe-count 16 --image-feature layering,'
              'striping,exclusive-lock,object-map,fast-diff,deep-flatten,'
              'journaling {}/img{}'.format(pool_name['val']['pool1'], iterator))
     for iterator in range(iterator + 1, iterator + 3)]
    [exec_cmd('rbd feature disable {}/img{} {}'
              .format(pool_name['val']['pool1'], iterator, val))
     for val in image_feature if 'layering' not in val and 'striping' not in val
     ]

    for val in list(reversed(image_feature)):
        if 'deep-flatten' not in val and 'layering' not in val \
                and 'striping' not in val:
            exec_cmd('rbd feature enable {}/img{} {}'
                     .format(pool_name['val']['pool1'], iterator, val))
            if 'fast-diff' in str(val) or 'object-map' in str(val):
                exec_cmd('rbd object-map rebuild {}/img{}'
                         .format(pool_name['val']['pool1'], iterator))

    # Resize
    combinations = cli.generate_combinations('image_resize')
    [exec_cmd('rbd resize {} {}'.format(param, pool_name['val']['pool1']
                                        + '/img' + str(iterator)))
     for param in combinations]

    # Images Deletion
    [exec_cmd('rbd rm {}/img{}'.format(pool_name['val']['pool1'], index))
     for index in range(0, 10)]

    # Copy Images
    exec_cmd('rbd cp {}/img{} {}/cpimg'.format(pool_name['val']['pool1'],
                                               iterator,
                                               pool_name['val']['pool2']))

    # Renaming Images
    exec_cmd('rbd mv {}/cpimg {}/mvimg'.format(pool_name['val']['pool2'],
                                               pool_name['val']['pool2']))

    # Image-meta set
    exec_cmd('rbd image-meta set {}/mvimg conf_rbd_cache false'
             .format(pool_name['val']['pool2']))

    # Image-meta list
    exec_cmd('rbd image-meta list {}/mvimg'.format(pool_name['val']['pool2']))

    # Image-meta get
    exec_cmd('rbd image-meta get {}/mvimg conf_rbd_cache'
             .format(pool_name['val']['pool2']))

    # Image-meta Removing
    exec_cmd('rbd image-meta remove {}/mvimg conf_rbd_cache'
             .format(pool_name['val']['pool2']))

    # Listing Images In the Pool
    [exec_cmd('rbd ls -l {}'.format(pool_name['val'][key]))
     for key, val in pool_name['val'].iteritems()]

    # Image Info
    exec_cmd('rbd info {}/img{}'.format(pool_name['val']['pool1'], iterator))

    # Image Status
    exec_cmd('rbd status {}/img{}'.format(pool_name['val']['pool1'], iterator))

    if cli.ceph_version > 2:
        # Moving Image to trash
        [exec_cmd('rbd trash mv {}/img{}'.format(pool_name['val']['pool1'],
                                                 iterator))
         for iterator in range(iterator, iterator-11, -1)]
        exec_cmd('rbd trash mv {}/mvimg'.format(pool_name['val']['pool2']))

        # Listing trash entries
        if exec_cmd('rbd trash ls {}'.format(pool_name['val']['pool1'])):

            # Restoring image from trash
            json_output = json.loads(exec_cmd('rbd trash ls {} --format=json'
                                              .format(pool_name['val']['pool1'])
                                              ))
            for num in range(0, 18, 2):
                exec_cmd('rbd trash restore {}/{}'
                         .format(pool_name['val']['pool1'], json_output[num]))

        # Removing image from trash
        if exec_cmd('rbd trash ls {}'.format(pool_name['val']['pool2'])):
            json_output = json.loads(exec_cmd('rbd trash ls {} --format=json'
                                              .format(pool_name['val']['pool2'])
                                              ))
            exec_cmd('rbd trash rm {}/{}'
                     .format(pool_name['val']['pool2'], json_output[0]))

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
