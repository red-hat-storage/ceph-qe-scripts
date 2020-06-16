import os
import sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import argparse
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

    path_list = ['/tmp/{}'.format(cli.rbd.random_string()),
                 '/tmp/{}'.format(cli.rbd.random_string()),
                 '/tmp/{}'.format(cli.rbd.random_string())]

    # Creation of Directories
    [exec_cmd('mkdir {}'.format(path)) for path in path_list]

    # Simple Image Creation
    combinations = cli.generate_combinations('image_size', 'object_size',
                                             'image_format')
    if k_m:
        combinations = cli.generate_combinations('image_size', 'object_size',
                                                 'image_format', 'data_pool')
        if cli.ceph_version == 3:
            invalid = [val for val in combinations
                   if (cli.search_param_val('--image-format', val) != 0 and
                       cli.search_param_val('--image-format', val)
                       .find('1') != -1)]
            map(lambda val: combinations.remove(val), invalid)

    combinations = list(filter(lambda val: cli.search_param_val('-s', val).find('M') != -1 and
                          cli.search_param_val('--object-size', val) != 0 and
                          cli.search_param_val('--object-size', val).find('B') != -1,
                          combinations))
    [exec_cmd('rbd create {} {}/img{}'.format(param,
                                              parameters.rep_pool['val']['pool0'],
                                              iterator))
     for iterator, param in enumerate(combinations, start=0)]

    # Snap Creation
    [exec_cmd('rbd snap create {}/img{num}@snapimg{num}'
              .format(parameters.rep_pool['val']['pool0'], num=iterator))
     for iterator in range(0, len(combinations))]

    # Export
    iterator = iterator3 = 0
    combinations = cli.generate_combinations('export_format')
    for iterator2 in range(0, iterator + 1):
        for iterator3, param in enumerate(combinations, start=0):
            exec_cmd('rbd export {} {}/img{num} {}/img{num}'
                     .format(param, parameters.rep_pool['val']['pool0'],
                             path_list[0], num=iterator2))

            exec_cmd('rbd export {} {}/img{num}@snapimg{num} {}/img{num}@snapimg{num}'
                     .format(param, parameters.rep_pool['val']['pool0'],
                             path_list[0], num=iterator2))

            if cli.ceph_version > 2 and not (iterator3 == len(combinations) - 1 and iterator2 == iterator):
                exec_cmd('rm {}/img{}'.format(path_list[0], iterator2))
                exec_cmd('rm {}/img{num}@snapimg{num}'.format(path_list[0],
                                                              num=iterator2))

    # Import
    combinations = cli.generate_combinations('export_format', 'image_format',
                                             'object_size', 'stripe',
                                             'image_feature', 'image_shared')
    if cli.ceph_version == 2:
        invalid = [val for val in combinations
                   if (cli.search_param_val('--image-feature', val) != 0 and
                       cli.search_param_val('--image-feature', val).find('striping') != -1 and
                       cli.search_param_val('--stripe-unit', val) == 0)]
        map(lambda val: combinations.remove(val), invalid)

    combinations = list(filter(lambda val: (cli.search_param_val('--image-format', val) == 0 or
                                       cli.search_param_val('--image-format', val) != 0 and
                                       cli.search_param_val('--image-format', val).find('1') == -1) and
                          (cli.search_param_val('--stripe-unit', val) == 0 or
                          (cli.get_byte_size(cli.search_param_val('--stripe-unit', val)) <=
                           cli.get_byte_size(cli.search_param_val('--object-size', val)))),
                          combinations))
    [exec_cmd('rbd import {} {}/img{} {} {}/imgimport{}'
              .format(param, path_list[0], iterator,
                      parameters.data_pool['arg'] + ' ' + parameters.data_pool['val']['pool0'],
                      parameters.rep_pool['val']['pool0'], iterator3))
     for iterator3, param in enumerate(combinations, start=0)]

    # Export-diff
    iterator = iterator2 = 0
    combinations = cli.generate_combinations('whole_object')
    for iterator2, param in enumerate(combinations, start=0):
        exec_cmd('rbd export-diff {} {}/img{num} {}/img{num}'
                 .format(param, parameters.rep_pool['val']['pool0'], path_list[1], num=iterator))
        exec_cmd(
            'rbd export-diff --from-snap snapimg{num} {} {}/img{num} {}/img{num}'
            .format(param, parameters.rep_pool['val']['pool0'], path_list[2], num=iterator))
        exec_cmd(
            'rbd export-diff {} {}/img{num}@snapimg{num} {}/img{num}@snapimg{num}'
            .format(param, parameters.rep_pool['val']['pool0'], path_list[1], num=iterator)),

        exec_cmd(
            'rbd export-diff --from-snap snapimg{num} {} {}/img{num}@snapimg{num} {}/img{num}@snapimg{num}'
            .format(param, parameters.rep_pool['val']['pool0'], path_list[2], num=iterator))

        if iterator2 == 0:
            for path in path_list[1:]:
                exec_cmd('rm {}/img{}'.format(path, iterator))
                exec_cmd('rm {}/img{num}@snapimg{num}'
                         .format(path, num=iterator))

    exec_cmd('rbd export-diff {}/img{num} {}/imgex{num}'
             .format(parameters.rep_pool['val']['pool0'], path_list[1], num=iterator))

    # Merge-diff
    exec_cmd('rbd merge-diff {path}/img{num} {path}/imgex{num} {}/merge-diff-img{num}'
             .format(path_list[0], path=path_list[1], num=iterator))

    # Import-diff
    exec_cmd('rbd import-diff {}/img{num} {}/img{num}'
             .format(path_list[1], parameters.rep_pool['val']['pool0'], num=iterator))

    # diff
    combinations = cli.generate_combinations('whole_object')
    for param in combinations:
        exec_cmd('rbd diff {} {}/img{}'.format(param, parameters.rep_pool['val']['pool0'],
                                               iterator))
        exec_cmd('rbd diff --from-snap snapimg{num} {} {}/img{num}'
                 .format(param, parameters.rep_pool['val']['pool0'], num=iterator))
        exec_cmd('rbd diff {} {}/img{num}@snapimg{num}'
                 .format(param, parameters.rep_pool['val']['pool0'], num=iterator))
        exec_cmd('rbd diff --from-snap snapimg{num} {} {}/img{num}@snapimg{num}'
                 .format(param, parameters.rep_pool['val']['pool0'], num=iterator))

    # Deletion Of Directories
    [exec_cmd('rm -rf {}'.format(path)) for path in path_list]

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
