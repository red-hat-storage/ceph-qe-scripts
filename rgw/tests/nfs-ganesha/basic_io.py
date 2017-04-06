import os
import shutil
import argparse


def create_delete_nested_dirs(config):

    nest_level = config['nest_level']
    files = config['Files']
    delete_dirs = config['delete_dirs']
    destination = config['destination']

    dirs = ['dir' + str(i) for i in range(nest_level)]

    current_dir = destination

    created_dir = []

    for each in dirs:

        nest = os.path.join(current_dir, each)
        print 'creating dir  :%s' % nest
        os.makedirs(nest)
        created_dir.append(nest)

        for no in range(files['files_in_dir']):
            path = os.path.join(nest, 'file_image' + str(no))

            print 'creating file :%s' % path

            try:
                fcreate = 'dd if=/dev/urandom of=%s bs=%sM count=1' % (path, files['size'])
                os.system(fcreate)

            except (IOError, Exception) as e:
                print e
                exit(1)

        current_dir = nest

        print '-------------------------------'

    if delete_dirs:

        created_dir.reverse()
        print 'deleting dirs'
        [shutil.rmtree(x) for x in created_dir]

    dir_created = destination + '/dir0'
    dir_exists = os.path.exists(dir_created)

    if not dir_exists:
        print 'deletion successful'

    else:
        print 'dir still exists'



if __name__ == '__main__':


    parser = argparse.ArgumentParser(description='NFS-Ganesha Automation')

    parser.add_argument('-c', dest="config",
                        help='nested dir test. format = [nest_dir_level-files_in_dir-file_size] ex: 30-3-10')


    parser.add_argument('-p', dest="path",
                        help='please mention the full path')

    parser.add_argument('-r', dest="repeat", default='50',
                        help='repeat creation and deletion')

    args = parser.parse_args()

    dir_config = args.config.split('-')

    destination = args.path

    args = parser.parse_args()

    repeat = int(args.repeat)

    for i in range(repeat):

        config = dict(nest_level=int(dir_config[0]),
                      Files=dict(files_in_dir=int(dir_config[1]), size=int(dir_config[2])),
                      destination=destination,
                      delete_dirs=True)

        create_delete_nested_dirs(config)



