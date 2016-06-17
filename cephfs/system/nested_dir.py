import os
import shutil


def create_delete_nested_dirs(config):

    nest_level = config['nest_level']
    files = config['Files']
    delete_dirs = config['delete_dirs']

    dirs = ['dir' + str(i) for i in range(nest_level)]

    current_dir = os.path.dirname(os.path.abspath(__file__))

    created_dir = []

    for each in dirs:

        nest = os.path.join(current_dir, each)
        print 'creating dir  :%s' % nest
        os.makedirs(nest)
        created_dir.append(nest)

        for no in range(files['files_in_dir']):
            path = os.path.join(nest, 'file_image' + str(no))

            print 'creating file :%s' % path
            fcreate = 'dd if=/dev/zero of=%s  bs=1 count=2 seek=%sM' % (path, files['size'])
            os.system(fcreate)

        current_dir = nest

        print '-------------------------------'

    if delete_dirs:

        created_dir.reverse()
        print 'deleting dirs'
        [shutil.rmtree(x) for x in created_dir]


if __name__ == '__main__':

    REPEAT = 1

    for i in range(REPEAT):

        config = dict(nest_level=30,
                      Files=dict(files_in_dir=3, size=10),
                      delete_dirs=True)

        create_delete_nested_dirs(config)
