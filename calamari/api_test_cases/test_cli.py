import libs.log as log
from utils.test_desc import AddTestInfo
from http_ops import Initialize
import argparse
from utils.utils import get_calamari_config


class Test(Initialize):

    def __init__(self, **config):

        super(Test, self).__init__(**config)

        self.cli_url = self.http_request.base_url + "cluster" + "/" + str(self.http_request.fsid) + "/cli"


def exec_test(config_data):

    add_test_info = AddTestInfo(1, 'api/v2/cluster/<fsid>/cli')
    add_test_info.started_info()

    try:

        test = Test(**config_data)

        commands = ['ceph osd tree',
                    ['ceph', '-s'],
                   # ["ceph", "osd", "dump"] # this type of command fails, i.e list of 3 elements .
                 ]

        """
        commands = [
            'ceph osd tree',
            ['ceph', '-s'],
            'ceph osd pool delete test_rbd test_rbd --yes-i-really-really-mean-it',
            # positive:
            'ceph osd pool create test_rbd 100',

            ## Create a test image that will be used in the api testing
            'rbd --cluster ceph  create test0 --image-format 2  --size 4096 --pool test_rbd --name client.test_rbd --keyring /etc/ceph/test_rbd.keyring',

            ## cp
            'rbd --cluster ceph  cp test_rbd/test0 test_rbd/test4',
            'rbd --cluster ceph  snap create --pool test_rbd --image test0 --snap snap101',
            'rbd --cluster ceph  cp test_rbd/test0@snap101 test_rbd/test5',
            'rbd --cluster ceph  cp test_rbd/test0@snap101 test_rbd/test6',

            ## remove image:
            'rbd --cluster ceph  create test100 --image-format 2  --size 4096 --pool test_rbd --name client.test_rbd --keyring /etc/ceph/test_rbd.keyring',
            'rbd --cluster ceph  remove -p test_rbd --image test100',
            'rbd --cluster ceph  create test100 --image-format 2  --size 4096 --pool test_rbd --name client.test_rbd --keyring /etc/ceph/test_rbd.keyring',
            'rbd --cluster ceph  remove test_rbd/test100',
            'rbd --cluster ceph  create test100 --image-format 2  --size 4096 --pool test_rbd --name client.test_rbd --keyring /etc/ceph/test_rbd.keyring',
            'rbd --cluster ceph  rm -p test_rbd --image test100',

            ## bench-write
            'rbd --cluster ceph  bench-write -p test_rbd --image test0 --io-size 1K --io-threads 3 --io-total 1M --io-pattern rand',
            'rbd --cluster ceph  bench-write -p test_rbd --image test0 --io-size 1K --io-threads 3 --io-total 1M --io-pattern seq',
            'rbd --cluster ceph  bench-write -p test_rbd --image test0 --io-size 1M --io-threads 3 --io-total 1G --io-pattern rand',
            'rbd --cluster ceph  bench-write -p test_rbd --image test0 --io-size 1G --io-threads 3 --io-total 2G --io-pattern rand',

            ## info
            'rbd --cluster ceph  info test_rbd/test0',

            ##resize,
            'rbd --cluster ceph  resize -p test_rbd --image test0 -s 4000M --allow-shrink',
            'rbd --cluster ceph  resize test_rbd/test0 -s 4096M',

            ## snap
            'rbd --cluster ceph  snap create --pool test_rbd --image test0 --snap snap1',
            'rbd --cluster ceph  snap remove --pool test_rbd --image test0 --snap snap1',
            'rbd --cluster ceph  snap create test_rbd/test0@snap1',
            'rbd --cluster ceph  snap list test_rbd/test0',
            'rbd --cluster ceph  snap rename test_rbd/test0@snap1 test_rbd/test0@snap1-1',
            'rbd --cluster ceph  snap rename test_rbd/test0@snap1-1 test_rbd/test0@snap1',
            'rbd --cluster ceph  snap rename --pool test_rbd --image test0 --snap snap1 --dest-pool test_rbd --dest test0 --dest-snap snap1-1',
            'rbd --cluster ceph  snap rename --pool test_rbd --image test0 --snap snap1-1 --dest-pool test_rbd --dest test0 --dest-snap snap1',
            'rbd --cluster ceph  snap protect test_rbd/test0@snap1',
            'rbd --cluster ceph  snap unprotect test_rbd/test0@snap1',
            'rbd --cluster ceph  snap protect -p test_rbd  --image test0 --snap snap1',
            'rbd --cluster ceph  snap unprotect -p test_rbd  --image test0 --snap snap1',
            'rbd --cluster ceph  snap create test_rbd/test0@snap100',
            'rbd --cluster ceph  snap rollback  test_rbd/test0@snap100',
            'rbd --cluster ceph  snap remove test_rbd/test0@snap1',
            'rbd --cluster ceph  snap purge test_rbd/test0',

            ## children, clone, flatten
            'rbd --cluster ceph  snap create --pool test_rbd --image test0 --snap snap121',
            'rbd --cluster ceph  snap protect test_rbd/test0@snap121',
            'rbd --cluster ceph  clone test_rbd/test0@snap121 test_rbd/test40',
            'rbd --cluster ceph  children test_rbd/test0@snap121',
            'rbd --cluster ceph  children -p test_rbd --image test0 --snap snap121 --format xml',
            'rbd --cluster ceph  children -p test_rbd --image test0 --snap snap121 --format json',
            'rbd --cluster ceph  children -p test_rbd --image test0 --snap snap121 --pretty-format',
            'rbd --cluster ceph  clone --pool test_rbd --image test0 --snap snap121 --dest-pool test_rbd --dest test41 --object-size 16K --stripe-unit 2 --stripe-count 2',
            'rbd --cluster ceph  clone test_rbd/test0@snap121 test_rbd/test50',
            'rbd --cluster ceph  flatten test_rbd/test40',
            'rbd --cluster ceph  flatten -p test_rbd --image test50',

            ## diff
            'rbd --cluster ceph  diff test_rbd/test0',
            'rbd --cluster ceph   diff -p test_rbd --image test0 --snap snap121 --whole-object --format xml',
            'rbd --cluster ceph   diff -p test_rbd --image test0 --snap snap121 --whole-object --format json',
            'rbd --cluster ceph   diff -p test_rbd --image test0 --snap snap121 --whole-object --format xml --pretty-format',

            ## export
            'rbd --cluster ceph  export test_rbd/test0 /tmp/RBD-test-image-export0',
            'rbd --cluster ceph  export -p test_rbd --image test0 --path /tmp/RBD-test-image-export1',
            'rbd --cluster ceph  export test_rbd/test0@snap1 /tmp/RBD-test-image-export2',

            ## feature disable enable
            'rbd --cluster ceph  create test-disenable --image-format 2  --size 4096 --pool test_rbd --name client.test_rbd --keyring /etc/ceph/test_rbd.keyring',
            'rbd --cluster ceph  feature disable test_rbd/test-disenable layering',
            'rbd --cluster ceph  remove -p test_rbd --image test-disenable',
            'rbd --cluster ceph  feature enable test_rbd/test0 journaling',
            'rbd --cluster ceph  feature disable test_rbd/test0 journaling',

            ##image-meta list, set, get
            'rbd --cluster ceph  image-meta set test_rbd/test0 rbd_cache_size false',
            'rbd --cluster ceph  image-meta list test_rbd/test0',
            'rbd --cluster ceph  image-meta list -p test_rbd --image test0 --format json',
            'rbd --cluster ceph  image-meta list -p test_rbd --image test0 --format xml',
            'rbd --cluster ceph  image-meta list -p test_rbd --image test0 --pretty-format',
            'rbd --cluster ceph  image-meta get test_rbd/test0 rbd_cache_size',

            ##list
            'rbd --cluster ceph  list',
            'rbd --cluster ceph  ls',

            ## rename
            'rbd --cluster ceph  rename test_rbd/test0 test_rbd/testRen',
            'rbd --cluster ceph  rename -p test_rbd --image testRen --dest-pool test_rbd --dest test0',

            # Status
            'rbd --cluster ceph  status test_rbd/test0',

            # Showmapped. Needs manual steps to test these. Tested manually
            # 'rbd --cluster ceph  showmapped --format json',
            # 'rbd --cluster ceph  showmapped --format xml',
            # 'rbd --cluster ceph  showmapped',
            # 'rbd --cluster ceph  showmapped --pretty-format',

            # unmap - can't be automated. involves running ext4 file system creation commands and mount cmds
            # unmap

            # watch: This doesn't return until enter is pressed. Already a defect exists. Can't be used in API
            # 'rbd --cluster ceph  watch test0'

            ## du
            # 'rbd --cluster ceph  du -p test_rbd',
            # 'rbd --cluster ceph  du -p test_rbd --image test0',
            # 'rbd --cluster ceph  du -p test_rbd --image test0 --pretty-format',
            # 'rbd --cluster ceph  du -p test_rbd --image test0 --snap snap1 --from-snap 3424',


            ## diff
            'rbd --cluster ceph  diff --pool test_rbd --image test0 --snap snap121 --from-snap snap121 --whole-object --format json',
            'rbd --cluster ceph  diff --pool test_rbd --image test0 --snap snap121 --from-snap snap121 --whole-object --pretty-format',
            'rbd --cluster ceph  diff --pool test_rbd --image test0 --snap snap121 --from-snap snap121 --pretty-format',
            'rbd --cluster ceph  diff --pool test_rbd --image test0 --snap snap121 --from-snap snap121',
            'rbd --cluster ceph  diff test_rbd/test0@snap121',
            'rbd --cluster ceph  diff --pool test_rbd --image test0 --snap snap121',

            # -----------------------------------------------------------------

            # Help commands:
            ' rbd	help	bench-write	',
            ' rbd	help	children	',
            ' rbd	help	clone	',
            ' rbd	help	copy	',
            ' rbd	help	create	',
            ' rbd	help	diff	',
            ' rbd	help	disk-usage	',
            ' rbd	help	export	',
            ' rbd	help	export-diff	',
            ' rbd	help	feature	disable	',
            ' rbd	help	feature	enable	',
            ' rbd	help	flatten	',
            ' rbd	help	image-meta	get	',
            ' rbd	help	image-meta	list	',
            ' rbd	help	image-meta	remove	',
            ' rbd	help	image-meta	set	',
            ' rbd	help	import	',
            ' rbd	help	import-diff	',
            ' rbd	help	info	',
            ' rbd	help	journal	export	',
            ' rbd	help	journal	import	',
            ' rbd	help	journal	info	',
            ' rbd	help	journal	inspect	',
            ' rbd	help	journal	reset	',
            ' rbd	help	journal	status	',
            ' rbd	help	list	',
            ' rbd	help	lock	add	',
            ' rbd	help	lock	list	',
            ' rbd	help	lock	remove	',
            ' rbd	help	map	',
            ' rbd	help	merge-diff	',
            ' rbd	help	mirror	image	demote	',
            ' rbd	help	mirror	image	disable	',
            ' rbd	help	mirror	image	enable	',
            ' rbd	help	mirror	image	promote	',
            ' rbd	help	mirror	image	resync	',
            ' rbd	help	mirror	image	status	',
            ' rbd	help	mirror	pool	disable	',
            ' rbd	help	mirror	pool	enable	',
            ' rbd	help	mirror	pool	info	',
            ' rbd	help	mirror	pool	peer	add	',
            ' rbd	help	mirror	pool	peer	remove	',
            ' rbd	help	mirror	pool	peer	set	',
            ' rbd	help	mirror	pool	status	',
            ' rbd	help	nbd	list	',
            ' rbd	help	nbd	map	',
            ' rbd	help	nbd	unmap	',
            ' rbd	help	object-map	rebuild	',
            ' rbd	help	remove	',
            ' rbd	help	rename	',
            ' rbd	help	resize	',
            ' rbd	help	showmapped	',
            ' rbd	help	snap	create	',
            ' rbd	help	snap	list	',
            ' rbd	help	snap	protect	',
            ' rbd	help	snap	purge	',
            ' rbd	help	snap	remove	',
            ' rbd	help	snap	rename	',
            ' rbd	help	snap	rollback	',
            ' rbd	help	snap	unprotect	',
            ' rbd	help	status	',
            ' rbd	help	unmap	',

            ########################################################################

            # create images

            ' rbd create test_rbd/test_image02 --size 4G',
            ' rbd create test_rbd/test_image01 --size 2G',
            ' rbd create test_rbd/test_image03 --size 6G',
            ' rbd create test_rbd/test_image04 --size 5G',
            ' rbd create test_rbd/test_image05 --size 3G',

            # list images in a pool

            'rbd list --pool test_rbd --format json --pretty-format json',
            'rbd list --long --pool test_rbd --format json --pretty-format json',
            'rbd list --long --pool test_rbd --format plain',
            'rbd list --long --pool test_rbd --format xml',
            'rbd list --long --pool test_rbd --format xml --pretty-format xml',

            # resize an image

            'rbd resize --pool test_rbd --image test_image03 --size 3G --no-progress --allow-shrink',
            'rbd resize --pool test_rbd --image test_image01 --size 1G --allow-shrink',
            'rbd resize --pool test_rbd --image test_image05 --size 5G',

            # add lock

            'rbd lock add --shared test_lock_tag test_rbd/test_image01 test_lock_id',
            'rbd lock add test_rbd/test_image02 test_lock_id',
            'rbd lock add --shared test_lock_tag test_rbd/test_image05 test_lock_id_03',
            'rbd lock add test_rbd/test_image04 test_lock_id_02',

            # list locks

            'rbd lock ls test_rbd/test_image01',
            'rbd lock ls test_rbd/test_image02 --format xml',
            'rbd lock ls --pool test_rbd --image test_image01 --format json --pretty-format json',

            # unlock lock (remove)

            'rbd lock rm test_rbd/test_image01 test_lock_id client.14325',
            'rbd lock rm --pool test_rbd --image test_image02 test_rbd/test_image02 test_lock_id client.14326',
            'rbd lock rm test_rbd/test_image04 test_lock_id_02 client.14329',

            # map

            # creating image and snaps to test map

            'rbd create test_rbd/test_image06 --image-feature layering --size 2G',
            'rbd snap create test_rbd/test_image06@snap060',

            'rbd map --pool test_rbd --image test_image06',
            'rbd map --pool test_rbd --image test_image06 --snap snap060',
            'rbd map --pool test_rbd --image test_image06 --snap snap060 -o fsid=aaaa_dddddddddddddddd_rrrrrrrrrrrrrrrrrrrrrrr_ share',
            'rbd map --pool test_rbd --image test_image06 --snap snap060 -o fsid=aaaa_dddddddddddddddd_rrrrrrrrrrrrrrrrrrrrrrr_ crc',

            # image-meta set

            'rbd image-meta set test_rbd/test_image06 test_key02 test_value02',

            # image-meta get

            'rbd image-meta get test_rbd/test_image06 test_key02',

            # image-meta list

            'rbd image-meta list --pool test_rbd --image test_image06 --format xml --pretty-format test_rbd/test_image06',
            'rbd image-meta list --pool test_rbd --image test_image06 --format json test_rbd/test_image06',

            # image-meta list
            'rbd image-meta remove --pool test_rbd --image test_image06 test_rbd/test_image06 test_key01'
            'rbd image-meta remove test_rbd/test_image06 test_key02',

            # image-meta remove - no error message for deleting non existing key

            'rbd image-meta remove --pool test_rbd --image test_image06 test_rbd/test_image06 test_key01',
            'rbd image-meta remove test_rbd/test_image06 test_key02'

        ]
        """

        data_to_post = map(lambda x: {'command': x}, commands)

        results = [test.post(test.cli_url, each_data, request_api=False) for each_data in data_to_post]

        failed = [(command, result) for result, command in zip(results, commands)
                  if result['status'] != 0 and result['err'] != ""]

        passed = len(commands) - len(failed)

        log.info('no of commands submitted: %s' % len(commands))
        log.info('no of commands passed: %s' % passed)

        if failed:
            log.info('no of commands failed : %s' % len(failed))
            raise AssertionError(failed)

        add_test_info.success('test ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed('test error')

    return add_test_info.completed_info(config_data['log_copy_location'])


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Calamari API Automation')

    parser.add_argument('-c', dest="config", default='config.yaml',
                        help='calamari config file: yaml file')

    args = parser.parse_args()

    calamari_config = get_calamari_config(args.config)

    exec_test(calamari_config)

