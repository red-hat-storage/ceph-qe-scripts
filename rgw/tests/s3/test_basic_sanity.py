import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
from lib.s3.rgw import RGW
import utils.log as log
from lib.s3.objects import KeyOp, PutContentsFromFile
import utils.utils as utils
from utils.test_desc import AddTestInfo


def test_exec():

    add_test = AddTestInfo('Basic Sanity check: get and pull')

    try:

        add_test.started_info()

        log.info('starting init of RGW instace. trying to authenticate')
        init_rgw = RGW('2D6OA0XPW2WEY4LZND4T', '58onUujPfEJGmC8VVM9BHGq9SkC9vyeRZYAGp8AD')

        bucky = init_rgw.bucket.create('random.wing')

        assert bucky['status'], "bucket creation failed"

        randon_bucket = bucky['bucket']

        key_op = KeyOp(randon_bucket)

        random_key = key_op.create('wing2')

        if random_key is None:
            raise AssertionError

        upload_from_file = PutContentsFromFile(random_key)

        random_file, md5 = utils.create_file('nexus', 60)

        uploaded_file = upload_from_file.put(random_file)
        assert uploaded_file['status'], "upload of key %s failed" % uploaded_file

        log.info('verifying the upload')

        all_keys_in_bucket = randon_bucket.get_all_keys()

        for key in all_keys_in_bucket:
            log.info('key_name %s' % key.name)
            log.info('key md5 %s' % key.etag)
            log.info('key size %s' % key.size)

        add_test.success_status('test successfull')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        add_test.failed_status('failed test cases')
        sys.exit(1)


def some_fucn():
    init_rgw = RGW('access_key', 'secret_key')

    bucky = init_rgw.bucket.create('rakesh')


if __name__ == '__main__':

    test_exec()
