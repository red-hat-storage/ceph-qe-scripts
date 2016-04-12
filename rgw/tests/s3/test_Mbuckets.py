import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
from lib.s3.rgw import RGW
import utils.log as log
import sys
from utils.test_desc import AddTestInfo


def test_exec():

    test_info = AddTestInfo('crate m buckets')

    try:

        test_info.started_info()

        rgw = RGW('2D6OA0XPW2WEY4LZND4T', '58onUujPfEJGmC8VVM9BHGq9SkC9vyeRZYAGp8AD')

        rgw.create_bucket_with_keys(100, 0)

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test faield: %s' % e)
        sys.exit(1)


if __name__ == '__main__':
    test_exec()
