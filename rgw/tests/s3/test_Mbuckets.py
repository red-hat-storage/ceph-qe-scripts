import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))

from lib.s3.rgw import RGWConfig
import utils.log as log
from utils.test_desc import AddTestInfo


def test_exec():

    test_info = AddTestInfo('crate m buckets')

    try:

        test_info.started_info()

        rgw = RGWConfig()

        rgw.user_count = 2
        rgw.bucket_count = 10

        rgw.exec_test()

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test faield: %s' % e)
        sys.exit(1)


if __name__ == '__main__':
    test_exec()
