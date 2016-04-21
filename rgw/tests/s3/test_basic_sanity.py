import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import utils.log as log
import sys
from utils.test_desc import AddTestInfo
from lib.s3.rgw import RGWConfig


def test_exec():

    test_info = AddTestInfo('crate m buckets')

    try:

        test_info.started_info()

        config = RGWConfig()

        config.user_count = 1
        config.bucket_count = 10
        config.objects_count = 4
        config.objects_size_range = {'min': 5, 'max': 15}

        config.exec_test()

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test faield: %s' % e)
        sys.exit(1)


if __name__ == '__main__':

    test_exec()
