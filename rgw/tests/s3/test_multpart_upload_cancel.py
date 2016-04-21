import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
from lib.s3.rgw import RGWConfig
import utils.log as log
import sys
from utils.test_desc import AddTestInfo


def test_exec():

    test_info = AddTestInfo('Multipart upload ')

    try:

        test_info.started_info()

        rgw = RGWConfig()

        rgw.user_count = 1
        rgw.bucket_count = 1
        rgw.objects_size_range = {'min': 500, 'max': 1500}
        rgw.multipart_upload = True
        rgw.multipart_break_part = 150

        rgw.exec_test()

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test faield: %s' % e)
        sys.exit(1)


if __name__ == '__main__':
    test_exec()
