from lib.s3.rgw import RGWMultpart
import utils.log as log
import sys
from utils.test_desc import AddTestInfo


def test_exec():

    test_info = AddTestInfo('Multi Part Upload and cancel after upload')

    try:

        test_info.started_info()

        rgw = RGWMultpart('secrete_key', 'access_key')
        rgw.set_cancel_upload = True

        rgw.upload(3000, 'large_bucket')

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test faield: %s' % e)
        sys.exit(1)


if __name__ == '__main__':
    test_exec()
