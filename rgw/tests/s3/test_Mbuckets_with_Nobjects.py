import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
from lib.s3.rgw import RGW
import utils.log as log
import sys
from utils.test_desc import AddTestInfo
from lib.admin import RGWAdminOps


def test_exec():

    test_info = AddTestInfo('crate m buckets with n objects')

    try:

        user_id = 'flash3'
        displayname = 'barry allen3'

        test_info.started_info()

        admin_ops = RGWAdminOps()

        user_details = admin_ops.create_admin_user(user_id, displayname)

        rgw = RGW(user_details['access_key'], user_details['secret_key'], user_details['user_id'])

        rgw.create_bucket_with_keys(2, 4, **{'min': 5, 'max': 20})
        rgw.download_objects()

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test faield: %s' % e)
        sys.exit(1)


if __name__ == '__main__':
    test_exec()