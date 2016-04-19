import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
from lib.s3.rgw import RGWMultpart
import utils.log as log
import sys
from utils.test_desc import AddTestInfo
from lib.admin import RGWAdminOps

def test_exec():

    test_info = AddTestInfo('Multi Part Upload')

    try:
        test_info.started_info()

        user_id = 'arrow1'
        displayname = 'oliver queen'

        test_info.started_info()

        admin_ops = RGWAdminOps()

        user_details = admin_ops.create_admin_user(user_id, displayname)

        rgw = RGWMultpart(user_details['access_key'], user_details['secret_key'], user_details['user_id'])

        rgw.upload(3000, 'bigbasket22')
        rgw.download('bigbasket22')

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test failed: %s' % e)
        sys.exit(1)


if __name__ == '__main__':
    test_exec()
