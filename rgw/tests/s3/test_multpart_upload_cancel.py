import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
from lib.s3.rgw import RGWMultpart
import utils.log as log
import sys
from utils.test_desc import AddTestInfo
from lib.admin import RGWAdminOps


def test_exec():

    test_info = AddTestInfo('MultiPart Upload and cancel after upload')

    try:

        test_info.started_info()

        break_part_no = 145
        size = 5000
        bucket_name = 'think.batman8'

        user_id = 'kidflash8'
        displayname = 'west jr8'

        admin_ops = RGWAdminOps()

        user_details = admin_ops.create_admin_user(user_id, displayname)

        rgw = RGWMultpart(user_details['access_key'], user_details['secret_key'], user_details['user_id'])

        rgw.break_upload_at_part_no = break_part_no

        rgw.upload(size, bucket_name)

        log.info('----------------------------')

        log.info('starting from part no: %s' % break_part_no)

        log.info('----------------------------')

        rgw.break_upload_at_part_no = 0
        rgw.upload(size, bucket_name)

        rgw.download()

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        test_info.failed_status('test faield: %s' % e)
        sys.exit(1)


if __name__ == '__main__':
    test_exec()
