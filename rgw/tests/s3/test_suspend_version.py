import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../..")))
import utils.log as log
import sys
from utils.test_desc import AddTestInfo
from lib.s3.rgw import Config
from lib.s3.rgw import RGW
import lib.s3.rgw as rgw_lib


def test_exec():

    test_info = AddTestInfo('enable versioning on a bucket and upload keys and its versions '
                            'and suspend version on the same bucket')

    try:

        config = Config()
        config.user_count = 1
        config.objects_count = 1
        config.objects_size_range = {'min': 5, 'max': 15}

        test_info.started_info()

        all_user_details = rgw_lib.create_users(config.user_count)

        for each_user in all_user_details:

            rgw = RGW(each_user)
            rgw.enable_versioning = True
            rgw.version_count = 5
            rgw.create_bucket_with_keys(config)
            rgw.enable_versioning = False
            rgw.create_bucket_with_keys(config)

        test_info.success_status('test completed')

        sys.exit(0)

    except AssertionError, e:
        log.error(e)
        sys.exit(1)


if __name__ == '__main__':

    test_exec()