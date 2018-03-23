import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import v2.lib.s3.s3lib as s3lib
import v2.utils.log as log
import v2.utils.utils as utils
from v2.utils.utils import HttpResponseParser
from v2.lib.exceptions import TestExecError


def create_bucket(rgw, user_info, rand_no=0):
    bucket_name = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no=rand_no)

    log.info('creating bucket with name: %s' % bucket_name)

    # bucket = s3_ops.resource_op(rgw_conn, 'Bucket', bucket_name_to_create)

    bucket_obj = s3lib.resource_op({'obj': rgw,
                                    'resource': 'Bucket',
                                    'args': [bucket_name]})

    created = s3lib.resource_op({'obj': bucket_obj,
                                 'resource': 'create',
                                 'args': None,
                                 'extra_info': {'access_key': user_info['access_key']}})

    if created is False:
        raise TestExecError("Resource execution failed: bucket creation faield")

    if created is not None:

        response = HttpResponseParser(created)

        if response.status_code == 200:
            log.info('bucket created')

        else:
            raise TestExecError("bucket creation failed")

    else:
        raise TestExecError("bucket creation failed")

    return bucket_obj, bucket_name,
