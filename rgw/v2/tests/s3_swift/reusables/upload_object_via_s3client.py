import json
import logging
import os
import random
import time
import timeit
from urllib import parse as urlparse

import v2.lib.manage_data as manage_data
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import ConfigOpts

log = logging.getLogger()


def upload_object_via_s3client(
    s3_client,
    bucketname,
    s3_object_name,
    TEST_DATA_PATH,
    config,
    each_user,
    append_data=False,
    append_msg=None,
):
    """
    upload object via s3 boto client way
    """
    log.info("s3 object name: %s" % s3_object_name)
    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
    log.info("s3 object path: %s" % s3_object_path)
    s3_object_size = config.obj_size
    if append_data is True:
        data_info = manage_data.io_generator(
            s3_object_path,
            s3_object_size,
            op="append",
            **{"message": "\n%s" % append_msg},
        )
    else:
        data_info = manage_data.io_generator(s3_object_path, s3_object_size)
    if data_info is False:
        TestExecError("data creation failed")
    put_obj = s3_client.put_object(
        Bucket=bucketname, Key=s3_object_name, Body=s3_object_path
    )
    if not put_obj:
        raise TestExecError("put object failed")
