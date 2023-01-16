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


def put_bucket_encryption(s3_client, bucketname, encryption_method):
    """
    put bucket encryption on a given bucket.
    """
    log.info(f"put bucket encryption on {bucketname}")
    if encryption_method == "s3":
        ssec_s3_kms = {
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        }
    else:
        ssec_s3_kms = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "testKey01",
                    }
                }
            ]
        }
    put_bkt_encryption = s3_client.put_bucket_encryption(
        Bucket=bucketname, ServerSideEncryptionConfiguration=ssec_s3_kms
    )

    if put_bkt_encryption is False:
        raise TestExecError("put bucket encryption failed")


def get_bucket_encryption(s3_client, bucketname):
    """
    get bucket notification for a given bucket
    """
    get_bkt_encryption = s3_client.get_bucket_encryption(Bucket=bucketname)
    if get_bkt_encryption is False:
        raise TestExecError("get bucket encryption failed")

    get_bkt_encryption_json = json.dumps(get_bkt_encryption, indent=2)
    log.info(f"bucket encryption for bucket: {bucketname} is {get_bkt_encryption_json}")


def get_object_encryption(s3_client, bucketname, s3_object_name):
    """
    get object encryption for an object, it should be AES256
    """
    get_obj_encryption = s3_client.get_object(Bucket=bucketname, Key=s3_object_name)
    result = get_obj_encryption["ServerSideEncryption"]
    if result == "AES256":
        log.info(f"server side encryption is with s3 keys on object {s3_object_name}")
    elif result == "aws:kms":
        log.info(f"server side encryption is with kmsi keys on object {s3_object_name}")
    else:
        raise TestExecError("object encryption has failed")


def put_object_encryption(
    s3_client,
    bucketname,
    s3_object_name,
    encryption_method,
    TEST_DATA_PATH,
    config,
    each_user,
    append_data=False,
    append_msg=None,
):
    """
    put object encryption for an object, it should be AES256
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

    log.info(f"Enable object encryption when object is uploaded.")
    if encryption_method == "s3":
        log.info("server side encryption is with s3 keys")
        put_obj_encryption = s3_client.put_object(
            Bucket=bucketname,
            Key=s3_object_name,
            Body=s3_object_path,
            ServerSideEncryption="AES256",
        )
    else:
        put_obj_encryption = s3_client.put_object(
            Bucket=bucketname,
            Key=s3_object_name,
            Body=s3_object_path,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId="testKey01",
        )

    if not put_obj_encryption:
        raise TestExecError("put object encryption failed")
