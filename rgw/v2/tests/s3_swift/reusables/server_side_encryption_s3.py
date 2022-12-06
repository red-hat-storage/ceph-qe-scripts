import json
import logging
import os
import random
import time
import timeit
from urllib import parse as urlparse

import v2.utils.utils as utils
from v2.lib.exceptions import EventRecordDataError

log = logging.getLogger()


def put_bucket_encryption(s3_client, bucketname):
    """
    put bucket encryption on a given bucket.
    """
    log.info(f"put bucket encryption on {bucketname}")
    ssec_s3 = {
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    }
    put_bkt_encryption = s3_client.put_bucket_encryption(
        Bucket=bucketname, ServerSideEncryptionConfiguration=ssec_s3
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
    log.info(f"Test if object uploaded is encrypted with AES256")
    get_obj_encryption = s3_client.get_object(Bucket=bucketname, Key=s3_object_name)
    log.info(
        f"server side encryption enabled on {s3_object_name} is : {get_obj_encryption['ServerSideEncryption']}"
    )
    result = get_obj_encryption["ServerSideEncryption"]
    if result != "AES256":
        raise TestExecError("object encryption has failed")


def put_object_encryption(s3_client, bucketname, s3_object_name):
    """
    put object encryption for an object, it should be AES256
    """
    log.info(f"Enable object encryption when object is uploaded.")
    put_obj_encryption = s3_client.put_object(
        Bucket=bucketname,
        Key=s3_object_name,
        Body="Sinister sisters hide in plain view",
        ServerSideEncryption="AES256",
    )

    if not put_obj_encryption:
        raise TestExecError("put object encryption failed")
