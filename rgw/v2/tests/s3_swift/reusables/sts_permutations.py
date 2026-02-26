import boto3
import logging
from botocore.exceptions import ClientError
import json
import random
import string
import inspect
import time
from datetime import datetime, timedelta
from v2.lib.s3.auth import Auth


def abort_multipart_upload(s3_client):
    try:
        response = s3_main.create_multipart_upload(Bucket=BUCKET, Key=OBJECT_KEY)
        upload_id = response['UploadId']
        s3_client.abort_multipart_upload(Bucket=BUCKET, Key=OBJECT_KEY, UploadId=upload_id)
        logging.info("AbortMultipartUpload succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"AbortMultipartUpload failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def create_bucket(s3):
    try:
        logging.info(f"CreateBucket {BUCKET}-copy")
        s3.create_bucket(Bucket=f"{BUCKET}-copy", ObjectLockEnabledForBucket=True)
        logging.info("CreateBucket succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"CreateBucket failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info("Creating Bucket with permanent creds for following tests")
        # s3_main.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)

def delete_bucket_policy(s3):
    try:
        s3.delete_bucket_policy(Bucket=BUCKET)
        logging.info("DeleteBucketPolicy succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"DeleteBucketPolicy failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def delete_bucket(s3):
    time.sleep(2)
    try:
        s3.delete_bucket(Bucket=BUCKET)
        logging.info("DeleteBucket succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"DeleteBucket failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def delete_bucket_website(s3):
    try:
        s3.delete_bucket_website(Bucket=BUCKET)
        logging.info("DeleteBucketWebsite succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"DeleteBucketWebsite failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def delete_object(s3):
    try:
        s3.delete_object(Bucket=BUCKET, Key=OBJECT_KEY)
        logging.info("DeleteObject succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"DeleteObject failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def delete_object_version(s3):
    try:
        logging.info(f"Deleting versions of object {OBJECT_KEY}")
        versions = s3_main.list_object_versions(Bucket=BUCKET, Prefix=OBJECT_KEY)
        for version in versions.get('Versions', []):
            s3.delete_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version['VersionId'])
            logging.info(f"Deleted version {version['VersionId']}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"DeleteObjectVersion failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_accelerate_configuration(s3):
    try:
        response = s3.get_bucket_accelerate_configuration(Bucket=BUCKET)
        logging.info(f"GetAccelerateConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetAccelerateConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_accelerate_configuration(s3):
    try:
        response = s3.get_bucket_accelerate_configuration(Bucket=BUCKET)
        logging.info(f"GetAccelerateConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetAccelerateConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_bucket_acl(s3):
    try:
        response = s3.get_bucket_acl(Bucket=BUCKET)
        logging.info(f"GetBucketAcl succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_bucket_cors(s3):
    try:
        response = s3.get_bucket_cors(Bucket=BUCKET)
        logging.info(f"GetBucketCORS succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketCORS failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_bucket_location(s3):
    try:
        response = s3.get_bucket_location(Bucket=BUCKET)
        logging.info(f"GetBucketLocation succeeded: {response['LocationConstraint']}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketLocation failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))



def get_bucket_logging(s3):
    try:
        response = s3.get_bucket_logging(Bucket=BUCKET)
        logging.info(f"GetBucketLogging succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketLogging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_bucket_notification(s3):
    try:
        response = s3.get_bucket_notification_configuration(Bucket=BUCKET)
        logging.info(f"GetBucketNotification succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketNotification failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_bucket_policy(s3):
    try:
        response = s3.get_bucket_policy(Bucket=BUCKET)
        logging.info(f"GetBucketPolicy succeeded: {response['Policy']}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketPolicy failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_bucket_request_payment(s3):
    try:
        response = s3.get_bucket_request_payment(Bucket=BUCKET)
        logging.info(f"GetBucketRequestPayment succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketRequestPayment failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_bucket_tagging(s3):
    try:
        response = s3.get_bucket_tagging(Bucket=BUCKET)
        logging.info(f"GetBucketTagging succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketTagging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_bucket_versioning(s3):
    try:
        response = s3.get_bucket_versioning(Bucket=BUCKET)
        logging.info(f"GetBucketVersioning succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketVersioning failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_bucket_website(s3):
    try:
        response = s3.get_bucket_website(Bucket=BUCKET)
        logging.info(f"GetBucketWebsite succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetBucketWebsite failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_lifecycle_configuration(s3):
    try:
        response = s3.get_bucket_lifecycle_configuration(Bucket=BUCKET)
        logging.info(f"GetLifecycleConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetLifecycleConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def get_object_acl(s3):
    try:
        response = s3.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
        logging.info(f"GetObjectAcl succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info(f"GetObjectAcl from object_owner")
        # response = s3_main_object_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
        # logging.info(f"GetObjectAcl succeeded: {response}")
    except ClientError as e:
        logging.error(f"GetObjectAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info(f"GetObjectAcl from object_owner")
        # response = s3_main_object_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
        # logging.info(f"GetObjectAcl succeeded: {response}")
    # try:
    #     logging.info(f"GetObjectAcl from object_owner")
    #     response = s3_main_object_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
    #     logging.info(f"GetObjectAcl succeeded: {response}")
    # except ClientError as e:
    #     logging.error(f"GetObjectAcl failed from object_owner: {e}")
    # try:
    #     logging.info(f"GetObjectAcl from bucket_owner")
    #     response = s3_main.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY)
    #     logging.info(f"GetObjectAcl succeeded: {response}")
    # except ClientError as e:
    #     logging.error(f"GetObjectAcl failed from bucket_owner: {e}")


def get_object(s3):
    multipart_obj_name = f"{OBJECT_KEY}_multi"
    try:
        response = s3.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
        content = response['Body'].read().decode('utf-8')
        logging.info(f"GetObject succeeded for {OBJECT_KEY}: {content}")
        response = s3.get_object(Bucket=BUCKET, Key=multipart_obj_name)
        content = response['Body'].read().decode('utf-8')
        logging.info(f"GetObject succeeded for {multipart_obj_name}: {content}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info(f"GetObject from object_owner")
        # response = s3_main_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
        # logging.info(f"GetObject succeeded: {response}")
    except ClientError as e:
        logging.error(f"GetObject failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info(f"GetObject from object_owner")
        # response = s3_main_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
        # logging.info(f"GetObject succeeded: {response}")
    # try:
    #     logging.info(f"GetObject from object_owner")
    #     response = s3_main_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
    #     content = response['Body'].read().decode('utf-8')
    #     logging.info(f"GetObject succeeded for {OBJECT_KEY}: {content}")
    #     response = s3_main_object_owner.get_object(Bucket=BUCKET, Key=multipart_obj_name)
    #     content = response['Body'].read().decode('utf-8')
    #     logging.info(f"GetObject succeeded for {multipart_obj_name}: {content}")
    # except ClientError as e:
    #     logging.error(f"GetObject failed from object_owner: {e}")
    # try:
    #     logging.info(f"GetObject from bucket_owner")
    #     response = s3_main.get_object(Bucket=BUCKET, Key=OBJECT_KEY)
    #     content = response['Body'].read().decode('utf-8')
    #     logging.info(f"GetObject succeeded for {OBJECT_KEY}: {content}")
    #     response = s3_main.get_object(Bucket=BUCKET, Key=multipart_obj_name)
    #     content = response['Body'].read().decode('utf-8')
    #     logging.info(f"GetObject succeeded for {multipart_obj_name}: {content}")
    # except ClientError as e:
    #     logging.error(f"GetObject failed from bucket_owner: {e}")








def get_object_version_acl(s3):
    versions = s3_main.list_object_versions(Bucket=BUCKET, Prefix=OBJECT_KEY)
    print(versions)
    if versions.get('Versions'):
        version_id = versions['Versions'][0]['VersionId']
    else:
        raise Exception("versions empty")
    try:
        response = s3.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
        logging.info(f"GetObjectVersionAcl succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except Exception as e:
        logging.error(f"GetObjectVersionAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    # try:
    #     logging.info(f"GetObjectVersionAcl from object_owner")
    #     response = s3_main_object_owner.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
    #     logging.info(f"GetObjectVersionAcl succeeded: {response}")
    # except Exception as e:
    #     logging.error(f"GetObjectVersionAcl failed from object_owner: {e}")
    # try:
    #     logging.info(f"GetObjectVersionAcl from bucket_owner")
    #     response = s3_main.get_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
    #     logging.info(f"GetObjectVersionAcl succeeded: {response}")
    # except Exception as e:
    #     logging.error(f"GetObjectVersionAcl failed from bucket_owner: {e}")

def get_object_version(s3):
    versions = s3_main.list_object_versions(Bucket=BUCKET, Prefix=OBJECT_KEY)
    version_id = ""
    if versions.get('Versions'):
        version_id = versions['Versions'][0]['VersionId']
    else:
        raise Exception("versions empty")
    try:
        response = s3.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
        content = response['Body'].read().decode('utf-8')
        logging.info(f"GetObjectVersion succeeded for {OBJECT_KEY}: {content}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info(f"GetObjectVersion from object_owner")
        # response = s3_main_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
        # logging.info(f"GetObjectVersion succeeded: {response}")
    except Exception as e:
        logging.error(f"GetObjectVersion failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info(f"GetObjectVersion from object_owner")
        # response = s3_main_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
        # logging.info(f"GetObjectVersion succeeded: {response}")
    # try:
    #     logging.info(f"GetObjectVersion from object_owner")
    #     response = s3_main_object_owner.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
    #     content = response['Body'].read().decode('utf-8')
    #     logging.info(f"GetObjectVersion succeeded for {OBJECT_KEY}: {content}")
    # except Exception as e:
    #     logging.error(f"GetObjectVersion failed from object_owner: {e}")
    # try:
    #     if versions.get('Versions'):
    #         version_id = versions['Versions'][0]['VersionId']
    #     else:
    #         raise Exception("versions empty")
    #     logging.info(f"GetObjectVersion from bucket_owner")
    #     response = s3_main.get_object(Bucket=BUCKET, Key=OBJECT_KEY, VersionId=version_id)
    #     content = response['Body'].read().decode('utf-8')
    #     logging.info(f"GetObjectVersion succeeded for {OBJECT_KEY}: {content}")
    # except Exception as e:
    #     logging.error(f"GetObjectVersion failed from bucket_owner: {e}")


def put_replication_configuration(s3):
    try:
        replication_config = {
            'Role': replication_role_arn,
            'Rules': [
                {
                    'ID': "replication-rule-1",
                    'Status': 'Enabled',
                    'Priority': 1,
                    'Filter': {
                        'Prefix': ''
                    },
                    'Destination': {
                        'Bucket': destination_bucket_arn,
                        'StorageClass': 'STANDARD'
                    },
                    'DeleteMarkerReplication': {
                        'Status': 'Disabled'
                    }
                }
            ]
        }

        response = s3.put_bucket_replication(
            Bucket=BUCKET,
            ReplicationConfiguration=replication_config
        )
        logging.info(f"PutReplicationConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutReplicationConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def get_replication_configuration(s3):
    try:
        response = s3.get_bucket_replication(Bucket=BUCKET)
        logging.info(f"GetReplicationConfiguration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"GetReplicationConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_replication_configuration(s3):
    try:
        s3.delete_bucket_replication(Bucket=BUCKET)
        logging.info("DeleteReplicationConfiguration succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"DeleteReplicationConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def list_all_my_buckets(s3):
    try:
        response = s3.list_buckets()
        buckets = [b['Name'] for b in response['Buckets']]
        logging.info(f"ListAllMyBuckets succeeded: {buckets}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"ListAllMyBuckets failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def list_bucket_multipart_uploads(s3):
    try:
        response = s3.list_multipart_uploads(Bucket=BUCKET)
        logging.info(f"ListBucketMultipartUploads succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"ListBucketMultipartUploads failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def list_bucket(s3):
    try:
        response = s3.list_objects_v2(Bucket=BUCKET)
        logging.info(f"ListBucket succeeded: {response.get('Contents', [])}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"ListBucket failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def list_bucket_versions(s3):
    try:
        response = s3.list_object_versions(Bucket=BUCKET)
        logging.info(f"ListBucketVersions succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"ListBucketVersions failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def list_multipart_upload_parts(s3_client):
    try:
        multipart_obj_name = f"{OBJECT_KEY}_multi2"
        upload = s3_main.create_multipart_upload(Bucket=BUCKET, Key=multipart_obj_name)
        upload_id = upload['UploadId']
        # Upload one part to generate a part listing
        s3_main.upload_part(Bucket=BUCKET, Key=multipart_obj_name, PartNumber=1, UploadId=upload_id, Body='Part 1')
        response = s3_client.list_parts(Bucket=BUCKET, Key=multipart_obj_name, UploadId=upload_id)
        logging.info(f"ListMultipartUploadParts succeeded: {response}")
        # s3.abort_multipart_upload(Bucket=BUCKET, Key=multipart_obj_name, UploadId=upload_id)
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"ListMultipartUploadParts failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def put_bucket_acl(s3):
    try:
        s3.put_bucket_acl(Bucket=BUCKET, ACL='private')
        logging.info("PutBucketAcl succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutBucketAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def put_bucket_cors(s3):
    cors_config = {
        'CORSRules': [{
            'AllowedHeaders': ['*'],
            'AllowedMethods': ['GET', 'PUT'],
            'AllowedOrigins': ['*'],
            'ExposeHeaders': ['ETag'],
            'MaxAgeSeconds': 3000
        }]
    }
    try:
        s3.put_bucket_cors(Bucket=BUCKET, CORSConfiguration=cors_config)
        logging.info("PutBucketCORS succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutBucketCORS failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("PutBucketCORS with bucket_owner")
        s3_main.put_bucket_cors(Bucket=BUCKET, CORSConfiguration=cors_config)







def put_bucket_logging(s3):
    try:
        s3.put_bucket_logging(
            Bucket=BUCKET,
            BucketLoggingStatus={
                'LoggingEnabled': {
                    'TargetBucket': BUCKET,
                    'TargetPrefix': 'logs/'
                }
            }
        )
        logging.info("PutBucketLogging succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutBucketLogging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def put_bucket_notification(s3):
    try:
        s3.put_bucket_notification_configuration(
            Bucket=BUCKET,
            NotificationConfiguration={
                'TopicConfigurations': []
            }
        )
        logging.info("PutBucketNotification succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutBucketNotification failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("PutBucketNotification with bucket_owner")
        s3_main.put_bucket_notification_configuration(
            Bucket=BUCKET,
            NotificationConfiguration={
                'TopicConfigurations': []
            }
        )

def put_bucket_policy(s3):
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*"
        }]
    }
    try:
        s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(policy))
        logging.info("PutBucketPolicy succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutBucketPolicy failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("PutBucketPolicy with bucket_owner")
        s3_main.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(policy))

def put_bucket_tagging(s3):
    try:
        s3.put_bucket_tagging(
            Bucket=BUCKET,
            Tagging={
                'TagSet': [
                    {'Key': 'Environment', 'Value': 'Test'}
                ]
            }
        )
        logging.info("PutBucketTagging succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutBucketTagging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("PutBucketTagging with bucket_owner")
        s3_main.put_bucket_tagging(
            Bucket=BUCKET,
            Tagging={
                'TagSet': [
                    {'Key': 'Environment', 'Value': 'Test'}
                ]
            }
        )

def put_bucket_versioning(s3):
    try:
        s3.put_bucket_versioning(
            Bucket=BUCKET,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        logging.info("PutBucketVersioning succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutBucketVersioning failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("PutBucketVersioning with bucket_owner")
        s3_main.put_bucket_versioning(
            Bucket=BUCKET,
            VersioningConfiguration={'Status': 'Enabled'}
        )

def put_bucket_website(s3):
    try:
        s3.put_bucket_website(
            Bucket=BUCKET,
            WebsiteConfiguration={
                'IndexDocument': {'Suffix': 'index_resource.html'},
                'ErrorDocument': {'Key': 'error.html'}
            }
        )
        logging.info("PutBucketWebsite succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutBucketWebsite failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("PutBucketWebsite with bucket_owner")
        s3_main.put_bucket_website(
            Bucket=BUCKET,
            WebsiteConfiguration={
                'IndexDocument': {'Suffix': 'index_resource.html'},
                'ErrorDocument': {'Key': 'error.html'}
            }
        )

def put_lifecycle_configuration(s3):
    try:
        s3.put_bucket_lifecycle_configuration(
            Bucket=BUCKET,
            LifecycleConfiguration={
                'Rules': [{
                    'ID': 'ExpireOldObjects',
                    'Prefix': '',
                    'Status': 'Enabled',
                    'Expiration': {'Days': 30}
                }]
            }
        )
        logging.info("PutLifecycleConfiguration succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutLifecycleConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("PutLifecycleConfiguration with bucket_owner")
        s3_main.put_bucket_lifecycle_configuration(
            Bucket=BUCKET,
            LifecycleConfiguration={
                'Rules': [{
                    'ID': 'ExpireOldObjects',
                    'Prefix': '',
                    'Status': 'Enabled',
                    'Expiration': {'Days': 30}
                }]
            }
        )

def put_object_acl(s3):
    try:
        s3.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL='private')
        logging.info("PutObjectAcl succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info("PutObjectAcl from object_owner")
        # s3_main_object_owner.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL='private')
    except ClientError as e:
        logging.error(f"PutObjectAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info("PutObjectAcl from object_owner")
        # s3_main_object_owner.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL='private')
    # try:
    #     logging.info("PutObjectAcl from object_owner")
    #     s3_main_object_owner.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL='private')
    #     logging.info("PutObjectAcl succeeded")
    # except ClientError as e:
    #     logging.error(f"PutObjectAcl failed from object_owner: {e}")
    # try:
    #     logging.info("PutObjectAcl from bucket_owner")
    #     s3_main.put_object_acl(Bucket=BUCKET, Key=OBJECT_KEY, ACL='private')
    #     logging.info("PutObjectAcl succeeded")
    # except ClientError as e:
    #     logging.error(f"PutObjectAcl failed from bucket_owner: {e}")

def put_object(s3):
    try:
        logging.info(f"uploading object {OBJECT_KEY} into bucket {BUCKET}")
        s3.put_object(Bucket=BUCKET, Key=OBJECT_KEY, Body=open("/home/cephuser/obj9KB", "rb"))
        # s3_main.put_object(Bucket=BUCKET, Key=OBJECT_KEY, Body='Sample content')
        logging.info("PutObject succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutObject failed: {e}")
        logging.info(f"uploading object with bucket owner")
        s3_main.put_object(Bucket=BUCKET, Key=OBJECT_KEY, Body='Sample content')
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def put_object_version_acl(s3):
    versions = s3_main.list_object_versions(Bucket=BUCKET, Prefix=OBJECT_KEY)
    try:
        for version in versions.get('Versions', []):
            logging.info(f"PutObjectVersionAcl for {version['Key']} for version {version['VersionId']}")
            s3.put_object_acl(Bucket=BUCKET, Key=version['Key'], VersionId=version['VersionId'], ACL='private')
        logging.info(f"PutObjectVersionAcl succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutObjectVersionAcl failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    # try:
    #     logging.info(f"PutObjectVersionAcl from object_owner")
    #     for version in versions.get('Versions', []):
    #         logging.info(f"PutObjectVersionAcl for {version['Key']} for version {version['VersionId']}")
    #         s3_main_object_owner.put_object_acl(Bucket=BUCKET, Key=version['Key'], VersionId=version['VersionId'], ACL='private')
    #     logging.info(f"PutObjectVersionAcl succeeded")
    # except ClientError as e:
    #     logging.error(f"PutObjectVersionAcl failed from object_owner: {e}")
    # try:
    #     logging.info(f"PutObjectVersionAcl from bucket_owner")
    #     for version in versions.get('Versions', []):
    #         logging.info(f"PutObjectVersionAcl for {version['Key']} for version {version['VersionId']}")
    #         s3_main.put_object_acl(Bucket=BUCKET, Key=version['Key'], VersionId=version['VersionId'], ACL='private')
    #     logging.info(f"PutObjectVersionAcl succeeded")
    # except ClientError as e:
    #     logging.error(f"PutObjectVersionAcl failed from bucket_owner: {e}")


def restore_object(s3):
    try:
        s3.restore_object(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            RestoreRequest={'Days': 1, 'GlacierJobParameters': {'Tier': 'Standard'}}
        )
        logging.info("RestoreObject succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"RestoreObject failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))










def copy_object(s3):
    try:
        s3.copy_object(Bucket=BUCKET, CopySource={'Bucket': BUCKET, 'Key': OBJECT_KEY}, Key=f"{OBJECT_KEY}_copy")
        logging.info("copy_object succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"copy_object failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def multipart_upload(s3):
    multipart_obj_name = f"{OBJECT_KEY}_multi"
    try:
        response = s3.create_multipart_upload(Bucket=BUCKET, Key=multipart_obj_name)
        upload_id = response['UploadId']
        part1 = s3.upload_part(Bucket=BUCKET, Key=multipart_obj_name, PartNumber=1, UploadId=upload_id, Body=open("/home/cephuser/obj12MB.parts/aa", mode="rb"))
        part2 = s3.upload_part(Bucket=BUCKET, Key=multipart_obj_name, PartNumber=2, UploadId=upload_id, Body=open("/home/cephuser/obj12MB.parts/ab", mode="rb"))
        s3.complete_multipart_upload(Bucket=BUCKET, Key=multipart_obj_name, UploadId=upload_id,
            MultipartUpload={'Parts': [{'ETag': part1['ETag'], 'PartNumber': 1}, {'ETag': part2['ETag'], 'PartNumber': 2}]})
        logging.info("multipart_upload succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"multipart_upload failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.error(f"multipart_upload with bucket owner")
        response = s3_main.create_multipart_upload(Bucket=BUCKET, Key=multipart_obj_name)
        upload_id = response['UploadId']
        part = s3_main.upload_part(Bucket=BUCKET, Key=multipart_obj_name, PartNumber=1, UploadId=upload_id, Body='part1')
        s3_main.complete_multipart_upload(Bucket=BUCKET, Key=multipart_obj_name, UploadId=upload_id,
                                     MultipartUpload={'Parts': [{'ETag': part['ETag'], 'PartNumber': 1}]})



# def delete_objects(s3):
#     try:
#         s3.delete_objects(Bucket=BUCKET, Delete={'Objects': [{'Key': OBJECT_KEY},{'Key': f"{OBJECT_KEY}_copy"}, {'Key': f"{OBJECT_KEY}_multi"}]})
#         logging.info("delete_objects succeeded")
#     except ClientError as e:
#         logging.error(f"delete_objects failed: {e}")
#         FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def delete_objects(s3):
    paginator = s3_main.get_paginator('list_object_versions')
    delete_list = []
    time.sleep(3)

    for page in paginator.paginate(Bucket=BUCKET):
        versions = page.get('Versions', []) + page.get('DeleteMarkers', [])
        for version in versions:
            delete_list.append({
                'Key': version['Key'],
                'VersionId': version['VersionId']
            })
    print(f"delete_list: {delete_list}")
    # raise Exception(f"\nstop the flow.")
    try:
        if delete_list:
            response = s3.delete_objects(
                Bucket=BUCKET,
                Delete={
                    'Objects': delete_list,
                    'Quiet': False
                }
            )
            if 'Errors' in response and response['Errors']:
                error_messages = [
                    f"Key: {error['Key']}, Code: {error['Code']}, Message: {error['Message']}"
                    for error in response['Errors']
                ]
                raise Exception(f"One or more object deletions failed: {'; '.join(error_messages)}")
            print(f"Deleted {len(delete_list)} object versions from bucket '{BUCKET}'. response:{response}")
        else:
            print("No object versions found to delete.")
        logging.info("delete_objects succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except Exception as e:
        logging.error(f"delete_objects failed: {e}")
        logging.error(f"deleting objects with bucket owner")
        if delete_list:
            response = s3_main.delete_objects(
                Bucket=BUCKET,
                Delete={
                    'Objects': delete_list,
                    'Quiet': False
                }
            )
            if 'Errors' in response and response['Errors']:
                error_messages = [
                    f"Key: {error['Key']}, Code: {error['Code']}, Message: {error['Message']}"
                    for error in response['Errors']
                ]
                raise Exception(f"One or more object deletions failed: {'; '.join(error_messages)}")
            print(f"Deleted {len(delete_list)} object versions from bucket '{BUCKET}'. response:{response}")
        else:
            print("No object versions found to delete.")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_bucket_encryption(s3):
    try:
        s3.put_bucket_encryption(Bucket=BUCKET,
            ServerSideEncryptionConfiguration={'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]})
        logging.info("put_bucket_encryption succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"put_bucket_encryption failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("put_bucket_encryption with bucket_owner")
        s3_main.put_bucket_encryption(Bucket=BUCKET,
            ServerSideEncryptionConfiguration={'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]})

def get_bucket_encryption(s3):
    try:
        response = s3.get_bucket_encryption(Bucket=BUCKET)
        logging.info(f"get_bucket_encryption succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"get_bucket_encryption failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def delete_bucket_encryption(s3):
    try:
        s3.delete_bucket_encryption(Bucket=BUCKET)
        logging.info("delete_bucket_encryption succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"delete_bucket_encryption failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("delete_bucket_encryption with bucket_owner")
        s3_main.delete_bucket_encryption(Bucket=BUCKET)

def put_public_access_block(s3):
    try:
        s3.put_public_access_block(Bucket=BUCKET,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            })
        logging.info("put_public_access_block succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"put_public_access_block failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("put_public_access_block with bucket_owner")
        s3_main.put_public_access_block(Bucket=BUCKET,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            })

def get_public_access_block(s3):
    try:
        response = s3.get_public_access_block(Bucket=BUCKET)
        logging.info(f"get_public_access_block succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"get_public_access_block failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def delete_public_access_block(s3):
    try:
        s3.delete_public_access_block(Bucket=BUCKET)
        logging.info("delete_public_access_block succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"delete_public_access_block failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("delete_public_access_block with bucket_owner")
        s3_main.delete_public_access_block(Bucket=BUCKET)

def head_bucket(s3):
    try:
        s3.head_bucket(Bucket=BUCKET)
        logging.info("head_bucket succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"head_bucket failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def head_object(s3):
    try:
        s3.head_object(Bucket=BUCKET, Key=OBJECT_KEY)
        logging.info("head_object succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"head_object failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def list_object_versions(s3):
    try:
        response = s3.list_object_versions(Bucket=BUCKET)
        logging.info(f"list_object_versions succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"list_object_versions failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def list_objects(s3):
    try:
        response = s3.list_objects(Bucket=BUCKET)
        logging.info(f"list_objects succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"list_objects failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))

def list_objects_v2(s3):
    try:
        response = s3.list_objects_v2(Bucket=BUCKET)
        logging.info(f"list_objects_v2 succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"list_objects_v2 failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))




def select_object_content(s3):
    try:
        response = s3.select_object_content(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            ExpressionType='SQL',
            Expression="SELECT * FROM S3Object",
            InputSerialization={'CSV': {}, 'CompressionType': 'NONE'},
            OutputSerialization={'CSV': {}}
        )
        for event in response['Payload']:
            if 'Records' in event:
                logging.info(f"select_object_content succeeded: {event['Records']['Payload']}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"select_object_content failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_object_tagging(s3_client):
    # Define the tags you want to apply
    tags = [
        {'Key': 'Environment', 'Value': 'Development'},
        {'Key': 'Project', 'Value': 'MyApplication'}
    ]

    try:
        response = s3_client.put_object_tagging(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            Tagging={
                'TagSet': tags
            }
        )
        logging.info(f"put_object_tagging succeeded, response: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"put_object_tagging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    # try:
    #     logging.info(f"put_object_tagging from object_owner")
    #     response = s3_main_object_owner.put_object_tagging(
    #         Bucket=BUCKET,
    #         Key=OBJECT_KEY,
    #         Tagging={
    #             'TagSet': tags
    #         }
    #     )
    #     logging.info(f"put_object_tagging succeeded, response: {response}")
    # except ClientError as e:
    #     logging.error(f"put_object_tagging failed from object_owner: {e}")
    # try:
    #     logging.info(f"put_object_tagging from bucket_owner")
    #     response = s3_main.put_object_tagging(
    #         Bucket=BUCKET,
    #         Key=OBJECT_KEY,
    #         Tagging={
    #             'TagSet': tags
    #         }
    #     )
    #     logging.info(f"put_object_tagging succeeded, response: {response}")
    # except ClientError as e:
    #     logging.error(f"put_object_tagging failed from bucket_owner: {e}")


def get_object_tagging(s3):
    try:
        response = s3.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
        logging.info(f"get_object_tagging succeeded: {response['TagSet']}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info(f"get_object_tagging from object_owner")
        # response = s3_main_object_owner.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
        # logging.info(f"get_object_tagging succeeded: {response}")
    except ClientError as e:
        logging.error(f"get_object_tagging failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info(f"get_object_tagging from object_owner")
        # response = s3_main_object_owner.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
        # logging.info(f"get_object_tagging succeeded: {response}")
    # try:
    #     logging.info(f"get_object_tagging from object_owner")
    #     response = s3_main_object_owner.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
    #     logging.info(f"get_object_tagging succeeded: {response['TagSet']}")
    # except ClientError as e:
    #     logging.error(f"get_object_tagging failed from object_owner: {e}")
    # try:
    #     logging.info(f"get_object_tagging from bucket_owner")
    #     response = s3_main.get_object_tagging(Bucket=BUCKET, Key=OBJECT_KEY)
    #     logging.info(f"get_object_tagging succeeded: {response['TagSet']}")
    # except ClientError as e:
    #     logging.error(f"get_object_tagging failed from bucket_owner: {e}")


def get_object_attributes(s3):
    try:
        response = s3.get_object_attributes(
            Bucket=BUCKET,
            Key=OBJECT_KEY,
            ObjectAttributes=['ETag', 'ObjectSize', 'Size', 'ObjectParts', 'Checksum']
        )
        logging.info(f"get_object_attributes succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"get_object_attributes failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))





def put_object_lock_configuration(s3):
    try:
        response = s3.put_object_lock_configuration(
            Bucket=BUCKET,
            ObjectLockConfiguration={
                'ObjectLockEnabled': 'Enabled',
                'Rule': {
                    'DefaultRetention': {
                        'Mode': 'GOVERNANCE',
                        'Days': 30
                    }
                }
            }
        )
        logging.info("PutObjectLockConfiguration succeeded")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"PutObjectLockConfiguration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        logging.info("PutObjectLockConfiguration with bucket_owner")
        s3_main.put_object_lock_configuration(
            Bucket=BUCKET,
            ObjectLockConfiguration={
                'ObjectLockEnabled': 'Enabled',
                'Rule': {
                    'DefaultRetention': {
                        'Mode': 'GOVERNANCE',
                        'Days': 30
                    }
                }
            }
        )


def get_object_lock_configuration(s3):
    try:
        response = s3.get_object_lock_configuration(Bucket=BUCKET)
        logging.info(f"get_object_lock_configuration succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"get_object_lock_configuration failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def put_object_legal_hold(s3,hold_status='ON'):
    try:
        response = s3.put_object_legal_hold(
            Bucket=BUCKET, Key=OBJECT_KEY,
            LegalHold={
                'Status': hold_status  # 'ON' or 'OFF'
            }
        )
        print(f"put_object_legal_hold succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        print(f"put_object_legal_hold failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info("put_object_legal_hold with bucket_owner")
        # s3_main.put_object_legal_hold(
        #     Bucket=BUCKET, Key=OBJECT_KEY,
        #     LegalHold={
        #         'Status': hold_status  # 'ON' or 'OFF'
        #     }
        # )


def get_object_legal_hold(s3):
    try:
        response = s3.get_object_legal_hold(Bucket=BUCKET, Key=OBJECT_KEY)
        logging.info(f"get_object_legal_hold succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"get_object_legal_hold failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def remove_object_legal_hold(s3):
    try:
        response = s3.put_object_legal_hold(
            Bucket=BUCKET, Key=OBJECT_KEY,
            LegalHold={
                'Status': 'OFF'
            }
        )
        print(f"remove_object_legal_hold with put_object_legal_hold succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        print(f"remove_object_legal_hold with put_object_legal_hold failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info("remove_object_legal_hold with bucket_owner")
        # s3_main.put_object_legal_hold(
        #     Bucket=BUCKET, Key=OBJECT_KEY,
        #     LegalHold={
        #         'Status': 'OFF'
        #     }
        # )



def put_object_retention(s3, retention_mode='GOVERNANCE', days=30):
    retain_until = datetime.utcnow() + timedelta(days=days)
    try:
        response = s3.put_object_retention(
            Bucket=BUCKET, Key=OBJECT_KEY,
            Retention={
                'Mode': retention_mode,  # 'GOVERNANCE' or 'COMPLIANCE'
                'RetainUntilDate': retain_until
            },
            BypassGovernanceRetention=False  # Set to True if you have permission to bypass
        )
        print(f"put_object_retention succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        print(f"put_object_retention failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info("put_object_retention with bucket_owner")
        # s3_main.put_object_retention(
        #     Bucket=BUCKET, Key=OBJECT_KEY,
        #     Retention={
        #         'Mode': retention_mode,  # 'GOVERNANCE' or 'COMPLIANCE'
        #         'RetainUntilDate': retain_until
        #     },
        #     BypassGovernanceRetention=False  # Set to True if you have permission to bypass
        # )



def get_object_retention(s3):
    try:
        response = s3.get_object_retention(Bucket=BUCKET, Key=OBJECT_KEY)
        logging.info(f"get_object_retention succeeded: {response}")
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        logging.error(f"get_object_retention failed: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))


def remove_object_retention(s3):
    try:
        response = s3.put_object_retention(
            Bucket=BUCKET, Key=OBJECT_KEY,
            Retention={
                'Mode': 'GOVERNANCE',
                'RetainUntilDate': datetime.utcnow() + timedelta(seconds=3)
            },
            BypassGovernanceRetention=True
        )
        print(f"remove_object_retention with put_object_retention succeeded: {response}")
        time.sleep(3)
        PASSED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
    except ClientError as e:
        print(f"Error removing retention: {e}")
        FAILED_ACTIONS.append(str(inspect.currentframe().f_code.co_name))
        # logging.info("remove_object_retention with bucket_owner")
        # s3_main.put_object_retention(
        #     Bucket=BUCKET, Key=OBJECT_KEY,
        #     Retention={
        #         'Mode': 'GOVERNANCE',
        #         'RetainUntilDate': datetime.utcnow() + timedelta(seconds=3)
        #     },
        #     BypassGovernanceRetention=True
        # )


# Setup logging
logging.basicConfig(level=logging.INFO)

# setup actions and resource db

BUCKET_ACTIONS = [
    "create_bucket",
    "delete_bucket",
    "delete_bucket_encryption",
    "delete_bucket_policy",
    "delete_bucket_website",
    "delete_public_access_block",
    "delete_replication_configuration",
    "get_accelerate_configuration",
    "get_bucket_acl",
    "get_bucket_cors",
    "get_bucket_encryption",
    "get_bucket_location",
    "get_bucket_logging",
    "get_bucket_notification",
    "get_bucket_policy",
    "get_bucket_request_payment",
    "get_bucket_tagging",
    "get_bucket_versioning",
    "get_bucket_website",
    "get_lifecycle_configuration",
    "get_object_lock_configuration",
    "get_public_access_block",
    "get_replication_configuration",
    "head_bucket",
    # "list_bucket",
    "list_bucket_multipart_uploads",
    # "list_bucket_versions",
    "list_object_versions",
    "list_objects",
    "list_objects_v2",
    "put_bucket_acl",
    "put_bucket_cors",
    "put_bucket_encryption",
    # "put_bucket_logging",
    "put_bucket_notification",
    "put_bucket_policy",
    "put_bucket_tagging",
    "put_bucket_versioning",
    "put_bucket_website",
    "put_lifecycle_configuration",
    "put_object_lock_configuration",
    "put_public_access_block"
]

OBJECT_ACTIONS = [
    "abort_multipart_upload",
    "copy_object",
    "delete_object",
    "delete_object_version",
    "delete_objects",
    "get_object",
    "get_object_acl",
    "get_object_attributes",
    "get_object_legal_hold",
    "get_object_retention",
    "get_object_tagging",
    "put_object_tagging",
    "get_object_version",
    "get_object_version_acl",
    "head_object",
    "list_multipart_upload_parts",
    "multipart_upload",
    "put_object",
    "put_object_acl",
    "put_object_legal_hold",
    "put_object_retention",
    "put_object_version_acl",
    "remove_object_legal_hold",
    "remove_object_retention",
    # "restore_object",
    "select_object_content"
]

GLOBAL_ACTIONS = [
    "list_all_my_buckets"
]

all_actions = BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS


s3_action_allowed_methods = {
    "s3:AbortMultipartUpload": ["abort_multipart_upload"],
    "s3:CreateBucket": ["create_bucket"],
    "s3:DeleteBucketPolicy": ["delete_bucket_policy"],
    "s3:DeleteBucket": ["delete_bucket"],
    "s3:DeleteBucketWebsite": ["delete_bucket_website"],
    "s3:DeleteObject": ["delete_object"],
    "s3:DeleteObjectVersion": ["delete_object_version", "delete_objects"],
    "s3:DeleteReplicationConfiguration": ["delete_replication_configuration"],
    "s3:GetAccelerateConfiguration": ["get_accelerate_configuration"],
    "s3:GetBucketAcl": ["get_bucket_acl"],
    "s3:GetBucketCORS": ["get_bucket_cors"],
    "s3:GetBucketLocation": ["get_bucket_location"],
    "s3:GetBucketLogging": ["get_bucket_logging"],
    "s3:GetBucketNotification": ["get_bucket_notification"],
    "s3:GetBucketPolicy": ["get_bucket_policy"],
    "s3:GetBucketRequestPayment": ["get_bucket_request_payment"],
    "s3:GetBucketTagging": ["get_bucket_tagging"],
    "s3:GetBucketVersioning": ["get_bucket_versioning"],
    "s3:GetBucketWebsite": ["get_bucket_website"],
    "s3:GetLifecycleConfiguration": ["get_lifecycle_configuration"],
    # "s3:GetObjectAcl": ["get_object_acl"],
    "s3:GetObjectAcl": [],
    # "s3:GetObject": ["get_object"],
    "s3:GetObject": [],
    "s3:GetObjectVersion": ["get_object_version", "get_object", "get_object_attributes", "head_object", "select_object_content", "copy_object"],
    # "s3:GetObjectVersion": ["get_object_version", "get_object", "head_object", "select_object_content"],
    # "s3:GetObjectAttributes": ["get_object_attributes"],
    "s3:GetObjectAttributes": [],
    # "s3:GetObjectVersionAttributes": ["get_object_attributes"],
    "s3:GetObjectVersionAttributes": [],
    # "s3:GetObjectTorrent": [],
    "s3:GetObjectVersionAcl": ["get_object_version_acl", "get_object_acl"],
    # "s3:GetObjectVersionTorrent": [],
    "s3:GetReplicationConfiguration": ["get_replication_configuration"],
    # "s3:IPAddress": [],
    # "s3:NotIpAddress": [],
    "s3:ListAllMyBuckets": ["list_all_my_buckets"],
    "s3:ListBucketMultipartUploads": ["list_bucket_multipart_uploads"],
    # "s3:ListBucket": ["list_bucket"],
    "s3:ListBucket": ["head_bucket", "list_objects", "list_objects_v2"],
    # "s3:ListBucketVersions": ["list_bucket_versions"],
    "s3:ListBucketVersions": ["list_object_versions"],
    "s3:ListMultipartUploadParts": ["list_multipart_upload_parts"],
    "s3:PutAccelerateConfiguration": [],
    "s3:PutBucketAcl": ["put_bucket_acl"],
    "s3:PutBucketCORS": ["put_bucket_cors"],
    # "s3:PutBucketLogging": ["put_bucket_logging"],
    "s3:PutBucketLogging": [],
    "s3:PutBucketNotification": ["put_bucket_notification"],
    "s3:PutBucketPolicy": ["put_bucket_policy"],
    "s3:PutBucketRequestPayment": [],
    "s3:PutBucketTagging": ["put_bucket_tagging"],
    "s3:PutBucketVersioning": ["put_bucket_versioning"],
    "s3:PutBucketWebsite": ["put_bucket_website"],
    "s3:PutLifecycleConfiguration": ["put_lifecycle_configuration"],
    # "s3:PutObjectAcl": ["put_object_acl"],
    "s3:PutObjectAcl": [],
    "s3:PutObjectVersionAcl": ["put_object_version_acl", "put_object_acl"],
    # "s3:PutObject": ["put_object", "multipart_upload", "copy_object"],
    "s3:PutObject": ["put_object", "multipart_upload"],
    "s3:PutReplicationConfiguration": [],
    "s3:RestoreObject": ["restore_object"]
}




s3_action_required_resource = {
    "s3:AbortMultipartUpload": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:CreateBucket": [
        "arn_access_all_buckets_and_objects",
        # "arn_access_only_the_bucket"
    ],
    "s3:DeleteBucketPolicy": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:DeleteBucket": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:DeleteBucketWebsite": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:DeleteObject": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:DeleteObjectVersion": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:DeleteReplicationConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetAccelerateConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketCORS": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketLocation": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketLogging": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketNotification": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketPolicy": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketRequestPayment": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketTagging": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketVersioning": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetBucketWebsite": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetLifecycleConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:GetObject": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:GetObjectVersion": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:GetObjectAttributes": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:GetObjectVersionAttributes": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:GetObjectAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:GetObjectVersionAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    # "s3:GetObjectTorrent": [
    #     "arn_access_all_buckets_and_objects",
    #     "arn_access_all_objects_under_all_buckets",
    #     "arn_access_only_the_bucket",
    #     "arn_access_all_objects_under_the_bucket"
    # ],
    # "s3:GetObjectVersionTorrent": [
    #     "arn_access_all_buckets_and_objects",
    #     "arn_access_all_objects_under_all_buckets",
    #     "arn_access_only_the_bucket",
    #     "arn_access_all_objects_under_the_bucket"
    # ],
    "s3:GetReplicationConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    # "s3:IPAddress": [
    #     "arn_access_all_buckets_and_objects"
    # ],
    # "s3:NotIpAddress": [
    #     "arn_access_all_buckets_and_objects"
    # ],
    "s3:ListAllMyBuckets": [
        "arn_access_all_buckets_and_objects"
    ],
    "s3:ListBucketMultipartUploads": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:ListBucket": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:ListBucketVersions": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:ListMultipartUploadParts": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:PutAccelerateConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutBucketAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutBucketCORS": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutBucketLogging": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutBucketNotification": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutBucketPolicy": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutBucketRequestPayment": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutBucketTagging": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutBucketVersioning": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutBucketWebsite": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:PutLifecycleConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket",
    ],
    "s3:PutObjectAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:PutObjectVersionAcl": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:PutObject": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ],
    "s3:PutReplicationConfiguration": [
        "arn_access_all_buckets_and_objects",
        "arn_access_only_the_bucket"
    ],
    "s3:RestoreObject": [
        "arn_access_all_buckets_and_objects",
        "arn_access_all_objects_under_all_buckets",
        "arn_access_all_objects_under_the_bucket",
        "arn_pseudo_directory_access"
    ]
}


FAILED_ACTIONS = []
PASSED_ACTIONS = []

s3_main = None

BUCKET = None
OBJECT_KEY = None


def test_sts_policy_permutations(user1, user2, user3, ssh_con, config):

    # Generate a random string of 5 characters
    characters = string.ascii_lowercase + string.digits
    random_string = ''.join(random.choice(characters) for i in range(5))

    auth1 = Auth(user1, ssh_con, ssl=config.ssl)
    iam = auth1.do_auth_iam_client()
    s3_main = auth1.do_auth_using_client()

    auth2 = Auth(user2, ssh_con, ssl=config.ssl)
    sts = auth2.do_auth_sts_client()

    auth3 = Auth(user3, ssh_con, ssl=config.ssl)
    s3_user3 = auth1.do_auth_using_client()

    # Configuration
    user1_name = user1["user_id"]
    user2_name = user2["user_id"]
    tenant_name = ""
    # ACCESS_KEY = 't2abc1'
    # SECRET_KEY = 't2abc1'
    # # for 8.1z3hotfix
    # # ENDPOINT_URL = 'http://10.8.129.105:80'
    # # for 7.1
    # # ENDPOINT_URL = 'http://10.0.67.83:80'
    # # for 8.1z3hotfix respin3
    # # ENDPOINT_URL = 'http://10.0.67.53:80'
    # ENDPOINT_URL = 'http://10.0.64.233:80'
    # REGION = 'us-east-1'
    # # ROLE_ARN = 'arn:aws:iam::tenant1:role/TestRole'
    # # ROLE_SESSION_NAME = 'TestSession'
    # BUCKET = 't2hsm1-bkt'
    # # OBJECT_KEY = f'warehouse/test-object1-{random_string}'
    # OBJECT_KEY = f'test-object1-{random_string}'
    # tenant_name = 'tenant2'
    # user1_name = 't2hsm1'
    #
    # user2_name = 't2hsm2'
    # user2_access_key = 't2abc2'
    # user2_secret_key = 't2abc2'

    # # Multipart upload parameters
    # multipart_key = 'multipart-object.txt'
    # part_data_paths = ['/root/obj10MB.parts/aa', '/root/obj10MB.parts/ab']



    #
    # # Initialize S3 client with permanent creds
    # s3_main = boto3.client(
    #     's3',
    #     aws_access_key_id=ACCESS_KEY,
    #     aws_secret_access_key=SECRET_KEY,
    #     # aws_access_key_id=user2_access_key,
    #     # aws_secret_access_key=user2_secret_key,
    #     endpoint_url=ENDPOINT_URL,
    #     region_name=REGION
    # )
    #
    # s3_main_object_owner = boto3.client(
    #     's3',
    #     # aws_access_key_id=ACCESS_KEY,
    #     # aws_secret_access_key=SECRET_KEY,
    #     aws_access_key_id=user2_access_key,
    #     aws_secret_access_key=user2_secret_key,
    #     endpoint_url=ENDPOINT_URL,
    #     region_name=REGION
    # )
    #
    #
    # # Initialize IAM and STS clients
    # iam = boto3.client(
    #     'iam',
    #     aws_access_key_id=ACCESS_KEY,
    #     aws_secret_access_key=SECRET_KEY,
    #     endpoint_url=ENDPOINT_URL,
    #     region_name=REGION
    # )
    #
    # sts = boto3.client(
    #     'sts',
    #     aws_access_key_id=user2_access_key,
    #     aws_secret_access_key=user2_secret_key,
    #     endpoint_url=ENDPOINT_URL,
    #     region_name=REGION
    # )


    resource_types = [
        {
            "name": "arn_access_all_buckets_and_objects",
            "resource_list": [
                f"arn:aws:s3::{tenant_name}:*"
            ],
            "object_name": 'test-object1',
            "bucket_names": ["user3_bucket_name", "<BUCKET>"]
        },
        {
            "name": "arn_access_all_objects_under_all_buckets",
            "resource_list": [
                f"arn:aws:s3::{tenant_name}:*/*"
            ],
            "object_name": 'test-object1',
            "bucket_names": ["user3_bucket_name", "<BUCKET>"]
        },
        {
            "name": "arn_access_only_the_bucket",
            "resource_list": [
                f"arn:aws:s3::{tenant_name}:<BUCKET>"
            ],
            "object_name": 'test-object1',
            "bucket_names": ["<BUCKET>"]
        },
        {
            "name": "arn_access_all_objects_under_the_bucket",
            "resource_list": [
                f"arn:aws:s3::{tenant_name}:<BUCKET>/*"
            ],
            "object_name": 'test-object1',
            "bucket_names": ["<BUCKET>"]
        },
        {
            "name": "arn_pseudo_directory_access",
            "resource_list": [
                f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse",
                f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse/",
                f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse/*",
            ],
            "object_name": f'warehouse/test-object1-{random_string}',
            "bucket_names": ["<BUCKET>"]
        }
    ]

    effects = ["Allow", "Deny"]

    index_effect = 1
    for effect in effects:
        index_actions = 1
        for s3_action in s3_action_required_resource:
            index_resource = 1
            for resource_type in resource_types:
                FAILED_ACTIONS = []
                PASSED_ACTIONS = []
                BUCKET = f't2hsm1-bkt-{random_string}-{index_effect}-{index_actions}-{index_resource}'
                OBJECT_KEY = resource_type["object_name"]
                raw_resources = resource_type["resource_list"]
                resource_list = [r.replace("<BUCKET>", BUCKET) for r in raw_resources]
                arn_type = resource_type["name"]

                user3_bucket_name = f"bkt1-user3-{random_string}-{index_effect}-{index_actions}-{index_resource}"
                s3_user3.create_bucket(Bucket=user3_bucket_name)

                expected_denied_actions = []
                expected_allowed_actions = all_actions
                if arn_type in s3_action_required_resource[s3_action]:
                    # expected_allowed_actions = BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS
                    # expected_denied_actions = []
                    expected_denied_actions = s3_action_allowed_methods[s3_action]
                    expected_allowed_actions = list(set(all_actions) - set(expected_denied_actions))
                elif arn_type == "arn_access_all_objects_under_all_buckets":
                    expected_allowed_actions = OBJECT_ACTIONS.copy()
                    expected_denied_actions = BUCKET_ACTIONS + GLOBAL_ACTIONS
                elif arn_type == "arn_access_only_the_bucket":
                    expected_allowed_actions = BUCKET_ACTIONS.copy()
                    expected_allowed_actions.remove("create_bucket")
                    expected_denied_actions = OBJECT_ACTIONS + GLOBAL_ACTIONS
                    expected_denied_actions.append("create_bucket")
                elif arn_type == "arn_access_all_objects_under_the_bucket":
                    expected_allowed_actions = OBJECT_ACTIONS.copy()
                    expected_denied_actions = BUCKET_ACTIONS + GLOBAL_ACTIONS
                elif arn_type == "arn_pseudo_directory_access":
                    expected_allowed_actions = OBJECT_ACTIONS.copy()
                    expected_denied_actions = BUCKET_ACTIONS + GLOBAL_ACTIONS
                expected_allowed_actions = sorted(expected_allowed_actions)
                expected_denied_actions = sorted(expected_denied_actions)

                session_policy_flags = [False, True]

                for session_policy_flag in session_policy_flags:
                    print(
                        f"\n\n====================================================================================================== \nTest {arn_type}")
                    print(f"BUCKET {BUCKET}")
                    print(f"OBJECT_KEY {OBJECT_KEY}")
                    print(f"resource_list {resource_list}")

                    # print(f"creating bucket {BUCKET} from {user1_name}")
                    # resp = s3_main.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
                    # print(f"creating bucket response: {resp}")

                    # Step 1: Create Role
                    role_name = f'TestRole-{random_string}-{index_actions}-{index_resource}'
                    print(f"role_name {role_name}")
                    assume_role_policy_document = {
                        'Version': '2012-10-17',
                        'Statement': [{
                            'Effect': 'Allow',
                            'Principal': {'AWS': [f'arn:aws:iam::{tenant_name}:user/{user2_name}']},
                            'Action': 'sts:AssumeRole'
                        }]
                    }
                    print(f'trust policy: {json.dumps(assume_role_policy_document).replace(" ", "")}')

                    try:
                        create_role_response = iam.create_role(
                            RoleName=role_name,
                            Path="/",
                            AssumeRolePolicyDocument=f'{json.dumps(assume_role_policy_document).replace(" ", "")}',
                            Description='Role for testing STS assume-role in Ceph RGW'
                        )
                        print("Role created:", create_role_response)
                    except ClientError as e:
                        logging.error(f"create role failed: {e}")


                    # Step 2: Attach Inline Policy
                    policy_name = 'TestPolicy'
                    policy_document = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": effect,
                                "Action": [
                                    f"{s3_action}"
                                ],
                                "Resource": resource_list
                            }
                        ]
                    }

                    print(f'role policy: {json.dumps(policy_document).replace(" ", "")}')
                    try:
                        put_role_resp = iam.put_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name,
                            PolicyDocument=json.dumps(policy_document).replace(" ", "")
                        )
                        print(f"Policy attached to role. resp: {put_role_resp}")
                    except ClientError as e:
                        logging.error(f"put role policy failed: {e}")
                    if session_policy_flag:

                        # Step 3: Assume Role

                        session_policy_document = {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:GetBucketLocation",
                                        "s3:ListBucket*"
                                    ],
                                    "Resource": [
                                        "arn:aws:s3::tenant2:<bucket_name>"
                                    ]
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:Get*",
                                        "s3:PutObject",
                                        "s3:PutObjectAcl",
                                        "s3:DeleteObject",
                                        "s3:AbortMultipartUpload"
                                    ],
                                    "Resource": [
                                        "arn:aws:s3::tenant2:<bucket_name>/warehouse",
                                        "arn:aws:s3::tenant2:<bucket_name>/warehouse/*",
                                        "arn:aws:s3::tenant2:<bucket_name>/warehouse/"
                                    ]
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:DeleteObject"
                                    ],
                                    "Resource": [
                                        "arn:aws:s3::tenant2:<bucket_name>"
                                    ]
                                }
                            ]
                        }

                        print(
                            f'session policy: {json.dumps(session_policy_document).replace(" ", "").replace("<bucket_name>", BUCKET)}')

                        # Step 3: Assume Role
                        assumed_role = sts.assume_role(
                            RoleArn=create_role_response['Role']['Arn'],
                            RoleSessionName='TestSession',
                            Policy=json.dumps(session_policy_document).replace(" ", "").replace("<bucket_name>", BUCKET)
                        )

                    else:
                        assumed_role = sts.assume_role(
                            RoleArn=create_role_response['Role']['Arn'],
                            RoleSessionName='TestSession'
                        )

                    credentials = assumed_role['Credentials']
                    print("Assumed role credentials:")
                    print("Access Key:", credentials['AccessKeyId'])
                    print("Secret Key:", credentials['SecretAccessKey'])
                    print("Session Token:", credentials['SessionToken'])


                    # # Initialize S3 client with sts creds
                    # s3 = boto3.client(
                    #     's3',
                    #     aws_access_key_id=credentials['AccessKeyId'],
                    #     aws_secret_access_key=credentials['SecretAccessKey'],
                    #     aws_session_token=credentials['SessionToken'],
                    #     endpoint_url=ENDPOINT_URL,
                    #     region_name=REGION
                    # )

                    assumed_role_user_info = {
                        "access_key": credentials['AccessKeyId'],
                        "secret_key": credentials['SecretAccessKey'],
                        "session_token": credentials['SessionToken'],
                        "user_id": user2["user_id"],
                    }

                    # log.info("got the credentials after assume role")
                    authstsuser = Auth(assumed_role_user_info, ssh_con, ssl=config.ssl)
                    s3 = authstsuser.do_auth_using_client()


                    s3_client_list = [
                        {
                            "s3_client": s3,
                            "desc": "sts-user-s3-client"
                        },
                        # {
                        #     "s3_client": s3_main_object_owner,
                        #     "desc": "object-owner-s3-client"
                        # },
                        # {
                        #     "s3_client": s3_main,
                        #     "desc": "bucket-owner-s3-client"
                        # }
                    ]
                    actual_bucket_name = BUCKET
                    output_list = []
                    index_s3_client = 0
                    for s3_client_dict in s3_client_list:

                        bucket_names = [BUCKET, user3_bucket_name]
                        object_names = [OBJECT_KEY, f'warehouse/test-object1-{random_string}']

                        for bucket_name in bucket_names:
                            for object_name in object_names:

                                FAILED_ACTIONS = []
                                PASSED_ACTIONS = []
                                s3_client = s3_client_dict["s3_client"]
                                desc = s3_client_dict["desc"]
                                BUCKET = f"{actual_bucket_name}-{desc}"
                                print(f"creating bucket {BUCKET} from {user1_name}")
                                resp = s3_main.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
                                print(f"creating bucket response: {resp}")

                                # time.sleep(2)

                                # Call each method
                                print("--------------------------------------------------------------------------------------------------- \nTest create_bucket")
                                create_bucket(s3_client)
                                print("")
                                print("--------------------------------------------------------------------------------------------------- \nTest abort_multipart_upload")
                                abort_multipart_upload(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_object")
                                put_object(s3)
                                print("--------------------------------------------------------------------------------------------------- \nTest multipart_upload")
                                multipart_upload(s3)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_object")
                                get_object(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_object_acl")
                                put_object_acl(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_object_acl")
                                get_object_acl(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_acl")
                                put_bucket_acl(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_cors")
                                put_bucket_cors(s3_client)
                                print("")
                                # print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_logging")
                                # put_bucket_logging(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_notification")
                                put_bucket_notification(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_policy")
                                put_bucket_policy(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_tagging")
                                put_bucket_tagging(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_versioning")
                                put_bucket_versioning(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_object_version_acl")
                                put_object_version_acl(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_website")
                                put_bucket_website(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_lifecycle_configuration")
                                put_lifecycle_configuration(s3_client)
                                print("")
                                # print("--------------------------------------------------------------------------------------------------- \nTest restore_object")
                                # restore_object(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest copy_object")
                                copy_object(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_encryption")
                                put_bucket_encryption(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_encryption")
                                get_bucket_encryption(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest delete_bucket_encryption")
                                delete_bucket_encryption(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_public_access_block")
                                put_public_access_block(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_public_access_block")
                                get_public_access_block(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest delete_public_access_block")
                                delete_public_access_block(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest head_bucket")
                                head_bucket(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest head_object")
                                head_object(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest list_object_versions")
                                list_object_versions(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest list_objects")
                                list_objects(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest list_objects_v2")
                                list_objects_v2(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest select_object_content")
                                select_object_content(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_object_tagging")
                                put_object_tagging(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_object_tagging")
                                get_object_tagging(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_object_attributes")
                                get_object_attributes(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_object_lock_configuration")
                                put_object_lock_configuration(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_object_lock_configuration")
                                get_object_lock_configuration(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_object_legal_hold")
                                put_object_legal_hold(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_object_legal_hold")
                                get_object_legal_hold(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest remove_object_legal_hold")
                                remove_object_legal_hold(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest put_object_retention")
                                put_object_retention(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_object_retention")
                                get_object_retention(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest remove_object_retention")
                                remove_object_retention(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_accelerate_configuration")
                                get_accelerate_configuration(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_acl")
                                get_bucket_acl(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_cors")
                                get_bucket_cors(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_location")
                                get_bucket_location(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_logging")
                                get_bucket_logging(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_notification")
                                get_bucket_notification(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_policy")
                                get_bucket_policy(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_request_payment")
                                get_bucket_request_payment(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_tagging")
                                get_bucket_tagging(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_versioning")
                                get_bucket_versioning(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_bucket_website")
                                get_bucket_website(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_lifecycle_configuration")
                                get_lifecycle_configuration(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_object_version_acl")
                                get_object_version_acl(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_object_version")
                                get_object_version(s3_client)
                                # print("--------------------------------------------------------------------------------------------------- \nTest put_replication_configuration")
                                # put_replication_configuration(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest get_replication_configuration")
                                get_replication_configuration(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest list_all_my_buckets")
                                list_all_my_buckets(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest list_bucket_multipart_uploads")
                                list_bucket_multipart_uploads(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest list_multipart_upload_parts")
                                list_multipart_upload_parts(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest delete_bucket_website")
                                delete_bucket_website(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest delete_replication_configuration")
                                delete_replication_configuration(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest delete_object_version")
                                delete_object_version(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest delete_object")
                                delete_object(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest delete_objects")
                                delete_objects(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest delete_bucket_policy")
                                delete_bucket_policy(s3_client)
                                print("--------------------------------------------------------------------------------------------------- \nTest delete_bucket")
                                delete_bucket(s3_client)
                                print("")
                                # print("--------------------------------------------------------------------------------------------------- \nTest list_bucket")
                                # list_bucket()
                                # print("--------------------------------------------------------------------------------------------------- \nTest list_bucket_versions")
                                # list_bucket_versions()

                                print(f"--------------------------------------------------------------------------------------------------- \nTest Summary for {arn_type} with deny {s3_action} and with s3_client {desc}")
                                actual_allowed_actions = sorted(PASSED_ACTIONS)
                                actual_denied_actions = sorted(FAILED_ACTIONS)
                                print(f"\nactual_allowed_actions: {actual_allowed_actions}")
                                print(f"\nexpected_allowed_actions: {expected_allowed_actions}")
                                print(f"\nactual_denied_actions: {actual_denied_actions}")
                                print(f"\nexpected_denied_actions: {expected_denied_actions}")
                                if expected_allowed_actions != actual_allowed_actions:
                                    print(f"\nthese actions are expected to be allowed but not allowed: {list(set(expected_allowed_actions) - set(actual_allowed_actions))}")
                                    print(
                                        f"\nthese actions are not expected to be allowed but allowed: {list(set(actual_allowed_actions) - set(expected_allowed_actions))}")
                                    # raise Exception(f"\nactual_allowed_actions not matched with expected_allowed_actions.")
                                if expected_denied_actions != actual_denied_actions:
                                    print(f"\nthese actions are expected to be denied but not denied: {list(set(expected_denied_actions) - set(actual_denied_actions))}")
                                    print(
                                        f"\nthese actions are not expected to be denied but denied: {list(set(actual_denied_actions) - set(expected_denied_actions))}")
                                    # raise Exception(f"\nactual_denied_actions not matched with expected_allowed_actions.")

                                # output_list.append([])
                                # for action in BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS:
                                #     result = ""
                                #     if action in actual_allowed_actions:
                                #         result = "Allowed"
                                #     elif action in actual_denied_actions:
                                #         result = "Denied"
                                #     output_list[index_s3_client].append(result)
                                # print("\n".join(output_list[index_s3_client]))
                                index_s3_client += 1

                            index_resource = index_resource + 1

                            # output_string = "action sts-user-s3-client object-owner-s3-client bucket-owner-s3-client\n"
                            # actions_list = BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS
                            # for i in range(0, len(actions_list)):
                            #     result = ""
                            #     output_string += f"{actions_list[i]} {output_list[0][i]} {output_list[1][i]} {output_list[2][i]}\n"
                            # print(output_string)
                            # raise Exception("stop the flow")


            index_actions = index_actions + 1
        index_effect = index_effect + 1





def exercise_all_s3api_requests(s3_client):
    FAILED_ACTIONS = []
    PASSED_ACTIONS = []

    # Call each method
    print(
        "--------------------------------------------------------------------------------------------------- \nTest create_bucket")
    create_bucket(s3_client)
    print("")
    print(
        "--------------------------------------------------------------------------------------------------- \nTest abort_multipart_upload")
    abort_multipart_upload(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_object")
    put_object(s3)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest multipart_upload")
    multipart_upload(s3)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_object")
    get_object(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_object_acl")
    put_object_acl(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_object_acl")
    get_object_acl(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_bucket_acl")
    put_bucket_acl(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_bucket_cors")
    put_bucket_cors(s3_client)
    print("")
    # print("--------------------------------------------------------------------------------------------------- \nTest put_bucket_logging")
    # put_bucket_logging(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_bucket_notification")
    put_bucket_notification(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_bucket_policy")
    put_bucket_policy(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_bucket_tagging")
    put_bucket_tagging(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_bucket_versioning")
    put_bucket_versioning(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_object_version_acl")
    put_object_version_acl(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_bucket_website")
    put_bucket_website(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_lifecycle_configuration")
    put_lifecycle_configuration(s3_client)
    print("")
    # print("--------------------------------------------------------------------------------------------------- \nTest restore_object")
    # restore_object(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest copy_object")
    copy_object(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_bucket_encryption")
    put_bucket_encryption(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_encryption")
    get_bucket_encryption(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest delete_bucket_encryption")
    delete_bucket_encryption(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_public_access_block")
    put_public_access_block(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_public_access_block")
    get_public_access_block(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest delete_public_access_block")
    delete_public_access_block(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest head_bucket")
    head_bucket(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest head_object")
    head_object(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest list_object_versions")
    list_object_versions(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest list_objects")
    list_objects(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest list_objects_v2")
    list_objects_v2(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest select_object_content")
    select_object_content(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_object_tagging")
    put_object_tagging(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_object_tagging")
    get_object_tagging(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_object_attributes")
    get_object_attributes(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_object_lock_configuration")
    put_object_lock_configuration(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_object_lock_configuration")
    get_object_lock_configuration(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_object_legal_hold")
    put_object_legal_hold(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_object_legal_hold")
    get_object_legal_hold(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest remove_object_legal_hold")
    remove_object_legal_hold(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest put_object_retention")
    put_object_retention(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_object_retention")
    get_object_retention(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest remove_object_retention")
    remove_object_retention(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_accelerate_configuration")
    get_accelerate_configuration(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_acl")
    get_bucket_acl(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_cors")
    get_bucket_cors(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_location")
    get_bucket_location(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_logging")
    get_bucket_logging(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_notification")
    get_bucket_notification(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_policy")
    get_bucket_policy(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_request_payment")
    get_bucket_request_payment(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_tagging")
    get_bucket_tagging(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_versioning")
    get_bucket_versioning(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_bucket_website")
    get_bucket_website(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_lifecycle_configuration")
    get_lifecycle_configuration(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_object_version_acl")
    get_object_version_acl(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_object_version")
    get_object_version(s3_client)
    # print("--------------------------------------------------------------------------------------------------- \nTest put_replication_configuration")
    # put_replication_configuration(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest get_replication_configuration")
    get_replication_configuration(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest list_all_my_buckets")
    list_all_my_buckets(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest list_bucket_multipart_uploads")
    list_bucket_multipart_uploads(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest list_multipart_upload_parts")
    list_multipart_upload_parts(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest delete_bucket_website")
    delete_bucket_website(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest delete_replication_configuration")
    delete_replication_configuration(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest delete_object_version")
    delete_object_version(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest delete_object")
    delete_object(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest delete_objects")
    delete_objects(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest delete_bucket_policy")
    delete_bucket_policy(s3_client)
    print(
        "--------------------------------------------------------------------------------------------------- \nTest delete_bucket")
    delete_bucket(s3_client)
    print("")
    # print("--------------------------------------------------------------------------------------------------- \nTest list_bucket")
    # list_bucket()
    # print("--------------------------------------------------------------------------------------------------- \nTest list_bucket_versions")
    # list_bucket_versions()



def test_sts_static_role_session_policy(user1, user2, user3, ssh_con, config):

    # Generate a random string of 5 characters
    characters = string.ascii_lowercase + string.digits
    random_string = ''.join(random.choice(characters) for i in range(5))

    auth1 = Auth(user1, ssh_con, ssl=config.ssl)
    iam = auth1.do_auth_iam_client()
    s3_main = auth1.do_auth_using_client()

    auth2 = Auth(user2, ssh_con, ssl=config.ssl)
    sts = auth2.do_auth_sts_client()

    auth3 = Auth(user3, ssh_con, ssl=config.ssl)
    s3_user3 = auth1.do_auth_using_client()

    # Configuration
    user1_name = user1["user_id"]
    user2_name = user2["user_id"]
    tenant_name = ""

    # resource_types = [
    #     {
    #         "name": "arn_access_all_buckets_and_objects",
    #         "resource_list": [
    #             f"arn:aws:s3::{tenant_name}:*"
    #         ],
    #         "object_name": 'test-object1',
    #         "bucket_names": ["user3_bucket_name", "<BUCKET>"]
    #     },
    #     {
    #         "name": "arn_access_all_objects_under_all_buckets",
    #         "resource_list": [
    #             f"arn:aws:s3::{tenant_name}:*/*"
    #         ],
    #         "object_name": 'test-object1',
    #         "bucket_names": ["user3_bucket_name", "<BUCKET>"]
    #     },
    #     {
    #         "name": "arn_access_only_the_bucket",
    #         "resource_list": [
    #             f"arn:aws:s3::{tenant_name}:<BUCKET>"
    #         ],
    #         "object_name": 'test-object1',
    #         "bucket_names": ["<BUCKET>"]
    #     },
    #     {
    #         "name": "arn_access_all_objects_under_the_bucket",
    #         "resource_list": [
    #             f"arn:aws:s3::{tenant_name}:<BUCKET>/*"
    #         ],
    #         "object_name": 'test-object1',
    #         "bucket_names": ["<BUCKET>"]
    #     },
    #     {
    #         "name": "arn_pseudo_directory_access",
    #         "resource_list": [
    #             f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse",
    #             f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse/",
    #             f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse/*",
    #         ],
    #         "object_name": f'warehouse/test-object1-{random_string}',
    #         "bucket_names": ["<BUCKET>"]
    #     }
    # ]
    #
    # FAILED_ACTIONS = []
    # PASSED_ACTIONS = []
    # BUCKET = f't2hsm1-bkt-{random_string}'
    # OBJECT_KEY = resource_type["object_name"]
    # raw_resources = resource_type["resource_list"]
    # resource_list = [r.replace("<BUCKET>", BUCKET) for r in raw_resources]
    # # arn_type = resource_type["name"]
    # arn_type = "arn_pseudo_directory_access"
    #
    # user3_bucket_name = f"bkt1-user3-{random_string}"
    # s3_user3.create_bucket(Bucket=user3_bucket_name)
    #
    # expected_denied_actions = []
    # expected_allowed_actions = all_actions
    # if arn_type in s3_action_required_resource[s3_action]:
    #     # expected_allowed_actions = BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS
    #     # expected_denied_actions = []
    #     expected_denied_actions = s3_action_allowed_methods[s3_action]
    #     expected_allowed_actions = list(set(all_actions) - set(expected_denied_actions))
    #
    # expected_denied_actions = all_actions
    # if arn_type in s3_action_required_resource[s3_action]:
    #     # expected_allowed_actions = BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS
    #     # expected_denied_actions = []
    #     expected_allowed_actions = s3_action_allowed_methods[s3_action]
    #     expected_denied_actions = list(set(all_actions) - set(expected_allowed_actions))
    #
    #
    # print(
    #     f"\n\n====================================================================================================== \nTest {arn_type}")
    # print(f"BUCKET {BUCKET}")
    # print(f"OBJECT_KEY {OBJECT_KEY}")
    # print(f"resource_list {resource_list}")
    #
    # # print(f"creating bucket {BUCKET} from {user1_name}")
    # # resp = s3_main.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    # # print(f"creating bucket response: {resp}")
    #
    # # Step 1: Create Role
    # role_name = f'TestRole-{random_string}-{index_actions}-{index_resource}'
    # print(f"role_name {role_name}")
    # assume_role_policy_document = {
    #     'Version': '2012-10-17',
    #     'Statement': [{
    #         'Effect': 'Allow',
    #         'Principal': {'AWS': [f'arn:aws:iam::{tenant_name}:user/{user2_name}']},
    #         'Action': 'sts:AssumeRole'
    #     }]
    # }
    # print(f'trust policy: {json.dumps(assume_role_policy_document).replace(" ", "")}')
    #
    # try:
    #     create_role_response = iam.create_role(
    #         RoleName=role_name,
    #         Path="/",
    #         AssumeRolePolicyDocument=f'{json.dumps(assume_role_policy_document).replace(" ", "")}',
    #         Description='Role for testing STS assume-role in Ceph RGW'
    #     )
    #     print("Role created:", create_role_response)
    # except ClientError as e:
    #     logging.error(f"create role failed: {e}")
    #
    #
    # # Step 2: Attach Inline Policy
    # policy_name = 'TestPolicy'
    # policy_document = {
    #     "Version": "2012-10-17",
    #     "Statement": [
    #         {
    #             "Effect": effect,
    #             "Action": [
    #                 f"{s3_action}"
    #             ],
    #             "Resource": resource_list
    #         }
    #     ]
    # }
    #
    # print(f'role policy: {json.dumps(policy_document).replace(" ", "")}')
    # try:
    #     put_role_resp = iam.put_role_policy(
    #         RoleName=role_name,
    #         PolicyName=policy_name,
    #         PolicyDocument=json.dumps(policy_document).replace(" ", "")
    #     )
    #     print(f"Policy attached to role. resp: {put_role_resp}")
    # except ClientError as e:
    #     logging.error(f"put role policy failed: {e}")
    # if session_policy_flag:
    #
    #     # Step 3: Assume Role
    #
    #     session_policy_document = {
    #         "Version": "2012-10-17",
    #         "Statement": [
    #             {
    #                 "Effect": "Allow",
    #                 "Action": [
    #                     "s3:GetBucketLocation",
    #                     "s3:ListBucket*"
    #                 ],
    #                 "Resource": [
    #                     "arn:aws:s3::tenant2:<bucket_name>"
    #                 ]
    #             },
    #             {
    #                 "Effect": "Allow",
    #                 "Action": [
    #                     "s3:Get*",
    #                     "s3:PutObject",
    #                     "s3:PutObjectAcl",
    #                     "s3:DeleteObject",
    #                     "s3:AbortMultipartUpload"
    #                 ],
    #                 "Resource": [
    #                     "arn:aws:s3::tenant2:<bucket_name>/warehouse",
    #                     "arn:aws:s3::tenant2:<bucket_name>/warehouse/*",
    #                     "arn:aws:s3::tenant2:<bucket_name>/warehouse/"
    #                 ]
    #             },
    #             {
    #                 "Effect": "Allow",
    #                 "Action": [
    #                     "s3:DeleteObject"
    #                 ],
    #                 "Resource": [
    #                     "arn:aws:s3::tenant2:<bucket_name>"
    #                 ]
    #             }
    #         ]
    #     }
    #
    #     print(
    #         f'session policy: {json.dumps(session_policy_document).replace(" ", "").replace("<bucket_name>", BUCKET)}')
    #
    #     # Step 3: Assume Role
    #     assumed_role = sts.assume_role(
    #         RoleArn=create_role_response['Role']['Arn'],
    #         RoleSessionName='TestSession',
    #         Policy=json.dumps(session_policy_document).replace(" ", "").replace("<bucket_name>", BUCKET)
    #     )
    #
    # else:
    #     assumed_role = sts.assume_role(
    #         RoleArn=create_role_response['Role']['Arn'],
    #         RoleSessionName='TestSession'
    #     )
    #
    # credentials = assumed_role['Credentials']
    # print("Assumed role credentials:")
    # print("Access Key:", credentials['AccessKeyId'])
    # print("Secret Key:", credentials['SecretAccessKey'])
    # print("Session Token:", credentials['SessionToken'])
    #
    #
    # # # Initialize S3 client with sts creds
    # # s3 = boto3.client(
    # #     's3',
    # #     aws_access_key_id=credentials['AccessKeyId'],
    # #     aws_secret_access_key=credentials['SecretAccessKey'],
    # #     aws_session_token=credentials['SessionToken'],
    # #     endpoint_url=ENDPOINT_URL,
    # #     region_name=REGION
    # # )
    #
    # assumed_role_user_info = {
    #     "access_key": credentials['AccessKeyId'],
    #     "secret_key": credentials['SecretAccessKey'],
    #     "session_token": credentials['SessionToken'],
    #     "user_id": user2["user_id"],
    # }
    #
    # # log.info("got the credentials after assume role")
    # authstsuser = Auth(assumed_role_user_info, ssh_con, ssl=config.ssl)
    # s3 = authstsuser.do_auth_using_client()



    index = 1
    FAILED_ACTIONS = []
    PASSED_ACTIONS = []
    BUCKET = f'bkt-{random_string}'
    # OBJECT_KEY = resource_type["object_name"]
    OBJECT_KEY = f'warehouse/test-object1-{random_string}'
    # raw_resources = resource_type["resource_list"]
    raw_resources = [
        f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse",
        f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse/",
        f"arn:aws:s3::{tenant_name}:<BUCKET>/warehouse/*",
    ]
    resource_list = [r.replace("<BUCKET>", BUCKET) for r in raw_resources]
    # arn_type = resource_type["name"]
    arn_type = "arn_pseudo_directory_access"
    expected_allowed_actions = []
    expected_denied_actions = list(set(all_actions) - set(expected_allowed_actions))
    # if arn_type == "arn_access_all_buckets_and_objects":
    #     expected_allowed_actions = BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS
    #     expected_denied_actions = []
    # elif arn_type == "arn_access_all_objects_under_all_buckets":
    #     expected_allowed_actions = OBJECT_ACTIONS
    #     expected_denied_actions = BUCKET_ACTIONS + GLOBAL_ACTIONS
    # elif arn_type == "arn_access_only_the_bucket":
    #     expected_allowed_actions = BUCKET_ACTIONS
    #     expected_denied_actions = OBJECT_ACTIONS + GLOBAL_ACTIONS
    # elif arn_type == "arn_access_all_objects_under_the_bucket":
    #     expected_allowed_actions = OBJECT_ACTIONS
    #     expected_denied_actions = BUCKET_ACTIONS + GLOBAL_ACTIONS
    # elif arn_type == "arn_pseudo_directory_access":
    #     expected_allowed_actions = OBJECT_ACTIONS
    #     expected_denied_actions = BUCKET_ACTIONS + GLOBAL_ACTIONS
    # expected_allowed_actions = sorted(expected_allowed_actions)
    # expected_denied_actions = sorted(expected_denied_actions)

    print(
        f"\n\n====================================================================================================== \nTest {arn_type}")
    print(f"BUCKET {BUCKET}")
    print(f"OBJECT_KEY {OBJECT_KEY}")
    print(f"resource_list {resource_list}")

    print(f"creating bucket {BUCKET} from {user_name}")
    # resp = s3_main.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    resp = s3_main.create_bucket(Bucket=BUCKET)
    print(f"creating bucket response: {resp}")

    # Step 1: Create Role
    role_name = f'TestRole-{random_string}-{index}'
    print(f"role_name {role_name}")
    assume_role_policy_document = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': [f'arn:aws:iam::{tenant_name}:user/{user2_name}']},
            'Action': 'sts:AssumeRole'
        }]
    }
    print(f'trust policy: {json.dumps(assume_role_policy_document).replace(" ", "")}')

    try:
        create_role_response = iam.create_role(
            RoleName=role_name,
            Path="/",
            AssumeRolePolicyDocument=f'{json.dumps(assume_role_policy_document).replace(" ", "")}',
            Description='Role for testing STS assume-role in Ceph RGW'
        )
        print("Role created:", create_role_response)
    except ClientError as e:
        logging.error(f"create role failed: {e}")
    role_arn = create_role_response['Role']['Arn']

    # Step 2: Attach Inline Policy
    policy_name = 'TestPolicy'
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucketMultipartUploads",
                    "s3:ListMultipartUploadParts",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:ListAllMyBuckets",
                    "s3:AbortMultipartUpload",
                    "s3:DeleteObject",
                    "s3:PutObject"
                ],
                "Resource": "arn:aws:s3::tenant2:*"
            }
        ]
    }
    print(f'role policy: {json.dumps(policy_document).replace(" ", "")}')

    try:
        put_role_resp = iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document).replace(" ", "")
        )
        print(f"Policy attached to role. resp: {put_role_resp}")
    except ClientError as e:
        logging.error(f"put role policy failed: {e}")

    # Step 3: Assume Role
    # assumed_role = sts.assume_role(
    #     RoleArn=create_role_response['Role']['Arn'],
    #     RoleSessionName='TestSession'
    # )
    session_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:ListBucket*"
                ],
                "Resource": [
                    "arn:aws:s3::tenant2:<bucket_name>"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:Get*",
                    "s3:PutObject",
                    "s3:PutObjectAcl",
                    "s3:DeleteObject",
                    "s3:AbortMultipartUpload"
                ],
                "Resource": [
                    "arn:aws:s3::tenant2:<bucket_name>/warehouse",
                    "arn:aws:s3::tenant2:<bucket_name>/warehouse/*",
                    "arn:aws:s3::tenant2:<bucket_name>/warehouse/"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:DeleteObject"
                ],
                "Resource": [
                    "arn:aws:s3::tenant2:<bucket_name>"
                ]
            }
        ]
    }

    print(f'session policy: {json.dumps(session_policy_document).replace(" ", "").replace("<bucket_name>", BUCKET)}')

    # Step 3: Assume Role
    assumed_role = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName='TestSession',
        Policy=json.dumps(session_policy_document).replace(" ", "").replace("<bucket_name>", BUCKET)
    )
    credentials = assumed_role['Credentials']
    print("Assumed role credentials:")
    print("Access Key:", credentials['AccessKeyId'])
    print("Secret Key:", credentials['SecretAccessKey'])
    print("Session Token:", credentials['SessionToken'])

    # Initialize S3 client with sts creds
    # s3 = boto3.client(
    #     's3',
    #     aws_access_key_id=credentials['AccessKeyId'],
    #     aws_secret_access_key=credentials['SecretAccessKey'],
    #     aws_session_token=credentials['SessionToken'],
    #     endpoint_url=ENDPOINT_URL,
    #     region_name=REGION
    # )

    assumed_role_user_info = {
        "access_key": credentials['AccessKeyId'],
        "secret_key": credentials['SecretAccessKey'],
        "session_token": credentials['SessionToken'],
        "user_id": user2["user_id"],
    }

    # log.info("got the credentials after assume role")
    authstsuser = Auth(assumed_role_user_info, ssh_con, ssl=config.ssl)
    s3 = authstsuser.do_auth_using_client()


    FAILED_ACTIONS = []
    PASSED_ACTIONS = []
    s3_client = s3

    # time.sleep(2)

    exercise_all_s3api_requests(s3_client)

    print(f"--------------------------------------------------------------------------------------------------- \nTest Summary for {arn_type} with deny {s3_action} and with s3_client {desc}")
    actual_allowed_actions = sorted(PASSED_ACTIONS)
    actual_denied_actions = sorted(FAILED_ACTIONS)
    print(f"\nactual_allowed_actions: {actual_allowed_actions}")
    print(f"\nexpected_allowed_actions: {expected_allowed_actions}")
    print(f"\nactual_denied_actions: {actual_denied_actions}")
    print(f"\nexpected_denied_actions: {expected_denied_actions}")
    if expected_allowed_actions != actual_allowed_actions:
        print(f"\nthese actions are expected to be allowed but not allowed: {list(set(expected_allowed_actions) - set(actual_allowed_actions))}")
        print(
            f"\nthese actions are not expected to be allowed but allowed: {list(set(actual_allowed_actions) - set(expected_allowed_actions))}")
        # raise Exception(f"\nactual_allowed_actions not matched with expected_allowed_actions.")
    if expected_denied_actions != actual_denied_actions:
        print(f"\nthese actions are expected to be denied but not denied: {list(set(expected_denied_actions) - set(actual_denied_actions))}")
        print(
            f"\nthese actions are not expected to be denied but denied: {list(set(actual_denied_actions) - set(expected_denied_actions))}")
        # raise Exception(f"\nactual_denied_actions not matched with expected_allowed_actions.")

    # output_list.append([])
    # for action in BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS:
    #     result = ""
    #     if action in actual_allowed_actions:
    #         result = "Allowed"
    #     elif action in actual_denied_actions:
    #         result = "Denied"
    #     output_list[index_s3_client].append(result)
    # print("\n".join(output_list[index_s3_client]))

    # output_string = "action sts-user-s3-client object-owner-s3-client bucket-owner-s3-client\n"
    # actions_list = BUCKET_ACTIONS + OBJECT_ACTIONS + GLOBAL_ACTIONS
    # for i in range(0, len(actions_list)):
    #     result = ""
    #     output_string += f"{actions_list[i]} {output_list[0][i]} {output_list[1][i]} {output_list[2][i]}\n"
    # print(output_string)
    # raise Exception("stop the flow")
