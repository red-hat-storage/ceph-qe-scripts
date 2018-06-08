# test basic creation of buckets with objects
import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.log as log
import v2.utils.utils as utils
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
import yaml
import v2.lib.manage_data as manage_data
from v2.lib.exceptions import TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure

TEST_DATA_PATH = None

ACLS = {0: 'private',
            1: 'public-read',
            2: 'public-read-write'}


def create_bucket(rgw_conn, user_info, rand_no=0):

    s3_ops = ResourceOps()

    bucket_name_to_create = utils.gen_bucket_name_from_userid(user_info['user_id'], rand_no)

    log.info('creating bucket with name: %s' % bucket_name_to_create)

    bucket = s3_ops.resource_op(rgw_conn, 'Bucket', bucket_name_to_create)

    created = s3_ops.resource_op(bucket, 'create', None, **{'access_key': user_info['access_key']})

    if created is False:
        raise TestExecError("Resource execution failed: bucket creation faield")

    if created is not None:

        response = HttpResponseParser(created)

        if response.status_code == 200:
            log.info('bucket created')

        else:
            raise TestExecError("bucket creation failed")

    return bucket


def test_acls_private(u1_rgw_conn, u1, u2_rgw_conn, u1_bucket, u2_bucket):


    # test for acl: private

    s3_ops = ResourceOps()

    u1_bucket_acl = s3_ops.resource_op(u1_rgw_conn, 'BucketAcl', u1_bucket.name)
    log.info('setting bucket acl: %s' % ACLS[0])
    u1_bucket_acl.put(ACL=ACLS[0])

    # access bucket_info of u1_bucket from u2

    log.info('u1 bucket info')

    u1_bucket_info = s3_ops.resource_op(u1_rgw_conn, 'Bucket', u1_bucket.name)

    log.info(u1_bucket_info.name)
    log.info(u1_bucket_info.creation_date)
    log.info(u1_bucket_info.load())

    log.info('trying to access u1 bucket info from u2 after setting u1 bucket acls to private')

    access_u1_bucket_from_u2 = s3_ops.resource_op(u2_rgw_conn, 'Bucket', u1_bucket.name)

    log.info('tryring to delete u1_bucket from u2')

    u1_bucket_deleted_response =  access_u1_bucket_from_u2.delete()


    try:

        response = HttpResponseParser(u1_bucket_deleted_response)

    except Exception,e :
           log.info('error deleting bucket as there is no permission on u1_bucket')

    else:
        raise TestExecError("bucket access should be restricted, but delete excuted")


def test_acls_public_write(u1_rgw_conn, u1, u2_rgw_conn, u1_bucket, u2_bucket):

    # test for acl: public-read-write

    s3_ops = ResourceOps()

    u1_bucket_acl = s3_ops.resource_op(u1_rgw_conn, 'BucketAcl', u1_bucket.name)
    log.info('setting bucket acl: %s' % ACLS[2])
    u1_bucket_acl.put(ACL=ACLS[2])

    # access bucket_info of u1_bucket from u2

    log.info('u1 bucket info')

    u1_bucket_info = s3_ops.resource_op(u1_rgw_conn, 'Bucket', u1_bucket.name)

    log.info(u1_bucket_info.name)
    log.info(u1_bucket_info.creation_date)
    log.info(u1_bucket_info.load())

    log.info('trying to access u1 bucket info from u2 after setting u1 bucket acls to public-read-write')

    access_u1_bucket_from_u2 = s3_ops.resource_op(u2_rgw_conn, 'Bucket', u1_bucket.name)

    log.info('tryring to delete u1_bucket from u2')

    u1_bucket_deleted_response =  access_u1_bucket_from_u2.delete()

    response = HttpResponseParser(u1_bucket_deleted_response)

    if response.status_code == 204:
        log.info('u1 bucket deleted from u2')

    else:
        log.info('error in bucket deletion')
        raise TestExecError, "error in bucket deletion"


def test_acls_public_read(u1_rgw_conn, u1, u2_rgw_conn, u1_bucket, u2_bucket):

    # test for public_read

    s3_ops = ResourceOps()

    u1_bucket_acl = s3_ops.resource_op(u1_rgw_conn, 'BucketAcl', u1_bucket.name)
    log.info('setting bucket acl: %s' % ACLS[1])
    u1_bucket_acl.put(ACL=ACLS[1])

    # access bucket_info of u1_bucket from u2

    log.info('u1 bucket info')

    u1_bucket_info = s3_ops.resource_op(u1_rgw_conn, 'Bucket', u1_bucket.name)

    log.info(u1_bucket_info.name)
    log.info(u1_bucket_info.creation_date)
    log.info(u1_bucket_info.load())

    s3_object_name = utils.gen_s3_object_name(u1_bucket.name, rand_no=0)

    log.info('s3 object name: %s' % s3_object_name)

    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)

    log.info('s3 object path: %s' % s3_object_path)

    s3_object_size = utils.get_file_size(config.objects_size_range['min'],
                                         config.objects_size_range['max'])

    data_info = manage_data.io_generator(s3_object_path, s3_object_size)

    if data_info is False:
        TestExecError("data creation failed")

    log.info('uploading s3 object: %s' % s3_object_path)

    upload_info = dict({'access_key': u1['access_key']}, **data_info)

    object_uploaded_status = s3_ops.resource_op(u1_bucket, 'upload_file', s3_object_path, s3_object_name,
                                                **upload_info)

    if object_uploaded_status is False:
        raise TestExecError("Resource execution failed: object upload failed")

    if object_uploaded_status is None:
        log.info('object uploaded')

    log.info('trying to access u1 bucket and its objects info from u2 after setting u1 bucket acls to public read')

    access_u1_bucket_from_u2 = s3_ops.resource_op(u2_rgw_conn, 'Bucket', u1_bucket.name)


    try:

        all_objects = access_u1_bucket_from_u2.objects.all()

        for obj in all_objects:
            log.info('obj name: %s' % obj.key)

    except Exception,e :
        msg  = 'access given to read, but still failing to read'
        raise TestExecError(msg)

    log.info('tryring to delete u1_bucket from u2')

    try:

        u1_bucket_deleted_response =  access_u1_bucket_from_u2.delete()

        response = HttpResponseParser(u1_bucket_deleted_response)
        log.info(response)

    except Exception, e :
        msg = 'access not given to write, hence fialing'
        log.info(msg)

    else:
        raise TestExecError("acces not given, but still bucket got deleted")

def test_exec(config):

    test_info = AddTestInfo('test with acls')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    try:

        test_info.started_info()

        s3_ops = ResourceOps()

        # create user

        config.user_count = 2

        all_users_info = s3lib.create_users(config.user_count)

        u1 = all_users_info[0]
        u2 = all_users_info[1]

        # authenticate

        u1_auth = Auth(u1)
        u1_rgw_conn = u1_auth.do_auth()

        u2_auth = Auth(u2)
        u2_rgw_conn = u2_auth.do_auth()

        no_of_buckets_to_create = 3

        u1_buckets = []
        u2_buckets = []

        for i in range(no_of_buckets_to_create):

            u1_bucket = create_bucket(u1_rgw_conn, u1, rand_no=i)
            log.info('u1_bucket_name: %s' % u1_bucket.name)

            u1_buckets.append(u1_bucket)

            u2_bucket = create_bucket(u2_rgw_conn, u2, rand_no=i)
            log.info('u2_bucket_name: %s' % u2_bucket.name)

            u2_buckets.append(u2_bucket)

        # test_acls_private(u1_rgw_conn, u1, u2, u1_buckets[0], u2_buckets[0])

        test_acls_public_write(u1_rgw_conn, u1, u2, u1_buckets[1], u2_buckets[1])

        # test_acls_public_read(u1_rgw_conn, u1, u2, u1_buckets[2], u2_buckets[2])

        # print u1_bucket_info.delete()

        test_info.success_status('test passed')

        sys.exit(0)

    except Exception,e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)

    except TestExecError, e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)


if __name__ == '__main__':

    project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
    test_data_dir = 'test_data'

    TEST_DATA_PATH = (os.path.join(project_dir, test_data_dir))

    log.info('TEST_DATA_PATH: %s' % TEST_DATA_PATH)

    if not os.path.exists(TEST_DATA_PATH):
        log.info('test data dir not exists, creating.. ')
        os.makedirs(TEST_DATA_PATH)

    parser = argparse.ArgumentParser(description='RGW S3 Automation')

    parser.add_argument('-c', dest="config",
                        help='RGW Test yaml configuration')

    args = parser.parse_args()

    yaml_file = args.config
    config = Config()
    config.shards = None
    config.max_objects = None
    if yaml_file is None:
        config.user_count = 2
        config.bucket_count = 10
        config.objects_count = 2
        config.objects_size_range = {'min': 10, 'max': 50}

    else:
        with open(yaml_file, 'r') as f:
            doc = yaml.load(f)
        config.user_count = doc['config']['user_count']
        config.bucket_count = doc['config']['bucket_count']
        config.objects_count = doc['config']['objects_count']
        config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                     'max': doc['config']['objects_size_range']['max']}


    log.info('user_count:%s\n'
             'bucket_count: %s\n'
             'objects_count: %s\n'
             'objects_size_range: %s\n'
             % (config.user_count, config.bucket_count, config.objects_count, config.objects_size_range))

    test_exec(config)



