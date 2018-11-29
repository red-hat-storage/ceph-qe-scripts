# test basic creation of buckets with objects
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.log as log
import traceback
import argparse
import yaml
from v2.lib.exceptions import TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
import resuables
from v2.lib.admin import UserMgmt

TEST_DATA_PATH = None

"""
testing steps:

covers TCs both: CEPH-9741, CEPH-9740

1. We have to first create a user with same name in 2 different tenants.
2. Then we have to create a bucket say b1 and an object say o1 in the bucket via both the users.
3. We then have to create another user say test2 in tenant2 and retrieve the bucket and object via this user (test2).
    
    So, in this test we check two things:

    1. if the bucket and object with same name is created using same user names but in different tenants.
    2. if we can retrieve bucket created by one user via a different user in same and different tenant.


"""


def create_tenant_user(tenant_name, user_id, cluster_name='ceph'):
    # using userid as displayname
    admin_ops = UserMgmt()
    return admin_ops.create_tenant_user(
        user_id=user_id,
        displayname=user_id,
        cluster_name=cluster_name,
        tenant_name=tenant_name)


def test_exec(config):
    test_info = AddTestInfo('test bucket policy')
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    try:
        test_info.started_info()
        # preparing data
        user_names = ['user1', 'user2', 'user3']
        Bucket_names = ['bucket1', 'bucket2', 'bucket3']
        object_names = ['o1', 'o2']
        tenant1 = 'tenant1'
        tenant2 = 'tenant2'
        t1_u1_info = create_tenant_user(tenant_name=tenant1, user_id=user_names[0])
        t1_u1_auth = Auth(t1_u1_info)
        t1_u1 = t1_u1_auth.do_auth()
        t2_u1_info = create_tenant_user(tenant_name=tenant2, user_id=user_names[0])
        t2_u1_auth = Auth(t2_u1_info)
        t2_u1 = t2_u1_auth.do_auth()
        t1_u1_b1 = resuables.create_bucket(bucket_name=Bucket_names[0], rgw=t1_u1, user_info=t1_u1_info)
        t2_u1_b1 = resuables.create_bucket(bucket_name=Bucket_names[0], rgw=t2_u1, user_info=t2_u1_info)
        resuables.upload_object(s3_object_name=object_names[0],
                                bucket=t1_u1_b1,
                                TEST_DATA_PATH=TEST_DATA_PATH,
                                config=config, user_info=t1_u1_info)
        resuables.upload_object(s3_object_name=object_names[0],
                                bucket=t2_u1_b1,
                                TEST_DATA_PATH=TEST_DATA_PATH,
                                config=config, user_info=t1_u1_info)
        t2_u2_info = create_tenant_user(tenant_name=tenant2, user_id=user_names[1])
        t2_u2_auth = Auth(t2_u2_info)
        t2_u2 = t2_u2_auth.do_auth()
        # will try to access the bucket and objects in both tenants
        # access t1_u1_b1
        log.info('trying to access tenant1->user1->bucket1')
        t1_u1_b1_from_t2_u2 = s3lib.resource_op({'obj': t2_u2,
                                                 'resource': 'Bucket',
                                                 'args': [Bucket_names[0]]})
        log.info('trying to download tenant1->user1->bucket1->object1 from tenant2->user2' )
        download_path1 = TEST_DATA_PATH + "/t1_u1_b1_%s.download" % object_names[0]
        t1_u1_b1_o1_download = s3lib.resource_op({'obj': t1_u1_b1_from_t2_u2,
                                                  'resource': 'download_file',
                                                  'args': [object_names[0], download_path1 ]})
        if t1_u1_b1_o1_download is False:
            log.info('object not downloaded\n')
        if t1_u1_b1_o1_download is None:
            raise TestExecError("object downloaded for tenant1->user1->bucket1->object1, this should not happen")

        log.info('trying to access tenant2->user1->bucket1 from user2 in tenant 2')

        t2_u1_b1_from_t2_u2 = s3lib.resource_op({'obj': t2_u2,
                                                 'resource': 'Bucket',
                                                 'args': [Bucket_names[0]]})
        log.info('trying to download tenant2->user1->bucket1->object1 from tenant2->user2')
        download_path2 = TEST_DATA_PATH + "/t2_u1_b1_%s.download" % object_names[0]
        t2_u1_b1_o1_download = s3lib.resource_op({'obj': t2_u1_b1_from_t2_u2,
                                                  'resource': 'download_file',
                                                  'args': [object_names[0], download_path2]})
        if t2_u1_b1_o1_download is False:
            log.info('object did not download, worked as expected')
        if t1_u1_b1_o1_download is None:
            raise TestExecError('object downloaded\n'
                                'downloaded tenant2->user1->bucket1->object1, this should not happen')
        test_info.success_status('test passed')

        sys.exit(0)

    except Exception, e:
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
    with open(yaml_file, 'r') as f:
        doc = yaml.load(f)
    config.user_count = doc['config']
    config.objects_size_range = {'min': doc['config']['objects_size_range']['min'],
                                 'max': doc['config']['objects_size_range']['max']}
    test_exec(config)
