"""
# test multitenant user access: CEPH-9741, CEPH-9740

Usage: test_multitenant_user_access.py -c configs/test_multitenant_access.yaml

Operation:
1. We have to first create a user with same name in 2 different tenants.
2. Then we have to create a bucket say b1 and an object say o1 in the bucket via both the users.
3. We then have to create another user say test2 in tenant2 and retrieve the bucket and object via this user (test2).
    
    So, in this test we check two things:

    1. if the bucket and object with same name is created using same user names but in different tenants.
    2. if we can retrieve bucket created by one user via a different user in same and different tenant.


"""
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.utils as utils
from v2.utils.log import configure_logging
import traceback
import random 
import argparse
import yaml
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.tests.s3_swift import reusable
from v2.lib.admin import UserMgmt
import logging

log = logging.getLogger()


TEST_DATA_PATH = None

def create_tenant_user(tenant_name, user_id, cluster_name='ceph'):
    # using userid as displayname
    admin_ops = UserMgmt()
    return admin_ops.create_tenant_user(
        user_id=user_id,
        displayname=user_id,
        cluster_name=cluster_name,
        tenant_name=tenant_name)


def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # preparing data
    user_names = ['user1', 'user2', 'user3']
    Bucket_names = ['bucket1', 'bucket2', 'bucket3']
    object_names = ['o1', 'o2']
    tenant1 = 'tenant1'+'_'+str(random.randrange(1, 100))
    tenant2 = 'tenant2'+'_'+str(random.randrange(1, 100))
    t1_u1_info = create_tenant_user(tenant_name=tenant1, user_id=user_names[0])
    t1_u1_auth = Auth(t1_u1_info, ssl=config.ssl)
    t1_u1 = t1_u1_auth.do_auth()
    t2_u1_info = create_tenant_user(tenant_name=tenant2, user_id=user_names[0])
    t2_u1_auth = Auth(t2_u1_info, ssl=config.ssl)
    t2_u1 = t2_u1_auth.do_auth()
    t1_u1_b1 = reusable.create_bucket(bucket_name=Bucket_names[0], rgw=t1_u1, user_info=t1_u1_info)
    t2_u1_b1 = reusable.create_bucket(bucket_name=Bucket_names[0], rgw=t2_u1, user_info=t2_u1_info)
    obj_sizes = list(config.mapped_sizes.values())
    config.obj_size = obj_sizes[0]
    reusable.upload_object(s3_object_name=object_names[0],
                           bucket=t1_u1_b1,
                           TEST_DATA_PATH=TEST_DATA_PATH,
                           config=config, user_info=t1_u1_info)
    config.obj_size = obj_sizes[1]
    reusable.upload_object(s3_object_name=object_names[0],
                           bucket=t2_u1_b1,
                           TEST_DATA_PATH=TEST_DATA_PATH,
                           config=config, user_info=t1_u1_info)
    t2_u2_info = create_tenant_user(tenant_name=tenant2, user_id=user_names[1])
    t2_u2_auth = Auth(t2_u2_info, ssl=config.ssl)
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
    # check for any crashes during the execution
    crash_info=reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")

if __name__ == '__main__':

    test_info = AddTestInfo('test bucket policy')
    test_info.started_info()

    try:
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
        parser.add_argument('-log_level', dest='log_level',
                            help='Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]',
                            default='info')
        args = parser.parse_args()
        yaml_file = args.config
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name,
                          set_level=args.log_level.upper())
        config = Config(yaml_file)
        config.read()
        config.user_count = 2
        config.objects_count = 2
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config)
        test_info.success_status('test passed')
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)
