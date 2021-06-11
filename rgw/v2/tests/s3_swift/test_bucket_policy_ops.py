"""
# test s3 bucket policy operations (create/modify/replace existing policy)

usage : test_bucket_policy_ops.py -c configs/<input-yaml>
where input-yaml test_bucket_policy_delete.yaml, test_bucket_policy_modify.yaml and test_bucket_policy_replace.yaml

Operation:
- create bucket in tenant1 for user1
- generate bucket policy to user1 in tenant1, policy: list access to user1 in tenant2
- add the policy to user1 in bucket1
- testing
- modify bucket policy to replace the existing policy - TC 11215
- add policy to the existing policy - TC 11214


"""
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.lib.s3.bucket_policy as s3_bucket_policy
import v2.utils.utils as utils
from v2.utils.log import configure_logging
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
import yaml
import json
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.tests.s3_swift import reusable
import botocore.exceptions as boto3exception
import logging

log = logging.getLogger()


TEST_DATA_PATH = None


# bucket policy examples: https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html
# Actions list: https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html
# test run: https://polarion.engineering.redhat.com/polarion/#/project/CEPH/testrun?id=3_0_RHEL_7_4_RGW_BucketPolicyCompatibilityWithS3&tab=records&result=passed
# ceph supported actions: http://docs.ceph.com/docs/master/radosgw/bucketpolicy/

# sample bucket policy dict, this will be used to construct bucket policy for the test.


def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # create user
    config.user_count = 1
    tenant1 = 'MountEverest'
    tenant2 = 'Himalayas'
    tenant1_user_info = s3lib.create_tenant_users(tenant_name=tenant1, no_of_users_to_create=config.user_count)
    tenant1_user1_info = tenant1_user_info[0]
    tenant2_user_info = s3lib.create_tenant_users(tenant_name=tenant2, no_of_users_to_create=config.user_count)
    tenant2_user1_info = tenant2_user_info[0]
    tenant1_user1_auth = Auth(tenant1_user1_info, ssl=config.ssl)
    tenant2_user1_auth = Auth(tenant2_user1_info, ssl=config.ssl)
    rgw_tenant1_user1 = tenant1_user1_auth.do_auth()
    rgw_tenant1_user1_c = tenant1_user1_auth.do_auth_using_client()
    rgw_tenant2_user1 = tenant2_user1_auth.do_auth()
    rgw_tenant2_user1_c = tenant2_user1_auth.do_auth_using_client()
    bucket_name1 = utils.gen_bucket_name_from_userid(tenant1_user1_info['user_id'], rand_no=1)
    t1_u1_bucket1 = reusable.create_bucket(bucket_name1, rgw_tenant1_user1,
                                           tenant1_user1_info,
                                           )
    bucket_name2 = utils.gen_bucket_name_from_userid(tenant1_user1_info['user_id'], rand_no=2)
    t1_u1_bucket2 = reusable.create_bucket(bucket_name2, rgw_tenant1_user1,
                                           tenant1_user1_info,
                                           )
    bucket_policy_generated = s3_bucket_policy.gen_bucket_policy(tenants_list=[tenant1],
                                                                 userids_list=[tenant2_user1_info['user_id']],
                                                                 actions_list=['CreateBucket'],
                                                                 resources=[t1_u1_bucket1.name]
                                                                 )
    bucket_policy = json.dumps(bucket_policy_generated)
    log.info('jsoned policy:%s\n' % bucket_policy)
    log.info('bucket_policy_generated:%s\n' % bucket_policy_generated)
    bucket_policy_obj = s3lib.resource_op({'obj': rgw_tenant1_user1,
                                           'resource': 'BucketPolicy',
                                           'args': [t1_u1_bucket1.name]})
    put_policy = s3lib.resource_op({'obj': bucket_policy_obj,
                                    'resource': 'put',
                                    'kwargs': dict(ConfirmRemoveSelfBucketAccess=True,
                                                   Policy=bucket_policy)})
    log.info('put policy response:%s\n' % put_policy)
    if put_policy is False:
        raise TestExecError("Resource execution failed: bucket creation faield")
    if put_policy is not None:
        response = HttpResponseParser(put_policy)
        if response.status_code == 200 or response.status_code == 204:
            log.info('bucket policy created')
        else:
            raise TestExecError("bucket policy creation failed")
    else:
        raise TestExecError("bucket policy creation failed")
    # get policy
    get_policy = rgw_tenant1_user1_c.get_bucket_policy(Bucket=t1_u1_bucket1.name)
    log.info('got bucket policy:%s\n' % get_policy['Policy'])
    # modifying bucket policy to take new policy
    if config.bucket_policy_op == 'modify':
        # adding new action list: ListBucket to existing action: CreateBucket
        log.info('modifying buckey policy')
        actions_list = ['ListBucket', 'CreateBucket']
        actions = list(map(s3_bucket_policy.gen_action, actions_list))
        bucket_policy2_generated = s3_bucket_policy.gen_bucket_policy(tenants_list=[tenant1],
                                                                      userids_list=[tenant2_user1_info['user_id']],
                                                                      actions_list=actions_list,
                                                                      resources=[t1_u1_bucket1.name]
                                                                      )
        bucket_policy2 = json.dumps(bucket_policy2_generated)
        put_policy = s3lib.resource_op({'obj': bucket_policy_obj,
                                        'resource': 'put',
                                        'kwargs': dict(ConfirmRemoveSelfBucketAccess=True,
                                                       Policy=bucket_policy2)})
        log.info('put policy response:%s\n' % put_policy)
        if put_policy is False:
            raise TestExecError("Resource execution failed: bucket creation faield")
        if put_policy is not None:
            response = HttpResponseParser(put_policy)
            if response.status_code == 200 or response.status_code == 204:
                log.info('bucket policy created')
            else:
                raise TestExecError("bucket policy creation failed")
        else:
            raise TestExecError("bucket policy creation failed")
        get_modified_policy = rgw_tenant1_user1_c.get_bucket_policy(Bucket=t1_u1_bucket1.name)
        modified_policy = json.loads(get_modified_policy['Policy'])
        log.info('got bucket policy:%s\n' % modified_policy)
        actions_list_from_modified_policy = modified_policy['Statement'][0]['Action']
        cleaned_actions_list_from_modified_policy = list(map(str, actions_list_from_modified_policy))
        log.info('cleaned_actions_list_from_modified_policy: %s' % cleaned_actions_list_from_modified_policy)
        log.info('actions list to be modified: %s' % actions)
        cmp_val = utils.cmp(actions, cleaned_actions_list_from_modified_policy)
        log.info('cmp_val: %s' % cmp_val)
        if cmp_val != 0:
            raise TestExecError("modification of bucket policy failed ")
    if config.bucket_policy_op == 'replace':
        log.info('replacing new bucket policy')
        new_policy_generated = s3_bucket_policy.gen_bucket_policy(tenants_list=[tenant1],
                                                                  userids_list=[tenant2_user1_info['user_id']],
                                                                  actions_list=['ListBucket'],
                                                                  resources=[t1_u1_bucket2.name]
                                                                  )
        new_policy = json.dumps(new_policy_generated)
        put_policy = s3lib.resource_op({'obj': bucket_policy_obj,
                                        'resource': 'put',
                                        'kwargs': dict(ConfirmRemoveSelfBucketAccess=True,
                                                       Policy=new_policy)})
        log.info('put policy response:%s\n' % put_policy)
        if put_policy is False:
            raise TestExecError("Resource execution failed: bucket creation faield")
        if put_policy is not None:
            response = HttpResponseParser(put_policy)
            if response.status_code == 200 or response.status_code == 204:
                log.info('new bucket policy created')
            else:
                raise TestExecError("bucket policy creation failed")
        else:
            raise TestExecError("bucket policy creation failed")
    if config.bucket_policy_op == 'delete':
        log.info('in delete bucket policy')
        delete_policy = s3lib.resource_op({'obj': bucket_policy_obj,
                                           'resource': 'delete',
                                           'args': None}
                                          )
        if delete_policy is False:
            raise TestExecError("Resource execution failed: bucket creation faield")
        if delete_policy is not None:
            response = HttpResponseParser(delete_policy)
            if response.status_code == 200 or response.status_code == 204:
                log.info('bucket policy deleted')
            else:
                raise TestExecError("bucket policy deletion failed")
        else:
            raise TestExecError("bucket policy deletion failed")
        # confirming once again by calling get_bucket_policy
        try:
            rgw_tenant1_user1_c.get_bucket_policy(Bucket=t1_u1_bucket1.name)
            raise TestExecError("bucket policy did not get deleted")
        except boto3exception.ClientError as e:
            log.info(e.response)
            response = HttpResponseParser(e.response)
            if response.error['Code'] == 'NoSuchBucketPolicy':
                log.info('bucket policy deleted')
            else:
                raise TestExecError("bucket policy did not get deleted")
        # log.info('get_policy after deletion: %s' % get_policy)

    #check sync status if a multisite cluster
    reusable.check_sync_status()

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

        test_exec(config)
        test_info.success_status('test passed')
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.info(e)
        log.info(traceback.format_exc())
        test_info.failed_status('test failed')
        sys.exit(1)
