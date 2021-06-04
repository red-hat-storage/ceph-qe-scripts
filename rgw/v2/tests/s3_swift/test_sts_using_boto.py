"""
test_sts_using_boto.py - Test STS using boto

Usage: test_sts_using_boto.py -c <input_yaml>
<input_yaml>
    test_sts_using_boto.yaml

Operation:
    s1: Create 2 Users.
        user1 will be the owner and will give permisison to create bucket to user2
    s2: add caps to user1 for creating create role - use radosgw-admin
    s3: create iam_client object using user1 credentials
    s4: gen a policy_doc added with user2 uid added in it.
    s5: create role
    s6: put role
    s7: get sts client object
    s8: assume role, this will return credentials and token
    s9: with above credentials create s3 object and start the io
        create bucket
        upload object


"""

import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
from v2.utils.log import configure_logging
import v2.utils.utils as utils
from v2.utils.utils import RGWService
from v2.tests.s3_swift import reusable
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
from v2.lib.exceptions import TestExecError, RGWBaseException
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure, AddUserInfo
import json, time, hashlib
import logging

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config):
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_config_set = CephConfOp()
    rgw_service = RGWService()

    # create users
    config.user_count = 2
    users_info = s3lib.create_users(config.user_count)
    # user1 is the owner
    user1, user2 = users_info[0], users_info[1]
    log.info('adding sts config to ceph.conf')
    sesison_encryption_token = 'abcdefghijklmnoq'
    ceph_config_set.set_to_ceph_conf('global', ConfigOpts.rgw_sts_key, sesison_encryption_token)
    ceph_config_set.set_to_ceph_conf('global', ConfigOpts.rgw_s3_auth_use_sts, True)
    srv_restarted = rgw_service.restart()
    time.sleep(30)
    if srv_restarted is False:
        raise TestExecError("RGW service restart failed")
    else:
        log.info('RGW service restarted')

    auth = Auth(user1)
    iam_client = auth.do_auth_iam_client()
    """
    TODO:
    policy_document and role_policy can be used valid dict types.
    need to explore on this. 
    """

    policy_document = "{\"Version\":\"2012-10-17\"," \
                      "\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"arn:aws:iam:::user/%s\"]}," \
                      "\"Action\":[\"sts:AssumeRole\"]}]}" % (user2['user_id'])

    role_policy = "{\"Version\":\"2012-10-17\"," \
                  "\"Statement\":{\"Effect\":\"Allow\"," \
                  "\"Action\":\"s3:*\"," \
                  "\"Resource\":\"arn:aws:s3:::*\"}}"

    add_caps_cmd = 'sudo radosgw-admin caps add --uid="{user_id}" --caps="roles=*"'.format(user_id=user1['user_id'])
    utils.exec_shell_cmd(add_caps_cmd)

    # log.info(policy_document)
    role_name = f"S3RoleOf.{user1['user_id']}"
    log.info(f'role_name: {role_name}')

    log.info('creating role')
    create_role_response = iam_client.create_role(
        AssumeRolePolicyDocument=policy_document,
        Path='/',
        RoleName=role_name,
    )
    log.info("create_role_response")
    log.info(create_role_response)

    policy_name = f"policy.{user1['user_id']}"
    log.info(f'policy_name: {policy_name}')

    log.info('putting role policy')
    put_policy_response = iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=role_policy
    )

    log.info('put_policy_response')
    log.info(put_policy_response)

    auth = Auth(user2)
    sts_client = auth.do_auth_sts_client()

    log.info('assuming role')
    assume_role_response = sts_client.assume_role(
        RoleArn=create_role_response['Role']['Arn'],
        RoleSessionName=user1['user_id'],
        DurationSeconds=3600
    )

    log.info(assume_role_response)

    assumed_role_user_info = {'access_key': assume_role_response['Credentials']['AccessKeyId'],
                             'secret_key': assume_role_response['Credentials']['SecretAccessKey'],
                             'session_token': assume_role_response['Credentials']['SessionToken'],
                             'user_id': user2['user_id']}

    log.info('got the credentials after assume role')
    s3client = Auth(assumed_role_user_info)
    s3_client_rgw = s3client.do_auth()

    io_info_initialize.initialize(basic_io_structure.initial())
    write_user_info = AddUserInfo()
    basic_io_structure = BasicIOInfoStructure()
    user_info = basic_io_structure.user(**{'user_id': assumed_role_user_info['user_id'],
                                           'access_key': assumed_role_user_info['access_key'],
                                           'secret_key': assumed_role_user_info['secret_key']})
    write_user_info.add_user_info(user_info)

    if config.test_ops['create_bucket'] is True:
        log.info('no of buckets to create: %s' % config.bucket_count)
        for bc in range(config.bucket_count):
            bucket_name_to_create = utils.gen_bucket_name_from_userid(assumed_role_user_info['user_id'], rand_no=bc)
            log.info('creating bucket with name: %s' % bucket_name_to_create)
            bucket = reusable.create_bucket(bucket_name_to_create, s3_client_rgw, assumed_role_user_info)
            if config.test_ops['create_object'] is True:
                # uploading data
                log.info('s3 objects to create: %s' % config.objects_count)
                for oc, size in list(config.mapped_sizes.items()):
                    config.obj_size = size
                    s3_object_name = utils.gen_s3_object_name(bucket_name_to_create, oc)
                    log.info('s3 object name: %s' % s3_object_name)
                    s3_object_path = os.path.join(TEST_DATA_PATH, s3_object_name)
                    log.info('s3 object path: %s' % s3_object_path)
                    if config.test_ops.get('upload_type') == 'multipart':
                        log.info('upload type: multipart')
                        reusable.upload_mutipart_object(s3_object_name, bucket,
                                                        TEST_DATA_PATH,
                                                        config,
                                                        assumed_role_user_info)
                    else:
                        log.info('upload type: normal')
                        reusable.upload_object(s3_object_name, bucket,
                                               TEST_DATA_PATH,
                                               config,
                                               assumed_role_user_info)

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == '__main__':

    test_info = AddTestInfo('create m buckets with n objects')
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = 'test_data'
        TEST_DATA_PATH = (os.path.join(project_dir, test_data_dir))
        log.info('TEST_DATA_PATH: %s' % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info('test data dir not exists, creating.. ')
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description='RGW S3 STS automation')
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
