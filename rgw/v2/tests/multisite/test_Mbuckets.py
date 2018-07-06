# test basic creation of buckets
import os, sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
from v2.lib.resource_op import Config
import v2.lib.resource_op as s3lib
from v2.lib.s3.auth import Auth
import v2.utils.log as log
import v2.utils.utils as utils
from v2.utils.utils import RGWService
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import HttpResponseParser
import traceback
import argparse
import yaml
import v2.lib.manage_data as manage_data
from v2.lib.exceptions import TestExecError
from v2.utils.test_desc import AddTestInfo
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
from v2.lib.s3.write_io_info import AddUserInfo
import time
import simplejson

TEST_DATA_PATH = None


def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    write_user_info = AddUserInfo()
    test_info = AddTestInfo('create m buckets')
    conf_path = '/etc/ceph/%s.conf' % config.cluster_name
    ceph_conf = CephConfOp(conf_path)
    rgw_service = RGWService()

    try:

        test_info.started_info()

        # get user

        with open('user_details') as fout:
            all_users_info = simplejson.load(fout)

        for each_user in all_users_info:

            user_info = basic_io_structure.user(**{'user_id': each_user['user_id'],
                                                   'access_key': each_user['access_key'],
                                                   'secret_key': each_user['secret_key']})

            write_user_info.add_user_info(user_info)

        for each_user in all_users_info:

            # authenticate

            auth = Auth(each_user)
            rgw_conn = auth.do_auth()

            # enabling sharding

            if config.test_ops['sharding']['enable'] is True:

                    log.info('enabling sharding on buckets')

                    max_shards = config.test_ops['sharding']['max_shards']

                    log.info('making changes to ceph.conf')

                    ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_override_bucket_index_max_shards,
                                                 max_shards)

                    log.info('trying to restart services ')

                    srv_restarted = rgw_service.restart()

                    time.sleep(10)

                    if srv_restarted is False:
                        raise TestExecError("RGW service restart failed")
                    else:
                        log.info('RGW service restarted')

            # create buckets

            if config.test_ops['create_bucket'] is True:

                log.info('no of buckets to create: %s' % config.bucket_count)

                for bc in range(config.bucket_count):

                    bucket_name_to_create = utils.gen_bucket_name_from_userid(each_user['user_id'], rand_no=bc)

                    log.info('creating bucket with name: %s' % bucket_name_to_create)

                    # bucket = s3_ops.resource_op(rgw_conn, 'Bucket', bucket_name_to_create)

                    bucket = s3lib.resource_op({'obj': rgw_conn,
                                                'resource': 'Bucket',
                                                'args': [bucket_name_to_create]})

                    created = s3lib.resource_op({'obj': bucket,
                                                'resource': 'create',
                                                'args': None,
                                                'extra_info': {'access_key': each_user['access_key']}})

                    if created is False:
                        raise TestExecError("Resource execution failed: bucket creation failed")

                    if created is not None:

                        response = HttpResponseParser(created)

                        if response.status_code == 200:
                           log.info('bucket created')

                        else:
                            raise TestExecError("bucket creation failed")

                    else:
                        raise TestExecError("bucket creation failed")

                    if config.test_ops['sharding']['enable'] is True:
                        cmd = 'radosgw-admin metadata get bucket:%s --cluster %s | grep bucket_id' \
                              % (bucket.name, config.cluster_name)

                        out = utils.exec_shell_cmd(cmd)

                        b_id = out.replace('"', '').strip().split(":")[1].strip().replace(',', '')

                        cmd2 = 'rados -p default.rgw.buckets.index ls --cluster %s | grep %s' \
                               % (config.cluster_name, b_id)

                        out = utils.exec_shell_cmd(cmd2)

                        log.info('got output from sharing verification.--------')

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

    if yaml_file is None:
        config.bucket_count = 10
    else:
        with open(yaml_file, 'r') as f:
            doc = yaml.load(f)
        config.bucket_count = doc['config']['bucket_count']
        config.cluster_name = doc['config']['cluster_name']
        config.test_ops = doc['config']['test_ops']

    log.info('bucket_count: %s\n'
             'cluster_name: %s' % (config.bucket_count, config.cluster_name))

    log.info('test_ops: %s' % config.test_ops)

    test_exec(config)