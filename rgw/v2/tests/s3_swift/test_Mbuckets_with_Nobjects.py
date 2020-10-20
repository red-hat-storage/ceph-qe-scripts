""" test_Mbuckets_with_Nobjects.py - Test with M buckets and N objects

Usage: test_Mbuckets_with_Nobjects.py -c <input_yaml>

<input_yaml>
	Note: Any one of these yamls can be used
	test_Mbuckets_with_Nobjects.yaml
	test_Mbuckets_with_Nobjects_download.yaml
	test_Mbuckets_with_Nobjects_aws4.yaml
	test_Mbuckets_with_Nobjects_compression.yaml
	test_Mbuckets_with_Nobjects_delete.yaml
	test_Mbuckets_with_Nobjects_enc.yaml
	test_Mbuckets_with_Nobjects_multipart.yaml
	test_Mbuckets_with_Nobjects_sharding.yaml
	test_gc_list.yaml
	test_gc_list_multipart.yaml

Operation:
	Creates M bucket and N objects
	Creates M bucket and N objects. Verify checksum of the downloaded objects
	Creates M bucket and N objects. Verify authentication signature_version:s3v4
	Creates M bucket and N objects. With compression enabled.
	Creates M bucket and N objects. Verify object delete succeeds.
	Creates M bucket and N objects. With encryption enabled.
	Creates M bucket and N objects. Upload multipart object.
	Creates M bucket and N objects. With sharding set to max_shards as specified in the config
	Verify gc command
""" 
# test basic creation of buckets with objects
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
from v2.lib.s3.write_io_info import IOInfoInitialize, BasicIOInfoStructure
import json, time, hashlib
import logging

log = logging.getLogger()
TEST_DATA_PATH = None
password = "32characterslongpassphraseneeded".encode('utf-8')
encryption_key = hashlib.md5(password).hexdigest()


def test_exec(config):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp()
    rgw_service = RGWService()

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    if config.test_ops.get('encryption_algorithm', None) is not None:
        log.info('encryption enabled, making ceph config changes')
        ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_crypt_require_ssl, "false")
        srv_restarted = rgw_service.restart()
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info('RGW service restarted')
    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssl=config.ssl)
        if config.use_aws4 is True:
            rgw_conn = auth.do_auth(**{'signature_version': 's3v4'})
        else:
            rgw_conn = auth.do_auth()
        # enabling sharding
        if config.test_ops['sharding']['enable'] is True:
            log.info('enabling sharding on buckets')
            max_shards = config.test_ops['sharding']['max_shards']
            log.info('making changes to ceph.conf')
            ceph_conf.set_to_ceph_conf('global', ConfigOpts.rgw_override_bucket_index_max_shards,
                                       str(max_shards))
            log.info('trying to restart services ')
            srv_restarted = rgw_service.restart()
            time.sleep(10)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info('RGW service restarted')
        if config.test_ops['compression']['enable'] is True:
            compression_type = config.test_ops['compression']['type']
            log.info('enabling compression')
            cmd = 'radosgw-admin zone get'
            out = utils.exec_shell_cmd(cmd)
            zone = json.loads(out)
            zone = zone.get("name")
            cmd = 'radosgw-admin zone placement modify --rgw-zone=%s ' \
                  '--placement-id=default-placement --compression=%s' % (zone,compression_type)
            out = utils.exec_shell_cmd(cmd)
            ceph_version = utils.exec_shell_cmd("ceph version").split()[4]
            try:
                data = json.loads(out)
                if ceph_version == 'luminous':
                    if data['placement_pools'][0]['val']['compression'] == compression_type:
                        log.info('Compression enabled successfully')

                else:
                    if ceph_version in ['nautilus', 'octopus']:
                        if data['placement_pools'][0]['val']['storage_classes']['STANDARD'][
                            'compression_type'] == compression_type:
                            log.info('Compression enabled successfully')
            except ValueError as e:
                exit(str(e))
            log.info('trying to restart rgw services ')
            srv_restarted = rgw_service.restart()
            time.sleep(10)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info('RGW service restarted')
        if config.gc_verification is True:
            conf = config.ceph_conf
            reusable.set_gc_conf(ceph_conf, conf)

        # create buckets
        if config.test_ops['create_bucket'] is True:
            log.info('no of buckets to create: %s' % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(each_user['user_id'], rand_no=bc)
                log.info('creating bucket with name: %s' % bucket_name_to_create)
                bucket = reusable.create_bucket(bucket_name_to_create, rgw_conn, each_user)
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
                            reusable.upload_mutipart_object(s3_object_name, bucket, TEST_DATA_PATH, config,
                                                            each_user)
                        else:
                            log.info('upload type: normal')
                            reusable.upload_object(s3_object_name, bucket, TEST_DATA_PATH, config, each_user)
                        if config.test_ops['download_object'] is True:
                            log.info('trying to download object: %s' % s3_object_name)
                            s3_object_download_name = s3_object_name + "." + "download"
                            s3_object_download_path = os.path.join(TEST_DATA_PATH, s3_object_download_name)
                            log.info('s3_object_download_path: %s' % s3_object_download_path)
                            log.info('downloading to filename: %s' % s3_object_download_name)
                            if config.test_ops.get('encryption_algorithm', None) is not None:
                                log.info('encryption download')
                                log.info('encryption algorithm: %s' % config.test_ops['encryption_algorithm'])
                                object_downloaded_status = bucket.download_file(s3_object_name,
                                                                                s3_object_download_path,
                                                                                ExtraArgs={
                                                                                    'SSECustomerKey': encryption_key,
                                                                                    'SSECustomerAlgorithm':
                                                                                        config.test_ops[
                                                                                            'encryption_algorithm']})
                            else:
                                object_downloaded_status = s3lib.resource_op({'obj': bucket,
                                                                              'resource': 'download_file',
                                                                              'args': [s3_object_name,
                                                                                       s3_object_download_path],
                                                                              })
                            if object_downloaded_status is False:
                                raise TestExecError("Resource execution failed: object download failed")
                            if object_downloaded_status is None:
                                log.info('object downloaded')
                            s3_object_downloaded_md5 = utils.get_md5(s3_object_download_path)
                            s3_object_uploaded_md5 = utils.get_md5(s3_object_path)
                            log.info('s3_object_downloaded_md5: %s' % s3_object_downloaded_md5)
                            log.info('s3_object_uploaded_md5: %s' % s3_object_uploaded_md5)
                            if str(s3_object_uploaded_md5) == str(s3_object_downloaded_md5):
                                log.info('md5 match')
                                utils.exec_shell_cmd('rm -rf %s' % s3_object_download_path)
                            else:
                                raise TestExecError('md5 mismatch')
                        if config.local_file_delete is True:
                            log.info('deleting local file created after the upload')
                            utils.exec_shell_cmd('rm -rf %s' % s3_object_path)
                    # verification of shards after upload
                    if config.test_ops['sharding']['enable'] is True:
                        cmd = 'radosgw-admin metadata get bucket:%s | grep bucket_id' % bucket.name
                        out = utils.exec_shell_cmd(cmd)
                        b_id = out.replace('"', '').strip().split(":")[1].strip().replace(',', '')
                        cmd2 = 'rados -p default.rgw.buckets.index ls | grep %s' % b_id
                        out = utils.exec_shell_cmd(cmd2)
                        log.info('got output from sharing verification.--------')
                    # print out bucket stats and verify in logs for compressed data by
                    # comparing size_kb_utilized and size_kb_actual
                    if config.test_ops['compression']['enable'] is True:
                        cmd = 'radosgw-admin bucket stats --bucket=%s' % bucket.name
                        out = utils.exec_shell_cmd(cmd)
                    # print out bucket stats and verify in logs for compressed data by
                    # comparing size_kb_utilized and size_kb_actual
                    if config.test_ops['compression']['enable'] is True:
                        cmd = 'radosgw-admin bucket stats --bucket=%s' % bucket.name
                        out = utils.exec_shell_cmd(cmd)
                    if config.test_ops['delete_bucket_object'] is True:
                        reusable.delete_objects(bucket)
                        log.info('set debug_rgw to 20 before delete the bucket')
                        config.debug_rgw = 20
                        ceph_conf.set_to_ceph_conf('global', ConfigOpts.debug_rgw,
                                                   str(config.debug_rgw))
                        log.info('trying to restart services')
                        srv_restarted = rgw_service.restart()
                        time.sleep(20)
                        if srv_restarted is False:
                            raise TestExecError("RGW service restart failed")
                        else:
                            log.info('RGW service restarted')
                        reusable.delete_bucket(bucket)
        # disable compression after test
        if config.test_ops['compression']['enable'] is True:
            log.info('disable compression')
            cmd = 'radosgw-admin zone get'
            out = utils.exec_shell_cmd(cmd)
            zone = json.loads(out)
            zone = zone.get("name")
            cmd = 'radosgw-admin zone placement modify --rgw-zone=%s ' \
                  '--placement-id=default-placement --compression=none' % zone
            out = utils.exec_shell_cmd(cmd)
            srv_restarted = rgw_service.restart()
            time.sleep(10)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info('RGW service restarted')

        if config.gc_verification is True:
            final_op = reusable.verify_gc()
            if final_op != -1:
                test_info.failed_status('test failed')
                sys.exit(1)
    
    # check for any crashes during the execution
    crash_info=reusable.check_for_crash()
    if crash_info:
        raise TestExecError("Crash found")

if __name__ == '__main__':

    test_info = AddTestInfo('create m buckets with n objects')
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = 'test_data'
        ceph_conf = CephConfOp()
        rgw_service = RGWService()
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

        # ch.setLevel(logging.getLevelName(console_log_level.upper()))
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

