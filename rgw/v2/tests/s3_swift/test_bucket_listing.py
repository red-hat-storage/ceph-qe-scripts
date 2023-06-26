"""
test_bucket_listing - Test listing of objects in bucket
Usage: test_bucket_listing.py -c <input_yaml>
<input_yaml>
    Note: any one of these yamls can be used
    test_bucket_listing_flat_ordered_versionsing.yaml
	test_bucket_listing_flat_ordered.yaml
	test_bucket_listing_flat_unordered.yaml
	test_bucket_listing_flat_ordered_benchmark.yaml
	test_bucket_listing_pseudo_ordered_benchmark.yaml
	test_bucket_listing_psuedo_only_ordered.yaml
	test_bucket_listing_pseudo_ordered.yaml		
Operation:
    Create user 
	create objects as per the object structure mentioned in the yaml
   	list the objects using boto and radosgw-admin command.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
import argparse
import hashlib
import json
import logging
import time
import traceback

import v2.lib.manage_data as manage_data
import v2.lib.resource_op as s3lib
import v2.utils.utils as utils
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.lib.s3.auth import Auth
from v2.lib.s3.write_io_info import BasicIOInfoStructure, BucketIoInfo, IOInfoInitialize
from v2.tests.s3_swift import reusable
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo
from v2.utils.utils import RGWService

log = logging.getLogger()
TEST_DATA_PATH = None
password = "32characterslongpassphraseneeded".encode("utf-8")
encryption_key = hashlib.md5(password).hexdigest()


def test_exec(config, ssh_con):

    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    write_bucket_io_info = BucketIoInfo()
    io_info_initialize.initialize(basic_io_structure.initial())
    ceph_conf = CephConfOp(ssh_con)
    rgw_service = RGWService()

    # create user
    all_users_info = s3lib.create_users(config.user_count)
    if config.test_ops.get("encryption_algorithm", None) is not None:
        log.info("encryption enabled, making ceph config changes")
        ceph_conf.set_to_ceph_conf(
            "global", ConfigOpts.rgw_crypt_require_ssl, "false", ssh_con
        )
        srv_restarted = rgw_service.restart(ssh_con)
        time.sleep(30)
        if srv_restarted is False:
            raise TestExecError("RGW service restart failed")
        else:
            log.info("RGW service restarted")

    for each_user in all_users_info:
        # authenticate
        auth = Auth(each_user, ssh_con, ssl=config.ssl)
        if config.use_aws4 is True:
            rgw_conn = auth.do_auth(**{"signature_version": "s3v4"})
        else:
            rgw_conn = auth.do_auth()
        objects_created_list = []
        bucket_created = []
        if config.test_ops["create_bucket"] is True:
            log.info("no of buckets to create: %s" % config.bucket_count)
            for bc in range(config.bucket_count):
                bucket_name_to_create = utils.gen_bucket_name_from_userid(
                    each_user["user_id"], rand_no=bc
                )
                log.info("creating bucket with name: %s" % bucket_name_to_create)
                bucket = reusable.create_bucket(
                    bucket_name_to_create, rgw_conn, each_user
                )
                bucket_created.append(bucket)
                if config.test_ops.get("enable_version", False):
                    log.info("enable bucket version")
                    reusable.enable_versioning(
                        bucket, rgw_conn, each_user, write_bucket_io_info
                    )
                if config.test_ops["create_object"] is True:
                    if config.test_ops["object_structure"] == "flat":
                        # uploading data
                        log.info(
                            "top level s3 objects to create: %s" % config.objects_count
                        )
                        for oc, size in list(config.mapped_sizes.items()):
                            config.obj_size = size
                            s3_object_name = utils.gen_s3_object_name(
                                bucket_name_to_create, oc
                            )
                            log.info("s3 object name: %s" % s3_object_name)
                            s3_object_path = os.path.join(
                                TEST_DATA_PATH, s3_object_name
                            )
                            log.info("s3 object path: %s" % s3_object_path)
                            if config.test_ops.get("upload_type") == "multipart":
                                log.info("upload type: multipart")
                                reusable.upload_mutipart_object(
                                    s3_object_name,
                                    bucket,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                )
                            else:
                                log.info("upload type: normal")
                                reusable.upload_object(
                                    s3_object_name,
                                    bucket,
                                    TEST_DATA_PATH,
                                    config,
                                    each_user,
                                )
                            objects_created_list.append(
                                (s3_object_name, s3_object_path)
                            )
                            # deleting the local file created after upload
                            if config.local_file_delete is True:
                                log.info("deleting local file created after the upload")
                                utils.exec_shell_cmd("rm -rf %s" % s3_object_path)

                    # this covers listing of a bucket with pseudo directories and objects in it ; Unable to list contents of large buckets https://bugzilla.redhat.com/show_bug.cgi?id=1874645#c72
                    if config.test_ops["object_structure"] == "pseudo":
                        log.info(
                            f"pseudo directories to create {config.pseudo_dir_count} with {config.objects_count} objects in each"
                        )
                        for count in range(config.pseudo_dir_count):
                            s3_pseudo_dir_name = utils.gen_s3_object_name(
                                bucket_name_to_create, count
                            )
                            s3_object_path = os.path.join(
                                TEST_DATA_PATH, s3_pseudo_dir_name
                            )
                            manage_data.pseudo_dir_generator(s3_object_path)
                            for oc, size in list(config.mapped_sizes.items()):
                                config.obj_size = size
                                s3_object_name = utils.gen_s3_pseudo_object_name(
                                    s3_pseudo_dir_name, oc
                                )
                                log.info("s3 object name: %s" % s3_object_name)
                                s3_object_path = os.path.join(
                                    TEST_DATA_PATH, s3_object_name
                                )
                                log.info("s3 object path: %s" % s3_object_path)
                                if config.test_ops.get("upload_type") == "multipart":
                                    log.info("upload type: multipart")
                                    reusable.upload_mutipart_object(
                                        s3_object_name,
                                        bucket,
                                        TEST_DATA_PATH,
                                        config,
                                        each_user,
                                    )
                                else:
                                    log.info("upload type: normal")
                                    reusable.upload_object(
                                        s3_object_name,
                                        bucket,
                                        TEST_DATA_PATH,
                                        config,
                                        each_user,
                                    )
                                # deleting the local file created after upload
                                if config.local_file_delete is True:
                                    log.info(
                                        "deleting local file created after the upload"
                                    )
                                    utils.exec_shell_cmd("rm -rf %s" % s3_object_path)

                # listing bucket with only pseudo directories ; Bug allows ordered bucket listing to get stuck -- 4.1 https://bugzilla.redhat.com/show_bug.cgi?id=1853052#c0
                if config.test_ops["create_object"] is False:
                    if config.test_ops["object_structure"] == "pseudo-dir-only":
                        log.info(
                            f"pseudo directories to create {config.pseudo_dir_count}"
                        )
                        for count in range(config.pseudo_dir_count):
                            s3_pseudo_dir_name = utils.gen_s3_object_name(
                                bucket_name_to_create, count
                            )
                            utils.create_psuedo_dir(s3_pseudo_dir_name, bucket)

                # radoslist listing of the bucket
                if config.test_ops["radoslist"] is True:
                    log.info("executing the command radosgw-admin bucket radoslist ")
                    radoslist = utils.exec_shell_cmd(
                        "radosgw-admin bucket radoslist --bucket %s"
                        % bucket_name_to_create
                    )
                    if radoslist is False:
                        raise TestExecError("Radoslist command execution failed")

                # get the configuration parameter - rgw_bucket_index_max_aio
                ceph_version_id, ceph_version_name = utils.get_ceph_version()
                if ceph_version_name in ["luminous", "nautilus"]:
                    if ssh_con:
                        cmd = "ceph daemon `ls -t /var/run/ceph/ceph-client.rgw.*.asok|head -1` config show |grep  rgw_bucket_index_max_aio"
                        _, stdout, _ = ssh_con.exec_command(cmd)
                        max_aio_output = stdout.readline()
                    else:
                        cmd = "ceph daemon `ls -t /var/run/ceph/ceph-client.rgw.*.asok|head -1` config show |grep  rgw_bucket_index_max_aio"
                        max_aio_output = utils.exec_shell_cmd(cmd)
                    max_aio = max_aio_output.split()[1]
                else:
                    cmd = "ceph config get mon rgw_bucket_index_max_aio"
                    max_aio_output = utils.exec_shell_cmd(cmd)
                    max_aio = max_aio_output.rstrip("\n")

                # bucket stats to get the num_objects of the bucket
                bucket_stats = utils.exec_shell_cmd(
                    "radosgw-admin bucket stats --bucket  %s" % bucket_name_to_create
                )
                bucket_stats_json = json.loads(bucket_stats)
                bkt_num_objects = bucket_stats_json["usage"]["rgw.main"]["num_objects"]

                # ordered listing via radosgw-admin command and noting time taken
                log.info(
                    "measure the execution time taken to list via radosgw-admin command"
                )
                if config.test_ops["radosgw_listing_ordered"] is True:
                    log.info("ordered listing via radosgw-admin command")
                    rgw_cmd_time = reusable.time_to_list_via_radosgw(
                        bucket_name_to_create, "ordered"
                    )
                    if rgw_cmd_time > 0:
                        rgw_cmd_time_secs = "{:.4f}".format(rgw_cmd_time)
                        rgw_cmd_time_mins = "{:.4f}".format(rgw_cmd_time / 60)
                        log.info(
                            f"with rgw_bucket_index_max_aio = {max_aio} time taken for ordered listing of {bkt_num_objects} objects is : {rgw_cmd_time_secs} secs ; {rgw_cmd_time_mins} mins"
                        )
                    else:
                        raise TestExecError(
                            "object listing via radosgw-admin command failed"
                        )

                # unordered listing via radosgw-admin command and noting time taken
                if config.test_ops["radosgw_listing_ordered"] is False:
                    log.info("unordered listing via radosgw-admin command")
                    rgw_time = reusable.time_to_list_via_radosgw(
                        bucket_name_to_create, "unordered"
                    )
                    if rgw_time > 0:
                        rgw_time_secs = "{:.4f}".format(rgw_time)
                        rgw_time_mins = "{:.4f}".format(rgw_time / 60)
                        log.info(
                            f"with rgw_bucket_index_max_aio = {max_aio} time taken for unordered listing of {bkt_num_objects} objects is : {rgw_time_secs} secs ; {rgw_time_mins} mins"
                        )
                    else:
                        raise TestExecError(
                            "object listing via radosgw-admin command failed"
                        )

                # listing via boto and noting the time taken
                log.info("measure the execution time taken to list via boto")
                boto_time = reusable.time_to_list_via_boto(
                    bucket_name_to_create, rgw_conn
                )
                if boto_time > 0:
                    boto_time_secs = "{:.4f}".format(boto_time)
                    boto_time_mins = "{:.4f}".format(boto_time / 60)
                    log.info(
                        f"with rgw_bucket_index_max_aio = {max_aio} time taken to list {bkt_num_objects} objects via boto : {boto_time_secs} secs ; {boto_time_mins} mins"
                    )
                else:
                    raise TestExecError("object listing via boto failed")

        # radoslist on all buckets. BZ:https://bugzilla.redhat.com/show_bug.cgi?id=1892265
        if config.radoslist_all is True:
            log.info(
                "Executing the command radosgw-admin bucket radoslist on all buckets"
            )
            reusable.get_radoslist()

        if config.test_ops.get("delete_bucket_object", False):
            for bkt in bucket_created:
                if config.test_ops.get("enable_version", False):
                    for name, path in objects_created_list:
                        reusable.delete_version_object(
                            bkt, name, path, rgw_conn, each_user
                        )
                else:
                    reusable.delete_objects(bkt)
                time.sleep(120)
                reusable.delete_bucket(bkt)

    # check sync status if a multisite cluster
    reusable.check_sync_status()

    # check for any crashes during the execution
    crash_info = reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")
    if config.user_remove is True:
        reusable.remove_user(each_user)


if __name__ == "__main__":

    test_info = AddTestInfo("Listing objects of a bucket via radosgw-admin and boto")
    test_info.started_info()

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        rgw_service = RGWService()
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info("TEST_DATA_PATH: %s" % TEST_DATA_PATH)
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)
        parser = argparse.ArgumentParser(description="RGW S3 Automation")
        parser.add_argument("-c", dest="config", help="RGW Test yaml configuration")
        parser.add_argument(
            "-log_level",
            dest="log_level",
            help="Set Log Level [DEBUG, INFO, WARNING, ERROR, CRITICAL]",
            default="info",
        )
        parser.add_argument(
            "--rgw-node", dest="rgw_node", help="RGW Node", default="127.0.0.1"
        )
        args = parser.parse_args()
        yaml_file = args.config
        rgw_node = args.rgw_node
        ssh_con = None
        if rgw_node != "127.0.0.1":
            ssh_con = utils.connect_remote(rgw_node)
        log_f_name = os.path.basename(os.path.splitext(yaml_file)[0])
        configure_logging(f_name=log_f_name, set_level=args.log_level.upper())
        config = Config(yaml_file)
        ceph_conf = CephConfOp(ssh_con)
        config.read(ssh_con)
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)

        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)
