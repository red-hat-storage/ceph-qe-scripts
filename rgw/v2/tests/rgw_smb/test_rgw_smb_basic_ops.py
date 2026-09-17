"""
test_rgw_smb_basic_ops - Basic SMB share create/list/delete with RGW backend

Usage: test_rgw_smb_basic_ops.py -c <input_yaml>

<input_yaml>
    configs/test_rgw_smb_basic_ops.yaml
    configs/test_rgw_smb_cluster_with_placement.yaml
    configs/test_rgw_smb_mount.yaml

Operation:
    Create RGW user (user1)
    Create bucket (test1)
    Optionally upload objects to the bucket
    Optionally create SMB cluster (placement label:smb)
    Apply SMB RGW credential + share resources via ceph smb apply
    List SMB shares and verify share is present
    Optionally mount/access share from client using samba-client (smbclient)
    Optionally delete one file from the share via smbclient and re-validate
    Delete SMB share (and credential)
    List SMB shares and verify share is removed
"""

import argparse
import logging
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))

import v2.lib.resource_op as s3lib
from v2.lib.exceptions import RGWBaseException, TestExecError
from v2.lib.resource_op import Config
from v2.lib.s3.write_io_info import BasicIOInfoStructure, IOInfoInitialize
from v2.tests.rgw_smb import reusable as smb_reusable
from v2.tests.s3_swift import reusable as s3_reusable
from v2.tests.s3cmd import reusable as s3cmd_reusable
from v2.utils import utils
from v2.utils.log import configure_logging
from v2.utils.test_desc import AddTestInfo

log = logging.getLogger()
TEST_DATA_PATH = None


def test_exec(config, ssh_con):
    """
    Executes RGW SMB basic share operations based on configuration.
    """
    io_info_initialize = IOInfoInitialize()
    basic_io_structure = BasicIOInfoStructure()
    io_info_initialize.initialize(basic_io_structure.initial())

    # Ensure smb mgr module is enabled before starting test operations
    log.info("Checking smb mgr module status before starting test")
    smb_reusable.ensure_smb_mgr_module_enabled()

    user_name = config.test_ops.get("user_name", "user1")
    bucket_name = config.test_ops.get("bucket_name", "test1")
    cluster_id = config.test_ops.get("cluster_id", "rgw-smb")
    share_id = config.test_ops.get("share_id", "rgw-share1")
    share_name = config.test_ops.get("share_name", "rshare1")
    credential_id = config.test_ops.get("credential_id", "external-rgw-creds")
    define_user_pass = config.test_ops.get("define_user_pass", "smbuser%smbpass")

    log.info(f"Creating RGW user: {user_name}")
    user_info = s3lib.create_users(
        no_of_users_to_create=1,
        user_names=[(user_name, None)],
    )[0]
    log.info(
        f"User created: user_id={user_info['user_id']}, "
        f"access_key={user_info['access_key']}"
    )

    auth = s3_reusable.get_auth(user_info, ssh_con, config.ssl, config.haproxy)
    rgw_conn = auth.do_auth()
    ip_and_port = s3cmd_reusable.get_rgw_ip_and_port(ssh_con, config.ssl)

    bucket = None
    created_objects = []
    if config.test_ops.get("create_bucket", True):
        log.info(f"Creating bucket: {bucket_name}")
        if config.haproxy:
            bucket = s3_reusable.create_bucket(bucket_name, rgw_conn, user_info)
        else:
            bucket = s3_reusable.create_bucket(
                bucket_name, rgw_conn, user_info, ip_and_port
            )
        log.info(f"Bucket {bucket_name} created successfully")

    if config.test_ops.get("create_object", False):
        if bucket is None:
            bucket = s3lib.resource_op(
                {"obj": rgw_conn, "resource": "Bucket", "args": [bucket_name]}
            )
        log.info(f"s3 objects to create: {config.objects_count}")
        if config.mapped_sizes is None:
            config.mapped_sizes = utils.make_mapped_sizes(config)
        for oc, size in list(config.mapped_sizes.items()):
            config.obj_size = size
            s3_object_name = utils.gen_s3_object_name(bucket_name, oc)
            log.info(f"Uploading s3 object: {s3_object_name}")
            s3_reusable.upload_object(
                s3_object_name, bucket, TEST_DATA_PATH, config, user_info
            )
            created_objects.append(s3_object_name)
        log.info(
            f"Uploaded {len(created_objects)} object(s) to bucket {bucket_name}: "
            f"{created_objects}"
        )

    if config.test_ops.get("create_smb_cluster", False):
        # 1. Create SMB cluster if it is not already present
        cluster_list = smb_reusable.list_smb_clusters()
        if smb_reusable.cluster_in_list(cluster_list, cluster_id):
            log.info(f"SMB cluster {cluster_id} already exists, skipping create")
        else:
            smb_reusable.create_smb_cluster(
                cluster_id,
                auth_mode=config.test_ops.get("smb_auth_mode", "user"),
                define_user_pass=define_user_pass,
                placement=config.test_ops.get("placement"),
            )
        # 2. Validate cluster is listed in ceph smb cluster ls
        log.info("Validating SMB cluster is listed in ceph smb cluster ls")
        cluster_list = smb_reusable.list_smb_clusters()
        smb_reusable.verify_cluster_in_list(
            cluster_list, cluster_id, expect_present=True
        )

    if config.test_ops.get("create_smb_share", True):
        # 1. Create SMB share
        log.info("Creating RGW-backed SMB share via declarative apply")
        resources = smb_reusable.build_rgw_share_resources(
            cluster_id=cluster_id,
            share_id=share_id,
            share_name=share_name,
            bucket_name=bucket_name,
            credential_id=credential_id,
            user_id=user_info["user_id"],
            access_key=user_info["access_key"],
            secret_key=user_info["secret_key"],
        )
        smb_reusable.apply_smb_resources(resources)
        # 2. Validate SMB services are available
        log.info("Validating SMB services are available in ceph")
        smb_reusable.verify_smb_service_available(cluster_id, expect_present=True)

    if config.test_ops.get("list_smb_share", True):
        log.info("Listing SMB shares after creation")
        share_list = smb_reusable.list_smb_shares(cluster_id)
        smb_reusable.verify_share_in_list(share_list, share_id, expect_present=True)
        share_info = smb_reusable.show_smb_share(cluster_id, share_id)
        log.info(f"Share details: {share_info}")

    if config.test_ops.get("mount_smb_share", False):
        log.info("Mounting RGW-backed SMB share from client node using samba-client")
        log.info(
            f"smbclient will use share_name '{share_name}' from config, "
            f"not share_id '{share_id}'"
        )
        test_file_path = None
        if TEST_DATA_PATH:
            test_file_path = os.path.join(TEST_DATA_PATH, "rgw_smb_mount_test.txt")
        smb_reusable.mount_smb_share_with_smbclient(
            cluster_id=cluster_id,
            share_name=share_name,
            define_user_pass=define_user_pass,
            smb_endpoint=config.test_ops.get("smb_endpoint"),
            smbclient_io=config.test_ops.get("smbclient_io", False),
            test_file_path=test_file_path,
            expected_names=created_objects,
            delete_one_file=config.test_ops.get("smbclient_delete", False),
        )
        log.info(
            f"SMB share {share_name} accessed successfully via smbclient "
            f"on the client node"
        )

    if config.test_ops.get("delete_smb_share", True):
        log.info("Deleting SMB share and RGW credential")
        if config.test_ops.get("delete_via_apply", True):
            remove_resources = smb_reusable.build_remove_rgw_share_resources(
                cluster_id=cluster_id,
                share_id=share_id,
                credential_id=credential_id,
                user_id=user_info["user_id"],
                access_key=user_info["access_key"],
                secret_key=user_info["secret_key"],
            )
            smb_reusable.apply_smb_resources(remove_resources)
        else:
            smb_reusable.remove_smb_share(cluster_id, share_id)
            remove_cred = [
                {
                    "resource_type": "ceph.smb.rgw.credential",
                    "rgw_credential_id": credential_id,
                    "intent": "removed",
                    "user_id": user_info["user_id"],
                    "access_key_id": user_info["access_key"],
                    "secret_access_key": user_info["secret_key"],
                }
            ]
            smb_reusable.apply_smb_resources(remove_cred)

        log.info("Listing SMB shares after deletion")
        share_list = smb_reusable.list_smb_shares(cluster_id)
        smb_reusable.verify_share_in_list(share_list, share_id, expect_present=False)

    if config.test_ops.get("delete_smb_cluster", False):
        # 1. Delete SMB cluster
        smb_reusable.remove_smb_cluster(cluster_id)
        # 2. Validating SMB cluster is not listed in ceph smb cluster ls
        log.info("Validating SMB cluster is not listed in ceph smb cluster ls")
        cluster_list = smb_reusable.list_smb_clusters()
        smb_reusable.verify_cluster_in_list(
            cluster_list, cluster_id, expect_present=False
        )
        # 3. Validating SMB services are not available in ceph
        log.info("Validating SMB services are not available in ceph")
        smb_reusable.verify_smb_service_available(cluster_id, expect_present=False)

    if config.user_remove is True:
        s3_reusable.remove_user(user_info)

    crash_info = s3_reusable.check_for_crash()
    if crash_info:
        raise TestExecError("ceph daemon crash found!")


if __name__ == "__main__":
    test_info = AddTestInfo("RGW SMB basic share create/list/delete")

    try:
        project_dir = os.path.abspath(os.path.join(__file__, "../../.."))
        test_data_dir = "test_data"
        TEST_DATA_PATH = os.path.join(project_dir, test_data_dir)
        log.info(f"TEST_DATA_PATH: {TEST_DATA_PATH}")
        if not os.path.exists(TEST_DATA_PATH):
            log.info("test data dir not exists, creating.. ")
            os.makedirs(TEST_DATA_PATH)

        parser = argparse.ArgumentParser(description="RGW SMB basic share operations")
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
        config.read(ssh_con)
        test_exec(config, ssh_con)
        test_info.success_status("test passed")
        sys.exit(0)

    except (RGWBaseException, Exception) as e:
        log.error(e)
        log.error(traceback.format_exc())
        test_info.failed_status("test failed")
        sys.exit(1)

    finally:
        utils.cleanup_test_data_path(TEST_DATA_PATH)
