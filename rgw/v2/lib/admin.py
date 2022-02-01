import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import json
import logging
import subprocess
import time

import v2.utils.utils as utils
from v2.lib.s3.write_io_info import AddUserInfo, BasicIOInfoStructure, TenantInfo

log = logging.getLogger()


class UserMgmt(object):
    def __init__(self):
        self.exec_cmd = lambda cmd: subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT
        )

    def create_admin_user(self, user_id, displayname, cluster_name="ceph"):
        """
        Function to create a S3-interface/admin user

        The S3-interface/admin user is created with the user_id, displayname, cluster_name.

        Parameters:
            user_id (char): id of the user
            displayname (char): Display Name of the user
            cluster_name (char): Name of the ceph cluster. defaults to 'ceph'

        Returns:
            user details, which contain the following
                - user_id
                - display_name
                - access_key
                - secret_key
        """
        try:
            write_user_info = AddUserInfo()
            basic_io_structure = BasicIOInfoStructure()
            log.info("cluster name: %s" % cluster_name)
            op = utils.exec_shell_cmd("radosgw-admin user list")
            if user_id in op:
                cmd = f"radosgw-admin user info --uid='{user_id}' --cluster {cluster_name}"
            else:
                cmd = f"radosgw-admin user create --uid='{user_id}' --display-name='{displayname}' --cluster {cluster_name}"
            log.info("cmd to execute:\n%s" % cmd)
            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            v = variable.stdout.read()
            v_as_json = json.loads(v)
            log.info(v_as_json)
            user_details = {}
            user_details["user_id"] = v_as_json["user_id"]
            user_details["display_name"] = v_as_json["display_name"]
            user_details["access_key"] = v_as_json["keys"][0]["access_key"]
            user_details["secret_key"] = v_as_json["keys"][0]["secret_key"]
            user_info = basic_io_structure.user(
                **{
                    "user_id": user_details["user_id"],
                    "access_key": user_details["access_key"],
                    "secret_key": user_details["secret_key"],
                }
            )
            write_user_info.add_user_info(user_info)
            log.info("access_key: %s" % user_details["access_key"])
            log.info("secret_key: %s" % user_details["secret_key"])
            log.info("user_id: %s" % user_details["user_id"])
            return user_details

        except subprocess.CalledProcessError as e:
            error = e.output + str(e.returncode)
            log.error(error)
            # traceback.print_exc(e)
            return False

    def create_rest_admin_user(self, user_id, displayname, cluster_name="ceph"):
        """
        Function to create an user with administrative capabilities

        To enable a user to exercise administrative functionality via the REST API

        Parameters:
            user_id (char): id of the user
            displayname (char): Display Name of the user
            cluster_name (char): Name of the ceph cluster. defaults to 'ceph'

        Returns:
            user details, which contain the following
                - user_id
                - display_name
                - access_key
                - secret_key
        """
        try:
            write_user_info = AddUserInfo()
            basic_io_structure = BasicIOInfoStructure()
            log.info("cluster name: %s" % cluster_name)
            cmd = f"radosgw-admin user create --uid='{user_id}' --display-name='{displayname}' --cluster {cluster_name}"
            log.info("cmd to execute:\n%s" % cmd)
            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            time.sleep(10)
            cmd = 'radosgw-admin caps add --uid=%s --caps="users=*" --cluster %s' % (
                user_id,
                cluster_name,
            )
            log.info("cmd to execute:\n%s" % cmd)
            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            v = variable.stdout.read()
            v_as_json = json.loads(v)
            log.info(v_as_json)
            user_details = {}
            user_details["user_id"] = v_as_json["user_id"]
            user_details["display_name"] = v_as_json["display_name"]
            user_details["access_key"] = v_as_json["keys"][0]["access_key"]
            user_details["secret_key"] = v_as_json["keys"][0]["secret_key"]
            user_info = basic_io_structure.user(
                **{
                    "user_id": user_details["user_id"],
                    "access_key": user_details["access_key"],
                    "secret_key": user_details["secret_key"],
                }
            )
            write_user_info.add_user_info(user_info)
            log.info("access_key: %s" % user_details["access_key"])
            log.info("secret_key: %s" % user_details["secret_key"])
            log.info("user_id: %s" % user_details["user_id"])
            return user_details

        except subprocess.CalledProcessError as e:
            error = e.output + str(e.returncode)
            log.error(error)
            # traceback.print_exc(e)
            return False

    def create_tenant_user(
        self, tenant_name, user_id, displayname, cluster_name="ceph"
    ):
        """
        Function to create an user under a tenant.

        To create an S3-interface user under tenant.

        Parameters:
            tenant_name (char): Name of the tenant
            user_id (char): id of the user
            displayname (char): Display Name of the user
            cluster_name (char): Name of the ceph cluster. defaults to 'ceph'

        Returns:
            user details, which contain the following
                - user_id
                - display_name
                - access_key
                - secret_key
                - tenant
        """
        try:
            write_user_info = AddUserInfo()
            basic_io_structure = BasicIOInfoStructure()
            tenant_info = TenantInfo()
            keys = utils.gen_access_key_secret_key(user_id)
            cmd = (
                'radosgw-admin --tenant %s --uid %s --display-name "%s" '
                "--access_key %s --secret %s user create --cluster %s"
                % (
                    tenant_name,
                    user_id,
                    displayname,
                    keys["access_key"],
                    keys["secret_key"],
                    cluster_name,
                )
            )
            log.info("cmd to execute:\n%s" % cmd)
            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            v = variable.stdout.read()
            v_as_json = json.loads(v)
            log.info(v_as_json)
            user_details = {}
            user_details["user_id"] = v_as_json["user_id"]
            user_details["display_name"] = v_as_json["display_name"]
            user_details["access_key"] = v_as_json["keys"][0]["access_key"]
            user_details["secret_key"] = v_as_json["keys"][0]["secret_key"]
            user_details["tenant"], user_details["user_id"] = user_details[
                "user_id"
            ].split("$")
            user_info = basic_io_structure.user(
                **{
                    "user_id": user_details["user_id"],
                    "access_key": user_details["access_key"],
                    "secret_key": user_details["secret_key"],
                }
            )
            write_user_info.add_user_info(
                dict(user_info, **tenant_info.tenant(user_details["tenant"]))
            )
            log.info("access_key: %s" % user_details["access_key"])
            log.info("secret_key: %s" % user_details["secret_key"])
            log.info("user_id: %s" % user_details["user_id"])
            log.info("tenant: %s" % user_details["tenant"])
            return user_details

        except subprocess.CalledProcessError as e:
            error = e.output + str(e.returncode)
            log.error(error)
            return False

    def create_subuser(self, tenant_name, user_id, cluster_name="ceph"):
        """
        Function to create an subuser under a tenant.

        To create an swift-interface user under tenant.
        Parameters:
             tenant_name (char): Name of the tenant
             user_id (char): id of the user
             cluster_name (char): Name of the ceph cluster. defaults to 'ceph'
        """
        try:
            write_user_info = AddUserInfo()
            basic_io_structure = BasicIOInfoStructure()
            tenant_info = TenantInfo()
            keys = utils.gen_access_key_secret_key(user_id)
            cmd = (
                "radosgw-admin subuser create --uid=%s$%s --subuser=%s:swift --tenant=%s --access=full --cluster %s"
                % (tenant_name, user_id, user_id, tenant_name, cluster_name)
            )
            log.info("cmd to execute:\n%s" % cmd)
            variable = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            v = variable.stdout.read()
            v_as_json = json.loads(v)
            log.info(v_as_json)
            user_details = {}
            user_details["user_id"] = v_as_json["subusers"][0]["id"]
            user_details["key"] = v_as_json["swift_keys"][0]["secret_key"]
            user_details["tenant"], _ = user_details["user_id"].split("$")
            user_info = basic_io_structure.user(
                **{
                    "user_id": user_details["user_id"],
                    "secret_key": user_details["key"],
                    "access_key": " ",
                }
            )
            write_user_info.add_user_info(
                dict(user_info, **tenant_info.tenant(user_details["tenant"]))
            )
            log.info("secret_key: %s" % user_details["key"])
            log.info("user_id: %s" % user_details["user_id"])
            log.info("tenant: %s" % user_details["tenant"])
            return user_details

        except subprocess.CalledProcessError as e:
            error = e.output + str(e.returncode)
            log.error(error)
            return False


class QuotaMgmt(object):
    def __init__(self):
        self.exec_cmd = lambda cmd: subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT
        )

    def set_bucket_quota(self, uid, max_objects, cluster_name="ceph"):
        """
        Function to set bucket quotas
        This function sets the quota of the max_objects with quota scope as bucket.

        Parameters:
            uid (char): user id
            max_objects(int): maximum number of objects
            cluster_name (char): Name of the ceph cluster. defaults to 'ceph'

        Returns:

        """
        cmd = (
            "radosgw-admin quota set --uid=%s --quota-scope=bucket --max-objects=%s --cluster %s"
            % (uid, max_objects, cluster_name)
        )
        status = utils.exec_shell_cmd(cmd)
        if not status[0]:
            raise AssertionError(status[1])
        log.info("quota set complete")

    def enable_bucket_quota(self, uid, cluster_name="ceph"):
        """
        Function to enable the quota with quota-scope as bucket

        Parameters:
            uid (char): user id
            cluster_name (char): Name of the ceph cluster. defaults to 'ceph'

        Returns:

        """
        cmd = (
            "radosgw-admin quota enable --quota-scope=bucket --uid=%s --cluster %s"
            % (uid, cluster_name)
        )
        status = utils.exec_shell_cmd(cmd)
        if not status[0]:
            raise AssertionError(status[1])
        log.info("quota set complete")
