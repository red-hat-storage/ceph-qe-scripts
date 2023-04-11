import logging
import os

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.tests.s3_swift import reusable

log = logging.getLogger()


def create_nfs_cluster(cluster_id, placement=None):
    log.info(f"Creating a NFS cluster {cluster_id}")
    if placement:
        cmd = f"ceph nfs cluster create {cluster_id} {placement}"
    else:
        cmd = f"ceph nfs cluster create {cluster_id}"
    out = utils.exec_shell_cmd(cmd)
    if out == False:
        raise TestExecError("Cluster creation failed")


def create_nfs_export(cluster_id, pseudo, export_type, uid, bucket=None):
    log.info("Creating a NFS RGW export")

    if export_type == "user":
        cmd = (
            f"ceph nfs export create rgw --cluster-id {cluster_id} "
            f"--pseudo-path {pseudo} --user-id {uid}"
        )
    if export_type == "bucket":
        cmd = (
            f"ceph nfs export create rgw --cluster-id {cluster_id} "
            f"--pseudo-path {pseudo} --user-id {uid} --bucket {bucket}"
        )
    out = utils.exec_shell_cmd(cmd)
    if out == False:
        raise TestExecError("Export creation failed")


def remove_nfs_cluster(cluster_id):
    log.info("Removing the NFS cluster")
    cmd = f"ceph nfs cluster rm {cluster_id}"
    out = utils.exec_shell_cmd(cmd)
    if out == False:
        raise TestExecError("Export creation failed")


def remove_nfs_export(cluster_id, pseudo_path=None):
    log.info("Removing Nfs RGW exports")
    if pseudo_path:
        cmd = f"ceph nfs export rm {cluster_id} {pseudo_path}"
        out = utils.exec_shell_cmd(cmd)
        if out == False:
            raise TestExecError("Export remove failed")

    cmd = f"ceph nfs export ls {cluster_id}"
    out = utils.exec_shell_cmd(cmd)
    for export in out.splitlines()[1:-1]:
        cmd = f"ceph nfs export rm {cluster_id} {export}"
        op = utils.exec_shell_cmd(cmd)
        if op == False:
            raise TestExecError("Export remove failed")
