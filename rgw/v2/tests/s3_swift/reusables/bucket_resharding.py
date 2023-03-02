import json
import logging
import time

import v2.utils.utils as utils
from v2.lib.exceptions import TestExecError
from v2.lib.rgw_config_opts import CephConfOp, ConfigOpts
from v2.utils.utils import RGWService

log = logging.getLogger()


class ReshardingService:
    config = None
    ssh_con = None
    num_shards_expected = None

    def __init__(self, config, ssh_con):
        self.config = config
        self.ssh_con = ssh_con
        self.ceph_conf = CephConfOp(ssh_con)
        self.rgw_service = RGWService()
        if self.config.sharding_type == "dynamic":
            log.info("sharding type is dynamic")
            # for dynamic,
            # the number of shards  should be greater than   [ (no of objects)/(max objects per shard) ]
            # example: objects = 500 ; max object per shard = 10
            # then no of shards should be at least 50 or more
            time.sleep(15)
            log.info("making changes to ceph.conf")
            self.ceph_conf.set_to_ceph_conf(
                "global",
                ConfigOpts.rgw_max_objs_per_shard,
                str(self.config.max_objects_per_shard),
                self.ssh_con,
            )

            self.ceph_conf.set_to_ceph_conf(
                "global", ConfigOpts.rgw_dynamic_resharding, "True", self.ssh_con
            )
            self.ceph_conf.set_to_ceph_conf(
                "global",
                ConfigOpts.rgw_max_dynamic_shards,
                str(self.config.max_rgw_dynamic_shards),
                self.ssh_con,
            )

            self.ceph_conf.set_to_ceph_conf(
                "global",
                ConfigOpts.rgw_reshard_thread_interval,
                str(self.config.rgw_reshard_thread_interval),
                self.ssh_con,
            )

            self.num_shards_expected = (
                self.config.objects_count / self.config.max_objects_per_shard
            )
            log.info("num_shards_expected: %s" % self.num_shards_expected)
            log.info("trying to restart services ")
            srv_restarted = self.rgw_service.restart(self.ssh_con)
            time.sleep(30)
            if srv_restarted is False:
                raise TestExecError("RGW service restart failed")
            else:
                log.info("RGW service restarted")

    def apply(self, bucket):
        if self.config.sharding_type == "manual":
            log.info("sharding type is manual")
            # for manual.
            # the number of shards will be the value set in the command.
            time.sleep(15)
            log.info("in manual sharding")
            cmd_exec = utils.exec_shell_cmd(
                "radosgw-admin bucket reshard --bucket=%s --num-shards=%s "
                "--yes-i-really-mean-it" % (bucket.name, self.config.shards)
            )
            if cmd_exec is False:
                raise TestExecError("manual resharding command execution failed")
        return True

    def verify(self, bucket):
        op = utils.exec_shell_cmd(
            "radosgw-admin bucket stats --bucket %s" % bucket.name
        )
        json_doc = json.loads(op)
        bucket_id = json_doc["id"]
        num_shards_created = json_doc["num_shards"]
        log.info("no_of_shards_created: %s" % num_shards_created)
        if self.config.sharding_type == "manual":
            if self.config.shards != num_shards_created:
                raise TestExecError("expected number of shards not created")
            log.info("Expected number of shards created")
        if self.config.sharding_type == "dynamic":
            log.info("Verify if resharding list is empty")
            reshard_list_op = json.loads(
                utils.exec_shell_cmd("radosgw-admin reshard list")
            )
            if not reshard_list_op:
                log.info(
                    "for dynamic number of shards created should be greater than or equal to number of expected shards"
                )
                log.info("no_of_shards_expected: %s" % self.num_shards_expected)
                if int(num_shards_created) >= int(self.num_shards_expected):
                    log.info("Expected number of shards created")
            else:
                raise TestExecError("Expected number of shards not created")

        log.info("Test acls are preserved after a resharding operation.")
        cmd = utils.exec_shell_cmd(
            f"radosgw-admin metadata get bucket.instance:{bucket.name}:{bucket_id}"
        )
        json_doc = json.loads(cmd)
        log.info("The attrs field should not be empty.")
        attrs = json_doc["data"]["attrs"][0]
        if not attrs["key"]:
            raise TestExecError("Acls lost after bucket resharding, test failure.")
        return True
