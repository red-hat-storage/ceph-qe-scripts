import argparse
import random

import libs.log as log
from http_ops import Initialize
from utils.test_desc import AddTestInfo
from utils.utils import get_calamari_config


class PoolDefination(object):
    def __init__(self):
        pass


class Test(Initialize):
    def __init__(self, **config):
        super(Test, self).__init__(**config)

        self.pool_url = (
            self.http_request.base_url
            + "cluster"
            + "/"
            + str(self.http_request.fsid)
            + "/pool"
        )


def exec_test(config_data):
    add_test_info = AddTestInfo(
        13, "\napi/v2/cluster/<fsid>/pool \n" "api/v2/cluster/<fsid>/pool/<pool_id>"
    )
    add_test_info.started_info()

    try:

        pool_name = "pool_" + "api_testing" + str(random.randint(1, 1000))

        pool_ops = Test(**config_data)

        pool_ops.get(pool_ops.pool_url)

        # ------------ creating pool --------------

        pool_definition = PoolDefination()

        pool_definition.name = pool_name
        pool_definition.size = 3
        pool_definition.pg_num = 64
        pool_definition.crush_ruleset = 0
        pool_definition.min_size = 2
        pool_definition.crash_replay_interval = 0
        pool_definition.pg_num = 64
        pool_definition.hashpspool = True
        pool_definition.quota_max_objects = 0
        pool_definition.quota_max_bytes = 0

        log.debug("pool definition complete")

        log.info("json data \n%s:" % pool_definition.__dict__)

        pool_ops.post(pool_ops.pool_url, pool_definition.__dict__)

        # ------------- editing pool ------------

        pools = pool_ops.get(pool_ops.pool_url)

        my_pool = None

        for pool in pools:
            if pool_definition.name == pool["name"]:
                log.debug("got matching pool")
                my_pool = pool
                log.debug(my_pool)
                break

        # asserts if my_pool is none,
        assert my_pool is not None, (
            "did not find any pool with the name %s" % pool_definition.name
        )

        pool_editing = PoolDefination()

        pool_editing.name = pool_name + "_renamed"

        pool_ops.patch(
            pool_ops.pool_url + "/" + str(my_pool["id"]), pool_editing.__dict__
        )

        # ---------------- deleting pool ---------------

        pool_ops.delete(pool_ops.pool_url + "/" + str(my_pool["id"]))

        add_test_info.success("test ok")

    except AssertionError, e:
        log.error(e)
        add_test_info.failed("test error")

    return add_test_info.completed_info(config_data["log_copy_location"])


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Calamari API Automation")

    parser.add_argument(
        "-c",
        dest="config",
        default="config.yaml",
        help="calamari config file: yaml file",
    )

    args = parser.parse_args()

    calamari_config = get_calamari_config(args.config)

    exec_test(calamari_config)
