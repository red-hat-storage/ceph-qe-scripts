import os, sys, glob
sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
from v2.lib.resource_op import Config
import datetime
import json
import v2.utils.utils as utils
from v2.utils.utils import HttpResponseParser
from v2.lib.exceptions import TestExecError
import v2.lib.manage_data as manage_data
import logging

log = logging.getLogger()


def validate_prefix_rule(bucket, config):

    log.info('verification starts')
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket=%s" % bucket.name)
    op2 = utils.exec_shell_cmd("radosgw-admin bucket list --bucket=%s" % bucket.name)
    json_doc = json.loads(op)
    json_doc2 = json.loads(op2)
    objects = json_doc['usage']['rgw.main']['num_objects']
    objs_total = (config.test_ops['version_count']) * (config.objects_count)
    objs_ncurr = (config.test_ops['version_count']) * (config.objects_count) - (config.objects_count)
    objs_diff = objs_total - objs_ncurr
    c1 = 0
    if objects == objs_total:
        for i, entry in enumerate(json_doc2):
            print(entry['tag'])
            if entry['tag'] == 'delete-marker':
                c1 = c1 + 1
        if c1 == (config.objects_count):
            log.info('Lifecycle expiration of current object version validated for prefix filter')
    if objects == objs_diff:
        log.info('Lifecycle expiration of non_current object version validated for prefix filter')
def validate_and_rule(bucket, config):
    log.info('verification starts')
    op = utils.exec_shell_cmd("radosgw-admin bucket stats --bucket=%s" % bucket.name)
    json_doc = json.loads(op)
    objects = json_doc['usage']['rgw.main']['num_objects']
    if objects == 0 :
        log.info('Lifecycle expiration with And rule validated successfully')

 

