"""
Reusable functions for LC policy
"""

import logging

from v2.lib.s3 import lifecycle as lc

log = logging.getLogger()


def create_transition_lc_config(id, prefix="", status="Enabled", days=None, date=None):
    rule = {}
    transition = lc.gen_transition()
    if days:
        transition["Transitions"].append(lc.gen_transition_days(days))
    else:
        transition["Transitions"].append(lc.gen_transition_date(date))
    transition["Transitions"][0].update((lc.gen_transition_class("CLOUDTIER")))
    filter = lc.gen_filter()
    filter["Filter"].update(lc.gen_prefix(prefix))
    rule.update(lc.gen_id(id))
    rule.update(filter)
    rule.update(transition)
    rule.update(lc.gen_status(status))
    lifecycle_config = lc.gen_lifecycle_configuration([rule])
    log.info("life_cycle config:\n%s" % lifecycle_config)
    return lifecycle_config
