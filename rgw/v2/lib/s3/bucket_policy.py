import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.log as log
import datetime


def bucket_policy_dict(version, principals_list, actions_list, resource, effect, sid):
    log.info('version: %s' % version)
    log.info('principal_list: %s' % principals_list)
    log.info('actions_list: %s' % actions_list)
    log.info('resource: %s' % resource)
    log.info('effect: %s' % effect)
    log.info('sid: %s' % sid)
    bucket_policy = {"Version": version,
                     "Statement": [{
                         "Action": actions_list,
                         "Principal": {"AWS": principals_list},
                         "Resource": resource,
                         "Effect": effect,
                         "Sid": sid}]}
    log.info('bucket_policy:%s\n' % bucket_policy)
    return bucket_policy


gen_principal = lambda tenant, user_id: "arn:aws:iam::%s:user/%s" % (tenant, user_id)
gen_action = lambda action: "s3:%s" % action
gen_resource = lambda bucket_name: "arn:aws:s3:::%s" % bucket_name
gen_version = lambda: '2012-10-17'  # datetime.date.today().strftime("%Y-%m-%d")


def gen_bucket_policy(tenants_list, userids_list, actions_list, resources, effect="Allow", sid="statement"):
    """
    :param tenants_list: list
    :param userids_list: list
    :param actions_list: list
    :param resources_list: list
    :param effect: string
    :param sid: string
    :return: bucket_policy

    """

    principals = list(map(gen_principal, tenants_list, userids_list))
    actions = list(map(gen_action, actions_list))
    resources = list(map(gen_resource, resources))
    version = gen_version()
    bucket_policy = bucket_policy_dict(version, principals, actions, resources, effect, sid)
    return bucket_policy
