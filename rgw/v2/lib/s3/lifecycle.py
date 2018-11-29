# lifecycle config parameters explanation:
# https://boto3.readthedocs.io/en/latest/reference/services/s3.html#S3.Client.put_bucket_lifecycle_configuration
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../../../")))
import v2.utils.log as log
import datetime
import json

sample_lifecycle_syntax = {
    'Rules': [
        {
            'Expiration': {
                'Date': '2015-1-1',
                'Days': 123,
                'ExpiredObjectDeleteMarker': True | False
            },
            'ID': 'rule1',
            'Prefix': 'string',  # deprecated, use filter
            'Filter': {
                'Prefix': 'string',
                'Tag': {
                    'Key': 'string',
                    'Value': 'string'
                },
                'And': {
                    'Prefix': 'string',
                    'Tags': [
                        {
                            'Key': 'string',
                            'Value': 'string'
                        },
                    ]
                }
            },
            'Status': 'Enabled',
            'Transitions': [
                {
                    'Date': '2015-1-1',
                    'Days': 123,
                    'StorageClass': 'STANDARD_IA'
                },
            ],
            'NoncurrentVersionTransitions': [
                {
                    'NoncurrentDays': 123,
                    'StorageClass': 'STANDARD_IA'
                },
            ],
            'NoncurrentVersionExpiration': {
                'NoncurrentDays': 123
            },  # use when versioning is enabled
            'AbortIncompleteMultipartUpload': {
                'DaysAfterInitiation': 123
            }
        },
    ]
}

# the below example lifecycle configuration will be used in our tests

lifecycle_configuration_using_for_tests = {
    'Rules': [
        {
            'Expiration': {
                'Date': '2015-1-1',
                'Days': 123,
                'ExpiredObjectDeleteMarker': True | False
            },
            'ID': 'rule1',
            'Filter': {
                'Prefix': 'string',
            },
            'Status': 'Enabled',
        },
    ]
}


def gen_lifecycle_rules(rule):
    # not using now, but may be used in the later stages
    gen_rule = dict(
        Expiration=rule.get("Expiration", None),
        ID=rule.get("Id", None),
        Prefix=rule.get("Prefix", None),
        Filter=rule.get("Filter", None),
        Status=rule.get("Status", None),
        Transitions=rule.get("Transitions", None),
        NoncurrentVersionTransitions=rule.get("NoncurrentVersionTransitions", None),
        NoncurrentVersionExpiration=rule.get("NoncurrentVersionExpiration", None),
        AbortIncompleteMultipartUpload=rule.get("AbortIncompleteMultipartUpload", None)
    )
    log.info('generated rule:\n%s' % gen_rule)
    cleaned_gen_rule = dict((k, v) for k, v in gen_rule.iteritems() if v is not None)
    log.info('cleaned rule:\n%s' % cleaned_gen_rule)
    log.info('generated rule:\n%s' % rule)
    return rule


def gen_lifecycle_configuration(rules):
    """
    :param rules: list
    :return: lifecycle configuration in json format
    """

    lifecycle_config = {'Rules': rules}
    # lifecycle_config = json.dumps(lifecycle_config)
    log.info('generated rules:\n%s' % rules)
    return lifecycle_config


gen_filter = lambda: {'Filter': {}}
gen_prefix = lambda prefix: {'Prefix': prefix}
gen_status = lambda status: {'Status': status}
gen_id = lambda id: {'ID': id}
gen_expiration = lambda: {'Expiration': {}}
gen_expiration_date = lambda date: {"Date": date}
gen_expiration_days = lambda days: {"Days": days}
gen_expired_object_deleteMarker = lambda bool: {"ExpiredObjectDeleteMarker": bool}

"""

# keep this code for now

def basic_rule(prefix,days,id,status="Enabled"):

    rule = {}

    expiration = gen_expiration()
    expiration['Expiration'].update(gen_expiration_days(days))

    filter = gen_filter()
    filter['Filter'].update(gen_prefix(prefix))

    rule.update(gen_id(id))
    rule.update(filter)
    rule.update(expiration)
    rule.update(gen_status(status))

    lifecycle_config = gen_lifecycle_configuration([rule])

    lifecycle_config = json.loads(lifecycle_config)

    return json.dumps(lifecycle_config,indent=4, sort_keys=True)
    
    
if __name__ == '__main__':

    print basic_rule(prefix="logs/", days=20, id="rul1")

"""
