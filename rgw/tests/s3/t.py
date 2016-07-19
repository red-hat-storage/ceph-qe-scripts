import os
import boto
import boto.s3.connection
import sys
from boto.s3.key import Key
from random import randint


u1_bucket = 'sandy2.bucky.0'
u2_bucket = 'margaret2.bucky.0'


access_key = 'ORQ0E8NCG6G19D46KJA4'
secret_key = 'c02xYBMXUrcPETCtTZOTXBO24dATp8naiF4GrZsF'

conn = boto.connect_s3(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    host='magna118',
    port=8080,
    is_secure=False,
    calling_format=boto.s3.connection.OrdinaryCallingFormat(),
)

access_key2 = 'E7P4AFVG7ML4FS880QDW'
secret_key2 = 'KX45ecyo9hdxub7JhfrwgiNz6MOdKD29B9WPoTj7'

conn2 = boto.connect_s3(
    aws_access_key_id=access_key2,
    aws_secret_access_key=secret_key2,
    host='magna118',
    port=8080,
    is_secure=False,
    calling_format=boto.s3.connection.OrdinaryCallingFormat(),
)


can_id = conn2.get_canonical_user_id()
print can_id

bu = conn.get_bucket(u1_bucket)


acp = bu.get_acl()

for grant in acp.acl.grants:
    print grant.permission, grant.id


all_keys = bu.get_all_keys()


for key in all_keys:
    print 'all keys 1--------------'
    print 'name: %s' % key.name
    print 'version_id %s' % key.version_id
    print 'size: %s' % key.size
    print 'etag: %s' % key.etag
    print 'md5: %s' % key.md5

    print '--------------'


bu2 = conn.get_bucket(u2_bucket)

acp2 = bu2.get_acl()

for grant in acp2.acl.grants:
    print grant.permission, grant.id

print 'copying the objects from u1 to u2'

for each in all_keys:
    bu2.copy_key(each.key, bu.name, each.key)

all_keys2 = bu2.get_all_keys()

for key in all_keys2:
    print 'all keys 2--------------'
    print 'name: %s' % key.name
    print 'version_id %s' % key.version_id
    print 'size: %s' % key.size
    print 'etag: %s' % key.etag
    print 'md5: %s' % key.md5

    print '--------------'




